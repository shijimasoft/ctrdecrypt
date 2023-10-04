mod ctrutils;
use ctrutils::{CiaFile, NcchHdr, CiaContent, CiaReader, gen_iv};

use std::{fs::File, path::Path, io::{Seek, Read, SeekFrom}, env};

use libaes::Cipher;
use hex_literal::hex;

const CMNKEYS: [[u8; 16]; 6] = [
    hex!("64c5fd55dd3ad988325baaec5243db98"),
    hex!("4aaa3d0e27d4d728d0b1b433f0f9cbc8"),
    hex!("fbb0ef8cdbb0d8e453cd99344371697f"),
    hex!("25959b7ad0409f72684198ba2ecd7dc6"),
    hex!("7ada22caffc476cc8297a0c7ceeeeebe"),
    hex!("a5051ca1b37dcf3afbcf8cc1edd9ce02")
];

const NCSD_PARTITIONS: [&str; 8] = [
    "Main",
    "Manual",
    "Download Play",
    "Partition4",
    "Partition5",
    "Partition6",
    "N3DSUpdateData",
    "UpdateData"
];

fn align(x: u64, y: u64) -> u64 {
    let mask: u64 = !(y - 1);
    (x + (y - 1)) & mask
}

fn flag_to_bool(flag: u8) -> bool {
    match flag {
        1 => true,
        0 => false,
        _ => panic!("Invalid crypto flag")
    }
}

fn decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut aes = Cipher::new_128(key);
    aes.set_auto_padding(false);

    aes.cbc_decrypt(iv, data)
}

fn parse_ncch(mut cia: CiaReader, csize: u64, mut titleid: [u8; 8], from_ncsd: bool) {
    println!("Parsing NCCH: {}", cia.cidx);
    cia.seek(0);
    let tmp: [u8; 512] = cia.read::<512>();
    let header: NcchHdr = unsafe { std::mem::transmute(tmp) };

    if titleid.iter().all(|&x| x == 0) {
        titleid = header.programid.clone();
        titleid.reverse();
    }
    
    let ncch_key_y = u128::from_be_bytes(header.signature[0..16].try_into().unwrap());
    
    println!("  Product code: {}", std::str::from_utf8(&header.productcode).unwrap());
    println!("  KeyY: {:032X}", ncch_key_y);
    println!("  Title ID: {}", hex::encode(titleid).to_uppercase());
    println!("  Format version: {}", header.formatversion);

    let uses_extra_crypto: bool = flag_to_bool(header.flags[3]);

    if uses_extra_crypto {
        println!("  Uses extra NCCH crypto, keyslot 0x25");
    }
    
    let fixed_crypto: u8;
    let mut encrypted: bool = true;

    if flag_to_bool(header.flags[7] & 1) {
        if flag_to_bool(header.titleid[3] & 16) { fixed_crypto = 2 } else { fixed_crypto = 1 }
        println!("  Uses fixed-key crypto")
    }

    if flag_to_bool(header.flags[7] & 4) {
        encrypted = false;
        println!("  Not encrypted")
    }

    let use_seed_crypto: bool = (header.flags[7] & 32) != 0;
    let _key_y = ncch_key_y;

    if use_seed_crypto {
        // TODO: FW > 9.6 seed system implementation (only eShop games)
        println!("TODO: Uses 9.6 NCCH Seed crypto with KeyY: {:032X}", _key_y);
    }

    let mut base: String = cia.name.strip_suffix(".cia").unwrap().to_string();
    base = format!("{}/{}.{}.ncch",
            env::current_dir().unwrap().to_str().unwrap(),
            base, 
            if from_ncsd { NCSD_PARTITIONS[cia.cidx as usize].to_string() } else { cia.cidx.to_string() }
        );

    
}

fn parse_cia(mut romfile: File, filename: String) {
    romfile.seek(SeekFrom::Start(0)).unwrap();
    let mut tmp: [u8; 32] = [0; 32];
    romfile.read_exact(&mut tmp).unwrap();
    let cia: CiaFile = unsafe { std::mem::transmute(tmp) };
    
    let cachainoff = align(cia.headersize as u64, 64);
    let tikoff = align(cachainoff + cia.cachainsize as u64, 64);
    let tmdoff = align(tikoff + cia.tiksize as u64, 64);
    let contentoffs = align(tmdoff + cia.tmdsize as u64, 64);

    romfile.seek(SeekFrom::Start((tikoff + 127 + 320) as u64)).unwrap();
    let mut enckey: [u8; 16] = [0; 16];
    romfile.read_exact(&mut enckey).unwrap();
    romfile.seek(SeekFrom::Start((tikoff + 156 + 320) as u64)).unwrap();
    let mut tid: [u8; 16] = [0; 16];
    romfile.read_exact(&mut tid[0..8]).unwrap();

    if hex::encode(tid).starts_with("00048") {
        println!("Unsupported CIA file");
        return
    }
    
    romfile.seek(SeekFrom::Start((tikoff + 177 + 320) as u64)).unwrap();
    let mut cmnkeyidx: u8 = 0;
    romfile.read_exact(std::slice::from_mut(&mut cmnkeyidx)).unwrap();

    let titkey: [u8; 16] = decrypt(&CMNKEYS[cmnkeyidx as usize], &tid,&enckey)
        .as_slice()
        .try_into()
        .unwrap();

    romfile.seek(SeekFrom::Start((tmdoff + 518) as u64)).unwrap();
    let mut content_count: [u8; 2] = [0; 2];
    romfile.read_exact(&mut content_count).unwrap();

    let mut next_content_offs = 0;
    for i in 0..u16::from_be_bytes(content_count) {
        romfile.seek(SeekFrom::Start(tmdoff + 2820 + (48 * i as u64))).unwrap();
        let mut cbuffer: [u8; 16] = [0; 16];
        romfile.read_exact(&mut cbuffer).unwrap();

        let content = CiaContent {
            cid: u32::from_be_bytes(cbuffer[0..4].try_into().unwrap()),
            cidx: u16::from_be_bytes(cbuffer[4..6].try_into().unwrap()),
            ctype: u16::from_be_bytes(cbuffer[6..8].try_into().unwrap()),
            csize: u64::from_be_bytes(cbuffer[8..16].try_into().unwrap())
        };
        
        let cenc: bool = (content.ctype & 1) != 0;

        romfile.seek(SeekFrom::Start((contentoffs + next_content_offs) as u64)).unwrap();
        let mut test: [u8; 512] = [0; 512];
        let mut search: [u8; 4] = test[256..260].try_into().unwrap(); 
        romfile.read_exact(&mut test).unwrap();

        let iv: [u8; 16] = gen_iv(content.cidx);
        
        if cenc {
            let testdec: Vec<u8> = decrypt(&titkey, &iv, &test);
            search = testdec[256..260].try_into().unwrap();
        }

        match std::str::from_utf8(&search) {
            Ok(utf8) => if utf8 == "NCCH"
            {
                romfile.seek(SeekFrom::Start(contentoffs + next_content_offs)).unwrap();
                let cia_handle = CiaReader::new(romfile.try_clone().unwrap(), cenc, filename.clone(), titkey, content.cidx, contentoffs + next_content_offs);
                next_content_offs = next_content_offs + align(content.csize, 64);
                parse_ncch(cia_handle, content.csize, tid[0..8].try_into().unwrap(), false);
            } else { println!("CIA content can't be parsed, skipping partition") }
            Err(_) => println!("CIA content can't be parsed, skipping partition")
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: ctrdecrypt <ROMFILE>");
        return;
    } else if !Path::exists(Path::new(&args[1])) {
        println!("ROM does not exist");
        return;
    }
    
    let mut rom = File::open(&args[1]).unwrap();
    
    if args[1].ends_with(".cia") {
        let mut check: [u8; 4] = [0; 4];
        rom.read_exact(&mut check).unwrap();
    
        if check[2..4] == [0, 0] { parse_cia(rom, args[1].to_string()) }
    
    }
}
