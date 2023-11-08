mod ctrutils;
use ctrutils::{CiaFile, NcchHdr, CiaContent, CiaReader, gen_iv};

use std::{fs::File, path::Path, io::{Seek, Read, SeekFrom, Write}, env, collections::HashMap};

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

const MEDIA_UNIT_SIZE: u32 = 512;

enum NcchSection {
    ExHeader = 1,
    ExeFS = 2,
    RomFS = 3
}

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

fn get_ncch_aes_counter(hdr: &NcchHdr, section: NcchSection) -> [u8; 16] {
    let mut counter: [u8; 16] = [0; 16];
    if hdr.formatversion == 2 || hdr.formatversion == 0 {
        let mut titleid: [u8; 8] = hdr.titleid;
        titleid.reverse();
        counter[0..8].copy_from_slice(&titleid);
        counter[8] = section as u8;
    
    } else if hdr.formatversion == 1 {
        let x = match section {
            NcchSection::ExHeader => 512,
            NcchSection::ExeFS => hdr.exefsoffset * MEDIA_UNIT_SIZE,
            NcchSection::RomFS => hdr.romfsoffset * MEDIA_UNIT_SIZE
        };

        counter[0..8].copy_from_slice(&hdr.titleid);
        for i in 0..4 {
            counter[12 + i] = (x >> ((3 - i) * 8) & 255) as u8
        }
    }

    counter
}

fn get_new_key(key_y: u128, header: &NcchHdr, titleid: String) -> u128 {
    let mut new_key: u128 = 0;
    let mut seeds: HashMap<String, [u8; 16]> = HashMap::new();
    let db_path = Path::new("seeddb.bin");

    let seeddb = File::open(db_path);
    let mut cbuffer: [u8; 4] = [0; 4];
    let mut kbuffer: [u8; 8] = [0; 8];
    let mut sbuffer: [u8; 16] = [0; 16];

    // Check into seeddb.bin
    match seeddb {
        Ok(mut seeddb) => {
            seeddb.read_exact(&mut cbuffer).unwrap();
            let seed_count = u32::from_le_bytes(cbuffer);
            seeddb.seek(SeekFrom::Current(12)).unwrap();
            
            for _ in 0..seed_count {
                seeddb.read_exact(&mut kbuffer).unwrap();
                kbuffer.reverse();
                let key = hex::encode(kbuffer);
                seeddb.read_exact(&mut sbuffer).unwrap();
                seeds.insert(key, sbuffer);
                seeddb.seek(SeekFrom::Current(8)).unwrap();
            }
        }
        Err(_) => println!("seeddb.bin not found, trying to connect to Nintendo servers...")
    }

    // Check into Nintendo's servers
    if !seeds.contains_key(&titleid) {
        println!("\t********************************");
        println!("\tCouldn't find seed in seeddb, checking online...");
        println!("\t********************************");
        for country in ["JP", "US", "GB", "KR", "TW", "AU", "NZ"] {
            let req = attohttpc::get(format!("https://kagiya-ctr.cdn.nintendo.net/title/0x{}/ext_key?country={}", titleid, country))
                .send()
                .unwrap();
            if req.is_success() {
                let bytes = req.text().unwrap();
                seeds.insert(titleid.clone(), hex::decode(bytes).unwrap().try_into().unwrap());
                break;
            }
        }
    }

    if seeds.contains_key(&titleid) {
        let seed_check = u32::from_be_bytes(header.seedcheck);
        let mut revtid = hex::decode(&titleid).unwrap();
        revtid.reverse();
        let sha_sum = sha256::digest([seeds[&titleid].to_vec(), revtid].concat());

        if u32::from_be_bytes(hex::decode(sha_sum.get(0..8).unwrap()).unwrap().try_into().unwrap()) == seed_check {
            let keystr = sha256::digest([u128::to_be_bytes(key_y), seeds[&titleid]].concat());
            new_key = u128::from_be_bytes(hex::decode(keystr.get(0..32).unwrap()).unwrap().try_into().unwrap());
        }
    }

    new_key
}

fn decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut aes = Cipher::new_128(key);
    aes.set_auto_padding(false);

    aes.cbc_decrypt(iv, data)
}

fn parse_ncch(mut cia: CiaReader, mut titleid: [u8; 8], from_ncsd: bool) {
    println!("Parsing NCCH: {}", cia.cidx);
    cia.seek(0);
    let mut tmp: [u8; 512] = cia.read::<512>();
    let header: NcchHdr = unsafe { std::mem::transmute(tmp) };

    if titleid.iter().all(|&x| x == 0) {
        titleid = header.programid;
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
    let mut key_y = ncch_key_y;

    if use_seed_crypto {
        println!("Uses 9.6 NCCH Seed crypto with KeyY: {:032X}", key_y);
        key_y = get_new_key(ncch_key_y, &header, hex::encode(titleid));
    }

    let mut base: String = cia.name.strip_suffix(".cia").unwrap().to_string();
    base = format!("{}/{}.{}.ncch",
            env::current_dir().unwrap().to_str().unwrap(),
            base, 
            if from_ncsd { NCSD_PARTITIONS[cia.cidx as usize].to_string() } else { cia.cidx.to_string() }
        );
    
    let mut ncch: File = File::create(base).unwrap();
    tmp[399] = tmp[399] & 2 | 4;
    ncch.write_all(&tmp).unwrap();

    if header.exhdrsize != 0 {
        let counter = get_ncch_aes_counter(&header, NcchSection::ExHeader);
        // ...
    }

    if header.exefssize != 0 {
        let counter = get_ncch_aes_counter(&header, NcchSection::ExeFS);
        // ...
    }

    if header.romfssize != 0 {
        let counter = get_ncch_aes_counter(&header, NcchSection::RomFS);
        // ...
    }
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
                next_content_offs += align(content.csize, 64);
                parse_ncch(cia_handle, tid[0..8].try_into().unwrap(), false);
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
