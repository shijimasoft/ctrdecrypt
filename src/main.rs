mod ctrutils;
use ctrutils::{cbc_decrypt, gen_iv, CiaContent, CiaFile, CiaReader, NcchHdr, NcsdHdr};

use byteorder::{ByteOrder, BigEndian, LittleEndian, ReadBytesExt};
use aes::{cipher::{KeyIvInit, StreamCipher}, Aes128};

use std::{collections::HashMap, env, fs::File, io::{Cursor, Read, Seek, SeekFrom, Write}, path::Path, usize, vec};

use hex_literal::hex;
use log::{debug, info, LevelFilter};

const CMNKEYS: [[u8; 16]; 6] = [
    hex!("64c5fd55dd3ad988325baaec5243db98"),
    hex!("4aaa3d0e27d4d728d0b1b433f0f9cbc8"),
    hex!("fbb0ef8cdbb0d8e453cd99344371697f"),
    hex!("25959b7ad0409f72684198ba2ecd7dc6"),
    hex!("7ada22caffc476cc8297a0c7ceeeeebe"),
    hex!("a5051ca1b37dcf3afbcf8cc1edd9ce02")
];

const KEY_0X2C: u128 = 246647523836745093481291640204864831571;
const KEY_0X25: u128 = 275024782269591852539264289417494026995;
const KEY_0X18: u128 = 174013536497093865167571429864564540276;
const KEY_0X1B: u128 = 92615092018138441822550407327763030402;
const FIXED_SYS: u128 = 109645209274529458878270608689136408907;

const KEYS_0: [u128; 4] = [KEY_0X2C, KEY_0X25, KEY_0X18, KEY_0X1B];
const KEYS_1: [u128; 2] = [0, FIXED_SYS];

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

pub type Aes128Ctr = ctr::Ctr128BE<Aes128>;

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
        1..=u8::MAX => true,
        0 => false
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

fn scramblekey(key_x: u128, key_y: u128) -> u128 {
    const MAX_BITS: u32 = 128;
    const MASK: u128 = u128::MAX;

    let rol = |val: u128, r_bits: u32| -> u128 {
        let r_bits = r_bits % MAX_BITS; // Ensure the shift is within bounds
        (val << r_bits) | (val >> (MAX_BITS - r_bits))
    };

    let value = (rol(key_x, 2) ^ key_y) + (42503689118608475533858958821215598218 & MASK);
    rol(value, 87)
}

fn dump_section(ncch: &mut File, cia: &mut CiaReader, offset: u64, size: u32, sec_type: NcchSection, sec_idx: usize, ctr: [u8; 16], uses_extra_crypto: u8, fixed_crypto: u8, encrypted: bool, keyys: [u128; 2]) {
    let sections = ["ExHeader", "ExeFS", "RomFS"];
    const CHUNK: u32 = 4194304; // 4 MiB
    debug!("  {} offset: {:08X}", sections[sec_idx], offset);
    debug!("  {} counter: {}", sections[sec_idx], hex::encode(&ctr));
    debug!("  {} size: {} bytes", sections[sec_idx], size);

    // Prevent integer overflow
    match offset.checked_sub(ncch.stream_position().unwrap()) {
        Some(tmp) => {
            if tmp > 0 {
                let mut buf = vec![0u8; tmp as usize];
                cia.read(&mut buf);
                if ncch.stream_position().unwrap() == 512 { buf[1] = 0x00; }
                ncch.write_all(&buf).unwrap();
            }
        }
        None => ()
    }

    if !encrypted {
        let mut sizeleft = size;
        let mut buf = vec![0u8; CHUNK as usize];

        while sizeleft > CHUNK {
            cia.read(&mut buf);
            ncch.write_all(&buf).unwrap();
            sizeleft -= CHUNK;
        }
        
        if sizeleft > 0 {
            buf = vec![0u8; sizeleft as usize];
            cia.read(&mut buf);
            ncch.write_all(&buf).unwrap();
        }
        return;
    }

    let key_0x2c = u128::to_be_bytes(scramblekey(KEYS_0[0], keyys[0]));
    let get_crypto_key = |extra_crypto: &u8| -> usize { match extra_crypto { 0 => 0, 1 => 1, 10 => 2, 11 => 3, _ => 0 }};

    match sec_type {
        NcchSection::ExHeader => {
            let mut key = key_0x2c;
            if flag_to_bool(fixed_crypto) {
                key = u128::to_be_bytes(KEYS_1[(fixed_crypto as usize)- 1]);
            }
            let mut buf = vec![0u8; size as usize];
            cia.read(&mut buf);
            Aes128Ctr::new_from_slices(&key, &ctr)
                .unwrap()
                .apply_keystream(&mut buf);
            ncch.write_all(&buf).unwrap();
        }
        NcchSection::ExeFS => {
            let mut key = key_0x2c;
            if flag_to_bool(fixed_crypto) {
                key = u128::to_be_bytes(KEYS_1[(fixed_crypto as usize)- 1]);
            }
            let mut exedata = vec![0u8; size as usize];
            cia.read(&mut exedata);
            let mut exetmp = exedata.clone();
            Aes128Ctr::new_from_slices(&key, &ctr)
                .unwrap()
                .apply_keystream(&mut exetmp);

            if flag_to_bool(uses_extra_crypto) {
                let mut exetmp2 = exedata;
                key = u128::to_be_bytes(scramblekey(KEYS_0[get_crypto_key(&uses_extra_crypto)], keyys[1]));
                
                Aes128Ctr::new_from_slices(&key, &ctr)
                    .unwrap()
                    .apply_keystream(&mut exetmp2);

                #[repr(C)]
                struct ExeInfo {
                    fname: [u8; 8],
                    off: [u8; 4],
                    size: [u8; 4],
                }

                for i in 0usize..10 {
                    let exebytes = &exetmp[i * 16..(i + 1) * 16];
                    let exeinfo: ExeInfo = unsafe { std::mem::transmute(LittleEndian::read_u128(exebytes)) };
                    
                    let mut off = LittleEndian::read_u32(&exeinfo.off) as usize;
                    let size = LittleEndian::read_u32(&exeinfo.size) as usize;
                    off += 512;

                    match exeinfo.fname.iter().rposition(|&x| x != 0) {
                        Some(zero_idx) => if exeinfo.fname[..=zero_idx].is_ascii()
                        {
                            // ASCII for 'icon'
                            let icon: [u8; 4] = hex!("69636f6e");
                            // ASCII for 'banner'
                            let banner: [u8; 6] = hex!("62616e6e6572");

                            if !(exeinfo.fname[..=zero_idx] == icon || exeinfo.fname[..=zero_idx] == banner) {
                                exetmp.splice(off..(off + size), exetmp2[off..off + size].iter().cloned());
                            }
                        }
                        None => { exetmp.splice(off..(off + size), exetmp2[off..off + size].iter().cloned()); }
                    }
                }
            }
            ncch.write_all(&exetmp).unwrap();
        }
        NcchSection::RomFS => {
            let mut key = u128::to_be_bytes(scramblekey(KEYS_0[get_crypto_key(&uses_extra_crypto)], keyys[1]));
            if flag_to_bool(fixed_crypto) {
                key = u128::to_be_bytes(KEYS_1[(fixed_crypto as usize) - 1]);
            }
            let mut sizeleft = size;
            let mut buf = vec![0u8; CHUNK as usize];
            let mut ctr_cipher = Aes128Ctr::new_from_slices(&key, &ctr).unwrap();
            while sizeleft > CHUNK {
                cia.read(&mut buf);
                if cia.cidx > 0 && !(cia.single_ncch || cia.from_ncsd) { buf[1] = buf[1] ^ cia.cidx as u8 }
                ctr_cipher.apply_keystream(&mut buf);
                ncch.write_all(&buf).unwrap();
                sizeleft -= CHUNK;
            }

            if sizeleft > 0 {
                buf = vec![0u8; sizeleft as usize];
                cia.read(&mut buf);
                if cia.cidx > 0 && !(cia.single_ncch || cia.from_ncsd) { buf[1] = buf[1] ^ cia.cidx as u8 }
                ctr_cipher.apply_keystream(&mut buf);
                ncch.write_all(&buf).unwrap();
            }
        }
    }
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
            let seed_count = LittleEndian::read_u32(&cbuffer);
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
        Err(_) => debug!("seeddb.bin not found, trying to connect to Nintendo servers...")
    }

    // Check into Nintendo's servers
    if !seeds.contains_key(&titleid) {
        for country in ["JP", "US", "GB", "KR", "TW", "AU", "NZ"] {
            let req = attohttpc::get(format!("https://kagiya-ctr.cdn.nintendo.net/title/0x{}/ext_key?country={}", titleid, country))
                .danger_accept_invalid_certs(true)
                .send()
                .unwrap();
            if req.is_success() {
                let bytes = req.bytes().unwrap();

                match bytes.try_into() {
                    Ok(bytes) => { 
                        seeds.insert(titleid.clone(), bytes);
                        debug!("A seed has been found online in the region {}", country);
                        break;
                    }
                    Err(_) => ()
                }
            }
        }
    }

    if seeds.contains_key(&titleid) {
        let seed_check = BigEndian::read_u32(&header.seedcheck);
        let mut revtid = hex::decode(&titleid).unwrap();
        revtid.reverse();
        let sha_sum = sha256::digest([seeds[&titleid].to_vec(), revtid].concat());

        if BigEndian::read_u32(&hex::decode(sha_sum.get(0..8).unwrap()).unwrap()) == seed_check {
            let keystr = sha256::digest([u128::to_be_bytes(key_y), seeds[&titleid]].concat());
            new_key = BigEndian::read_u128(&hex::decode(keystr.get(0..32).unwrap()).unwrap());
        }
    }

    new_key
}

fn parse_ncsd(cia: &mut CiaReader) {
    debug!("Parsing NCSD in file: {}", cia.name);
    cia.seek(0);
    let mut tmp: [u8; 512] = [0u8; 512];
    cia.read(&mut tmp);
    let mut header: NcsdHdr = unsafe { std::mem::transmute(tmp) };
    for idx in 0..header.offset_sizetable.len() {
        if header.offset_sizetable[idx].offset != 0 {
            cia.cidx = idx as u16;
            cia.content_id = idx as u32;
            header.titleid.reverse();
            parse_ncch(cia, (header.offset_sizetable[idx].offset * MEDIA_UNIT_SIZE).clone().into(), header.titleid);
        }
    }
}

fn parse_ncch(cia: &mut CiaReader, offs: u64, mut titleid: [u8; 8]) {
    if cia.from_ncsd {
        debug!("  Parsing {} NCCH", NCSD_PARTITIONS[cia.cidx as usize]);
    } else if cia.single_ncch {
        debug!("  Parsing NCCH in file: {}", cia.name);
    } else {
        debug!("Parsing NCCH: {}", cia.cidx)
    }

    cia.seek(offs);
    let mut tmp = [0u8; 512];
    cia.read(&mut tmp);
    let mut header: NcchHdr = unsafe { std::mem::transmute(tmp) };
    if titleid.iter().all(|&x| x == 0) {
        titleid = header.programid;
        titleid.reverse();
    }

    let ncch_key_y = BigEndian::read_u128(header.signature[0..16].try_into().unwrap());

    debug!("  Product code: {}", std::str::from_utf8(&header.productcode).unwrap());
    debug!("  KeyY: {:032X}", ncch_key_y);
    header.titleid.reverse();
    debug!("  Title ID: {}", hex::encode(header.titleid).to_uppercase());
    header.titleid.reverse();
    debug!("  Content ID: {:08X}\n", cia.content_id);
    debug!("  Format version: {}\n", header.formatversion);

    let uses_extra_crypto: u8 = header.flags[3];

    if flag_to_bool(uses_extra_crypto) {
        debug!("  Uses extra NCCH crypto, keyslot 0x25");
    }

    let mut fixed_crypto: u8 = 0;
    let mut encrypted: bool = true;

    if flag_to_bool(header.flags[7] & 1) {
        if flag_to_bool(header.titleid[3] & 16) { fixed_crypto = 2 } else { fixed_crypto = 1 }
        debug!("  Uses fixed-key crypto")
    }

    if flag_to_bool(header.flags[7] & 4) {
        encrypted = false;
        debug!("  Not encrypted")
    }

    let use_seed_crypto: bool = (header.flags[7] & 32) != 0;
    let mut key_y = ncch_key_y;

    if use_seed_crypto {
        key_y = get_new_key(ncch_key_y, &header, hex::encode(titleid));
        debug!("Uses 9.6 NCCH Seed crypto with KeyY: {:032X}", key_y);
    }

    let mut base: String;
    let path = Path::new(&cia.name);
    let file_name = path.file_name().unwrap().to_string_lossy();

    if cia.single_ncch || cia.from_ncsd {
        base = file_name.strip_suffix(".3ds").unwrap().to_string();
    } else {
        base = file_name.strip_suffix(".cia").unwrap().to_string();
    }

    base = format!("{}/{}.{}.{:08X}.ncch",
            path.parent().unwrap().display(),
            base,
            if cia.from_ncsd { NCSD_PARTITIONS[cia.cidx as usize].to_string() } else { cia.cidx.to_string() },
            cia.content_id
        );

    let mut ncch: File = File::create(base.clone()).unwrap();
    tmp[399] = tmp[399] & 2 | 4;

    ncch.write_all(&tmp).unwrap();
    let mut counter: [u8; 16];
    if header.exhdrsize != 0 {
        counter = get_ncch_aes_counter(&header, NcchSection::ExHeader);
        dump_section(&mut ncch, cia, 512, header.exhdrsize * 2, NcchSection::ExHeader, 0, counter, uses_extra_crypto, fixed_crypto, encrypted, [ncch_key_y, key_y]);
    }

    if header.exefssize != 0 {
        counter = get_ncch_aes_counter(&header, NcchSection::ExeFS);
        dump_section(&mut ncch, cia, (header.exefsoffset * MEDIA_UNIT_SIZE) as u64, header.exefssize * MEDIA_UNIT_SIZE, NcchSection::ExeFS, 1, counter, uses_extra_crypto, fixed_crypto, encrypted, [ncch_key_y, key_y]);
    }

    if header.romfssize != 0 {
        counter = get_ncch_aes_counter(&header, NcchSection::RomFS);
        dump_section(&mut ncch, cia, (header.romfsoffset * MEDIA_UNIT_SIZE) as u64, header.romfssize * MEDIA_UNIT_SIZE, NcchSection::RomFS, 2, counter, uses_extra_crypto, fixed_crypto, encrypted, [ncch_key_y, key_y]);
    }
    
    info!("{}", base);
}

fn parse_cia(mut romfile: File, filename: String, partition: Option<u8>) {
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
        debug!("Unsupported CIA file");
        return
    }

    romfile.seek(SeekFrom::Start((tikoff + 177 + 320) as u64)).unwrap();
    let mut cmnkeyidx: u8 = 0;
    romfile.read_exact(std::slice::from_mut(&mut cmnkeyidx)).unwrap();

    cbc_decrypt(&CMNKEYS[cmnkeyidx as usize], &tid, &mut enckey);
    let titkey = enckey;

    romfile.seek(SeekFrom::Start((tmdoff + 518) as u64)).unwrap();
    let mut content_count: [u8; 2] = [0; 2];
    romfile.read_exact(&mut content_count).unwrap();

    let mut next_content_offs = 0;
    for i in 0..BigEndian::read_u16(&content_count) {
        romfile.seek(SeekFrom::Start(tmdoff + 2820 + (48 * i as u64))).unwrap();
        let mut cbuffer: [u8; 16] = [0; 16];
        romfile.read_exact(&mut cbuffer).unwrap();

        let mut bcursor = Cursor::new(cbuffer);
        let content = CiaContent {
            cid:   bcursor.read_u32::<BigEndian>().unwrap(),
            cidx:  bcursor.read_u16::<BigEndian>().unwrap(),
            ctype: bcursor.read_u16::<BigEndian>().unwrap(),
            csize: bcursor.read_u64::<BigEndian>().unwrap()
        };

        let cenc: bool = (content.ctype & 1) != 0;

        romfile.seek(SeekFrom::Start((contentoffs + next_content_offs) as u64)).unwrap();
        let mut test: [u8; 512] = [0; 512]; 
        romfile.read_exact(&mut test).unwrap();
        let mut search: [u8; 4] = test[256..260].try_into().unwrap();

        let iv: [u8; 16] = gen_iv(content.cidx);
        
        if cenc {
            cbc_decrypt(&titkey, &iv, &mut test);
            search = test[256..260].try_into().unwrap();
        }

        match std::str::from_utf8(&search) {
            Ok(utf8) => if utf8 == "NCCH"
            {
                romfile.seek(SeekFrom::Start(contentoffs + next_content_offs)).unwrap();
                let mut cia_handle = CiaReader::new(romfile.try_clone().unwrap(), cenc, filename.clone(), titkey, content.cid, content.cidx, contentoffs + next_content_offs, false, false);
                next_content_offs += align(content.csize, 64);

                match partition {
                    Some(number) => if (i as u8) != number { continue; },
                    None => (),
                }
                parse_ncch(&mut cia_handle, 0, tid[0..8].try_into().unwrap());

            } else { debug!("CIA content can't be parsed, skipping partition") }
            Err(_) => debug!("CIA content can't be parsed, skipping partition")
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut partition: Option<u8> = None;
    let mut verbose = true;

    if args.len() < 2 {
        println!("Usage: ctrdecrypt <ROMFILE> [OPTIONS]\nOptions:\n\t--ncch <partition-number>\n\t--no-verbose");
        return;
    }

    if !Path::exists(Path::new(&args[1])) {
        println!("ROM does not exist");
        return;
    }

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--ncch" => {
                if i + 1 >= args.len() {
                    println!("Missing partition number");
                    return;
                }
                match args[i + 1].parse::<u8>() {
                    Ok(num) => partition = Some(num),
                    Err(_) => {
                        println!("Invalid partition number: {}", args[i + 1]);
                    }
                }
                i += 1; // Partition number already checked
            }
            "--no-verbose" => verbose = false,
            _ => {
                println!("Invalid argument: {}", args[i]);
                return;
            }
        }
        i += 1;
    }

    env_logger::Builder::new()
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .filter(None, if verbose { LevelFilter::Debug } else { LevelFilter::Info })
        .init();

    let mut rom = File::open(&args[1]).unwrap();
    rom.seek(SeekFrom::Start(256)).unwrap();
    let mut magic: [u8; 4] = [0u8; 4];
    rom.read_exact(&mut magic).unwrap();

    match std::str::from_utf8(&magic) {
        Ok(ptype) => {
            if ptype == "NCSD" {
                let mut reader = CiaReader::new(rom.try_clone().unwrap(), false, args[1].to_string(), [0u8; 16], 0, 0, 0, false, true);
                parse_ncsd(&mut reader);
                return;
            } else if ptype == "NCCH" {
                let mut reader = CiaReader::new(rom.try_clone().unwrap(), false, args[1].to_string(), [0u8; 16], 0, 0, 0, true, false);
                parse_ncch(&mut reader, 0, [0u8; 8]);
                return;
            }
        }
        Err(_) => ()
    }

    if args[1].ends_with(".cia") {
        let mut check: [u8; 4] = [0; 4];
        rom.read_exact(&mut check).unwrap();

        if check[2..4] == [0, 0] { parse_cia(rom, args[1].to_string(), partition) }
    }
}
