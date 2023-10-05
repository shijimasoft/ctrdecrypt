use std::{fs::File, io::{Seek, SeekFrom, Read}};
use libaes::Cipher;

#[repr(C)]
pub struct NcchHdr {
    pub signature: [u8; 256],
    magic: [u8; 4],
    ncchsize: u32,
    pub titleid: [u8; 8],
    makercode: u16,
    pub formatversion: u8,
    formatversion2: u8,
    seedcheck: [u8; 4],
    pub programid: [u8; 8],
    padding1: [u8; 16],
    logohash: [u8; 32],
    pub productcode: [u8; 16],
    exhdrhash: [u8; 32],
    pub exhdrsize: u32,
    padding2: u32,
    pub flags: [u8; 8],
    plainregionoffset: u32,
    plainregionsize: u32,
    logooffset: u32,
    logosize: u32,
    pub exefsoffset: u32,
    pub exefssize: u32,
    exefshashsize: u32,
    padding4: u32,
    pub romfsoffset: u32,
    pub romfssize: u32,
    romfshashsize: u32,
    padding5: u32,
    exefshash: [u8; 32],
    romfshash: [u8; 32]
}

#[repr(C)]
pub struct CiaFile {
    pub headersize: u32,
    pub type_: u16,
    pub version: u16,
    pub cachainsize: u32,
    pub tiksize: u32,
    pub tmdsize: u32,
    pub metasize: u32,
    pub contentsize: u64,
}

#[repr(C)]
pub struct CiaContent {
    pub cid: u32,
    pub cidx: u16,
    pub ctype: u16,
    pub csize: u64,
}

pub fn gen_iv(cidx: u16) -> [u8; 16] {
    let mut iv: [u8; 16] = [0; 16];
    iv[0..2].copy_from_slice(&u16::to_be_bytes(cidx));

    iv
}

pub struct CiaReader {
    pub fhandle: File,
    encrypted: bool,
    pub name: String,
    pub key: [u8; 16],
    pub cidx: u16,
    iv: [u8; 16],
    contentoff: u64,
    cipher: Cipher
}

impl CiaReader {
    pub fn new(fhandle: File, encrypted: bool, name: String, key: [u8; 16], cidx: u16, contentoff: u64) -> CiaReader {
        let mut cipher = Cipher::new_128(&key);
        cipher.set_auto_padding(false);

        CiaReader {
            fhandle,
            encrypted,
            name,
            key,
            cidx,
            iv: gen_iv(cidx),
            contentoff,
            cipher
        }
    }

    pub fn seek(&mut self, offs: u64) {
        if offs == 0 {
            self.fhandle.seek(SeekFrom::Start(self.contentoff)).unwrap();
            self.iv = gen_iv(self.cidx);
        } else {
            self.fhandle.seek(SeekFrom::Start(self.contentoff + offs - 16)).unwrap();
            self.fhandle.read_exact(&mut self.iv).unwrap();
        }
    }

    pub fn read<const BYTES: usize>(&mut self) -> [u8; BYTES] {
        let mut data: [u8; BYTES] = [0; BYTES];
        self.fhandle.read_exact(&mut data).unwrap();
        
        if self.encrypted {
            data = self.cipher.cbc_decrypt(&self.iv, &data).try_into().unwrap();
        }

        data
    }
}