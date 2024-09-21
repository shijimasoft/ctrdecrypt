use std::{fs::File, io::{Read, Seek, SeekFrom}};

use byteorder::{ByteOrder, BigEndian};
use aes::{cipher::{BlockDecryptMut, KeyIvInit}, Aes128};
use block_padding::NoPadding;

pub type Aes128Cbc = cbc::Decryptor<Aes128>;

pub fn gen_iv(cidx: u16) -> [u8; 16] {
    let mut iv: [u8; 16] = [0; 16];
    BigEndian::write_u16(&mut iv[0..2], cidx);

    iv
}

pub fn cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
    Aes128Cbc::new_from_slices(key, iv)
        .unwrap()
        .decrypt_padded_mut::<NoPadding>(data)
        .unwrap();
}

#[repr(C)]
pub struct NcchHdr {
    pub signature: [u8; 256],
    magic: [u8; 4],
    ncchsize: u32,
    pub titleid: [u8; 8],
    makercode: u16,
    pub formatversion: u8,
    formatversion2: u8,
    pub seedcheck: [u8; 4],
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
pub struct NcchOffsetSize {
    pub offset: u32,
    size: u32,
}

#[repr(C)]
pub struct NcsdHdr {
    signature: [u8; 256],
    magic: [u8; 4],
    mediasize: u32,
    pub titleid: [u8; 8],
    padding0: [u8; 16],
    pub offset_sizetable: [NcchOffsetSize; 8],
    padding1: [u8; 40],
    flags: [u8; 8],
    ncchidtable: [u8; 64],
    padding2: [u8; 48]
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

pub struct CiaReader {
    pub fhandle: File,
    encrypted: bool,
    pub name: String,
    pub key: [u8; 16],
    pub content_id: u32,
    pub cidx: u16,
    iv: [u8; 16],
    contentoff: u64,
    pub single_ncch: bool,
    pub from_ncsd: bool,
    last_enc_block: u128,
}

impl CiaReader {
    pub fn new(fhandle: File, encrypted: bool, name: String, key: [u8; 16], content_id: u32, cidx: u16, contentoff: u64, single_ncch: bool, from_ncsd: bool) -> CiaReader {
        CiaReader {
            fhandle,
            encrypted,
            name,
            key,
            content_id,
            cidx,
            iv: gen_iv(cidx),
            contentoff,
            single_ncch,
            from_ncsd,
            last_enc_block: 0
        }
    }

    pub fn seek(&mut self, offs: u64) {
        if self.single_ncch || self.from_ncsd {
            self.fhandle.seek(SeekFrom::Start(offs)).unwrap();
        } else if offs == 0 {
            self.fhandle.seek(SeekFrom::Start(self.contentoff)).unwrap();
            self.iv = gen_iv(self.cidx);
        } else {
            self.fhandle.seek(SeekFrom::Start(self.contentoff + offs - 16)).unwrap();
            self.fhandle.read_exact(&mut self.iv).unwrap();
        }
    }

    pub fn read(&mut self, data: &mut [u8]) {
        self.fhandle.read_exact(data).unwrap();

        if self.encrypted {
            let last_enc_block = BigEndian::read_u128(&data[(data.len() - 16)..]);
            cbc_decrypt(&self.key, &self.iv, data);
            let first_dec_block = BigEndian::read_u128(&data[0..16]);
            
            // XOR the last encrypted block with the first decrypted block
            BigEndian::write_u128(&mut data[0..16], first_dec_block ^ self.last_enc_block);

            self.last_enc_block = last_enc_block;
        }
    }
}
