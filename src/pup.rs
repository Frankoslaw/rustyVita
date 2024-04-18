use bytes::{Buf, Bytes};
use lazy_static::lazy_static;
use log::{error, info};
use std::fs::{self, File};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{collections::HashMap, io::prelude::*};

use crate::{HEADER_LENGTH, SCE_MAGIC};

lazy_static! {
    static ref PUP_TYPES: HashMap<u64, &'static str> = HashMap::from([
        (0x100, "version.txt"),
        (0x101, "license.xml"),
        (0x200, "psp2swu.self"),
        (0x204, "cui_setupper.self"),
        (0x400, "package_scewm.wm"),
        (0x401, "package_sceas.as"),
        (0x2005, "UpdaterES1.CpUp"),
        (0x2006, "UpdaterES2.CpUp"),
    ]);
    static ref TYPECOUNT: AtomicUsize = AtomicUsize::new(0);
}

const FSTYPE: [&'static str; 28] = [
    "unknown0",
    "os0",
    "unknown2",
    "unknown3",
    "vs0_chmod",
    "unknown5",
    "unknown6",
    "unknown7",
    "pervasive8",
    "boot_slb2",
    "vs0",
    "devkit_cp",
    "motionC",
    "bbmc",
    "unknownE",
    "motionF",
    "touch10",
    "touch11",
    "syscon12",
    "syscon13",
    "pervasive14",
    "unknown15",
    "vs0_tarpatch",
    "sa0",
    "pd0",
    "pervasive19",
    "unknown1A",
    "psp_emulist",
];

pub fn make_filename(hdr: &mut Bytes, filetype: u64) -> String {
    let magic: u32 = hdr.get_u32_le();
    let version = hdr.get_u32_le();
    let flags: u32 = hdr.get_u32_le();
    let _moffs: u32 = hdr.get_u32_le();
    let metaoffs: u64 = hdr.get_u64_le();

    if magic == SCE_MAGIC as u32 && version == 3 && flags == 0x30040 {
        let mut meta =
            Bytes::from(hdr[(metaoffs as usize)..(HEADER_LENGTH - metaoffs as usize)].to_owned());
        meta.advance(4);

        let t = meta.get_u8() as usize;

        if t < 0x1C {
            // 0x1C is the file separator
            let name = format!("{}-{:0>2}.pkg", FSTYPE[t], TYPECOUNT.load(Ordering::SeqCst));
            TYPECOUNT.fetch_add(1, Ordering::SeqCst);

            return name;
        }
    }

    return format!("unknown-0x{:#X}.pkg", filetype);
}

pub fn extract_pup_files(pup: &mut File, output: &mut PathBuf) {
    // TODO: Reduce number of buffers
    let mut pup_buf = Vec::new();
    pup.read_to_end(&mut pup_buf).unwrap();
    pup.rewind().unwrap();

    const SCEUF_HEADER_SIZE: usize = 0x80;
    const SCEUF_FILEREC_SIZE: usize = 0x20;

    let mut header_buf = vec![0u8; SCEUF_HEADER_SIZE];
    pup.read_exact(&mut header_buf).unwrap();

    let mut header = Bytes::from(header_buf);

    if String::from_utf8_lossy(header.get(0..5).unwrap()) != "SCEUF" {
        error!("Invalid PUP");
        return;
    }

    let pup_version: u32 = header.get(0x8..(0x8 + 4)).unwrap().get_u32_le();

    header.advance(0x10);
    let firmware_version: u32 = header.get_u32_le();
    let build_number: u32 = header.get_u32_le();
    let cnt: u32 = header.get_u32_le();

    info!("PUP Version: 0x{:0}", pup_version);
    info!("Firmware Version: {:#X}", firmware_version);
    info!("Build Number: {:0}", build_number);
    info!("Number Of Files: {}", cnt);

    for _ in 0..cnt {
        let mut sceuf_header_buf = vec![0u8; SCEUF_FILEREC_SIZE];
        pup.read_exact(&mut sceuf_header_buf).unwrap();

        let mut secuf_header = Bytes::from(sceuf_header_buf);

        let filetype: u64 = secuf_header.get_u64_le();
        let offset: u64 = secuf_header.get_u64_le();
        let length: u64 = secuf_header.get_u64_le();
        let _flags: u64 = secuf_header.get_u64_le();

        let filename: String;

        if PUP_TYPES.contains_key(&filetype) {
            filename = PUP_TYPES.get(&filetype).unwrap().to_string();
        } else {
            let mut hdr = Bytes::from(
                pup_buf[(offset as usize)..(offset as usize + HEADER_LENGTH)].to_owned(),
            );
            filename = make_filename(&mut hdr, filetype);
        }

        let mut target_path = output.clone();
        target_path.push(filename);

        let content =
            Bytes::from(pup_buf[(offset as usize)..((offset + length) as usize)].to_owned());

        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(target_path.as_path())
            .unwrap();

        file.write_all(&content).unwrap();
    }
}