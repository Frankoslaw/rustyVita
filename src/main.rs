use std::fs::{self, File};
use std::path::PathBuf;

use pup::extract_pup_files;

pub const HEADER_LENGTH: usize = 0x1000;
pub const SCE_MAGIC: usize = 0x00454353;

mod pup;

fn main() {
    env_logger::init();

    let mut pup_file = File::open("./assets/PSVUPDAT.PUP").unwrap();
    let mut out_path = PathBuf::from("./assets/out");

    fs::create_dir_all(out_path.clone()).unwrap();

    extract_pup_files(&mut pup_file, &mut out_path);
}
