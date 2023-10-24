use owo_colors::{OwoColorize, Stream::Stdout};
use path_clean::PathClean;
use rand::Rng;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) mod arg_parser;
pub(crate) mod styles;

pub fn search_and_replace(
    path_to_file: &Path,
    search: &str,
    replace: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_content = fs::read_to_string(path_to_file)?;

    let new_content = match file_content.find(replace) {
        None => file_content.replace(search, replace),
        Some(_) => file_content.replace(search, ""),
    };

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path_to_file)?;
    file.write_all(new_content.as_bytes())?;

    Ok(())
}

pub fn create_root_folder(
    general_output_folder: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let time = format!(
        "{:?}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
    );
    let prefix = "output_";
    let result = [prefix, &time].join("");
    if cfg!(debug_assertions) {
        println!(
            "{} Creating output folder: {}",
            "[+]".if_supports_color(Stdout, |text| text.green()),
            &result.if_supports_color(Stdout, |text| text.yellow())
        );
    }
    let mut result_path = general_output_folder.to_path_buf();
    result_path.push(result);
    fs::create_dir(&result_path)?;

    Ok(result_path)
}

pub fn absolute_path(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let path = path.as_ref();

    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    }
    .clean();

    Ok(absolute_path)
}

pub fn write_to_file(content: &[u8], path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(path)?;
    file.write_all(content)?;

    Ok(())
}

fn vec_from_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    Ok(bytes)
}

pub fn meta_vec_from_file(file_path: &Path) -> Vec<u8> {
    if cfg!(debug_assertions) {
        println!(
            "{} Reading binary file ..",
            "[+]".if_supports_color(Stdout, |text| text.green())
        );
    }
    let path_to_shellcode_file = Path::new(&file_path);
    let shellcode = vec_from_file(path_to_shellcode_file);

    match shellcode {
        Ok(bytes) => {
            if cfg!(debug_assertions) {
                println!(
                    "{} Done reading binary file!",
                    "[+]".if_supports_color(Stdout, |text| text.green())
                );
            }
            bytes
        }
        Err(err) => panic!("{:?}", err),
    }
}

pub fn path_to_string(input: &Path) -> String {
    format!("{:?}", &input)
}

pub fn random_vec(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let result: Vec<u8> = (0..len).map(|_| rng.gen_range(0..=0xff)).collect();
    result
}
