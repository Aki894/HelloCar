//! Wireless HiCar discovery, authentication, session transport and media.
pub mod wire;
pub mod json;
pub mod media;
pub mod crypto;
pub mod identity;
pub mod session;
pub mod hisight;
pub mod dmsdp;
pub mod live;
#[cfg(unix)]
pub mod uplink;
pub mod radio;
pub mod backend;
#[cfg(unix)]
pub mod native;
mod cli;

pub type Result<T> = std::result::Result<T, String>;
pub fn run(args: &[String]) -> Result<()> { cli::run(args) }

pub fn hex(data: &[u8]) -> String { data.iter().map(|b|format!("{b:02x}")).collect() }
pub fn unhex(text: &str) -> Result<Vec<u8>> {
    if text.len()%2!=0 || text.len()>4*1024*1024 || !text.is_ascii() {
        return Err("invalid bounded hex input".into());
    }
    (0..text.len()).step_by(2).map(|i|u8::from_str_radix(&text[i..i+2],16)
        .map_err(|_|"invalid hex byte".into())).collect()
}
