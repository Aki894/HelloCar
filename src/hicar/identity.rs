//! Read-only compatibility with the Python schema-1 identity file.
use super::{Result,json,crypto::{Crypto,wipe}};
use std::path::Path;
pub struct Identity {pub device_id:String,pub pin:String,pub name:String}
impl Identity {
    pub fn parse(data:&[u8])->Result<Self>{
        if data.len()>4096{return Err("identity file exceeds limit".into());}
        let value=json::parse(data)?;
        if value.get("schema").and_then(|v|v.as_u64())!=Some(1){return Err("unsupported identity schema".into());}
        let text=|name:&str|value.get(name).and_then(|v|v.as_str()).map(str::to_owned).ok_or("invalid identity field".to_owned());
        let device_id=text("device_id")?;let pin=text("pin")?;let name=text("name")?;
        if device_id.len()!=64||!device_id.bytes().all(|b|b.is_ascii_hexdigit())
            ||pin.len()!=6||!pin.bytes().all(|b|b.is_ascii_digit())||name.is_empty()||name.chars().count()>64 {
            return Err("invalid private identity".into());
        }Ok(Self{device_id,pin,name})
    }
    pub fn wire_id(&self,model:&str,address:&str,crypto:&Crypto)->Result<String>{
        let parts:Vec<_>=address.split(':').collect();
        if model.len()!=8||!model.bytes().all(|b|b.is_ascii_hexdigit())||parts.len()!=6
            ||parts.iter().any(|p|p.len()!=2||!p.bytes().all(|b|b.is_ascii_hexdigit())){return Err("invalid model or adapter address".into());}
        let seed=format!("{}{}",model,parts.join("")).to_ascii_uppercase();
        Ok(super::hex(&crypto.sha256(seed.as_bytes())?).to_ascii_uppercase())
    }
    #[cfg(unix)]pub fn load(path:&Path)->Result<Self>{
        use std::{fs::OpenOptions,io::Read,os::unix::fs::{OpenOptionsExt,PermissionsExt}};
        let f=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)
            .open(path).map_err(|_|"cannot open private identity")?;
        let meta=f.metadata().map_err(|_|"cannot stat private identity")?;
        if !meta.is_file()||meta.len()>4096||meta.permissions().mode()&0o077!=0{return Err("identity must be a private regular file".into());}
        let mut data=Vec::new();f.take(4097).read_to_end(&mut data).map_err(|_|"cannot read identity")?;
        let result=Self::parse(&data);wipe(&mut data);result
    }
}
impl Drop for Identity{fn drop(&mut self){unsafe{wipe(self.device_id.as_bytes_mut());wipe(self.pin.as_bytes_mut());}}}

#[cfg(all(test,unix))]mod tests{
    use super::*;use std::{fs,os::unix::fs::{PermissionsExt,symlink}};
    #[test]fn python_schema_is_read_only_and_private(){
        let root=std::env::temp_dir().join(format!("hellocar-id-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir(&root).unwrap();let path=root.join("identity.json");
        let record=serde_json::json!({"schema":1,"device_id":"ab".repeat(32),"pin":"012345","name":"HelloCar 中文"}).to_string();
        fs::write(&path,&record).unwrap();fs::set_permissions(&path,fs::Permissions::from_mode(0o600)).unwrap();
        let id=Identity::load(&path).unwrap();assert_eq!(id.pin,"012345");assert_eq!(id.name,"HelloCar 中文");
        assert_eq!(fs::read(&path).unwrap(),record.as_bytes());
        symlink(&path,root.join("linked")).unwrap();assert!(Identity::load(&root.join("linked")).is_err());
        fs::set_permissions(&path,fs::Permissions::from_mode(0o644)).unwrap();assert!(Identity::load(&path).is_err());
        assert!(Identity::parse(b"{}").is_err());fs::remove_dir_all(root).unwrap();
    }
}
