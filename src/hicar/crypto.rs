//! OpenSSL EVP loaded on demand, after CLI validation selects a crypto operation.
use super::Result;
use libloading::Library;
use std::ffi::{c_void,c_int};
type New=unsafe extern "C" fn()->*mut c_void;
type Free=unsafe extern "C" fn(*mut c_void);
type Init=unsafe extern "C" fn(*mut c_void,*const c_void,*mut c_void,*const u8,*const u8)->c_int;
type Update=unsafe extern "C" fn(*mut c_void,*mut u8,*mut c_int,*const u8,c_int)->c_int;
type Final=unsafe extern "C" fn(*mut c_void,*mut u8,*mut c_int)->c_int;
type Sha=unsafe extern "C" fn(*const u8,usize,*mut u8)->*mut u8;
pub struct Crypto { _library:Library,new:New,free:Free,algorithm:New,init:Init,update:Update,finish:Final,sha:Sha }
impl Crypto {
    pub fn load()->Result<Self>{
        let path=std::env::var_os("HELLOCAR_CRYPTO_LIBRARY").unwrap_or_else(||"libcrypto.so.3".into());
        unsafe{
            let l=Library::new(path).map_err(|_|"cannot load system crypto library")?;
            Ok(Self{new:*l.get(b"EVP_CIPHER_CTX_new\0").map_err(|_|"missing EVP API")?,
                free:*l.get(b"EVP_CIPHER_CTX_free\0").map_err(|_|"missing EVP API")?,
                algorithm:*l.get(b"EVP_aes_128_ctr\0").map_err(|_|"missing AES CTR")?,
                init:*l.get(b"EVP_EncryptInit_ex\0").map_err(|_|"missing EVP API")?,
                update:*l.get(b"EVP_EncryptUpdate\0").map_err(|_|"missing EVP API")?,
                finish:*l.get(b"EVP_EncryptFinal_ex\0").map_err(|_|"missing EVP API")?,
                sha:*l.get(b"SHA256\0").map_err(|_|"missing SHA256")?,_library:l})
        }
    }
    pub fn sha256(&self,data:&[u8])->Result<[u8;32]>{
        let mut out=[0u8;32];
        if unsafe{(self.sha)(data.as_ptr(),data.len().try_into().map_err(|_|"SHA size overflow")?,out.as_mut_ptr())}.is_null(){return Err("SHA256 failed".into());}Ok(out)
    }
    pub fn transform(&self,key:&[u8],iv:&[u8],data:&[u8])->Result<Vec<u8>>{
        if !matches!(key.len(),16|32)||iv.len()!=16||data.is_empty()||data.len()>=10*1024*1024{return Err("invalid cipher record".into());}
        // The context is freed before this dynamic library can be dropped.
        struct Context<'a>(*mut c_void,&'a Crypto);
        impl Drop for Context<'_>{fn drop(&mut self){unsafe{(self.1.free)(self.0);}}}
        let p=unsafe{(self.new)()};if p.is_null(){return Err("cannot allocate EVP context".into());}
        let c=Context(p,self);let mut out=vec![0;data.len()+16];let mut count=0;let mut tail=0;
        unsafe{
            if (self.init)(c.0,(self.algorithm)(),std::ptr::null_mut(),key.as_ptr(),iv.as_ptr())!=1
                ||(self.update)(c.0,out.as_mut_ptr(),&mut count,data.as_ptr(),data.len() as c_int)!=1
                ||count<0||count as usize>data.len()
                ||(self.finish)(c.0,out.as_mut_ptr().add(count as usize),&mut tail)!=1
                ||tail<0||count as usize+tail as usize!=data.len(){return Err("EVP cipher failed".into());}
        }
        out.truncate(data.len());Ok(out)
    }
}
pub fn wipe(data:&mut [u8]){for b in data{unsafe{std::ptr::write_volatile(b,0);}}std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);}
