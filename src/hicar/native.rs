//! Synchronous, thread-confined HiChain adapter. C callbacks never unwind.
use super::{Result,crypto::{Crypto,wipe},json};
use libloading::Library;
use std::{cell::Cell,ffi::{c_void,c_char,CStr},fs::{self,File,OpenOptions},io::{Read,Write,Seek,SeekFrom},
    os::unix::{fs::{DirBuilderExt,OpenOptionsExt,PermissionsExt},io::{AsRawFd,FromRawFd}},path::Path,
    marker::PhantomData,rc::Rc,sync::{Mutex,atomic::{AtomicBool,Ordering}}};

#[repr(C)] struct Blob<const N:usize>{length:u32,value:[u8;N]}
impl<const N:usize> Blob<N>{
    fn empty()->Self{Self{length:0,value:[0;N]}}
    fn from(data:&[u8])->Result<Self>{if data.is_empty()||data.len()>N{return Err("native parameter length outside limit".into());}
        let mut out=Self::empty();out.length=data.len() as u32;out.value[..data.len()].copy_from_slice(data);Ok(out)}
}
#[repr(C)] struct Parameters {own:Blob<64>,peer:Blob<64>,key_length:u32}
#[repr(C)] struct Identity {session_id:u32,package:Blob<256>,service:Blob<256>,context:*mut c_void}
#[repr(C)] struct Buffer {value:*mut c_void,size:u32,length:u32}
#[repr(C)] struct Callbacks {
    transmit:unsafe extern "C" fn(*const Identity,*const u8,u32),
    params:unsafe extern "C" fn(*const Identity,i32,*mut Blob<16>,*mut Parameters),
    key:unsafe extern "C" fn(*const Identity,*const Blob<128>),
    result:unsafe extern "C" fn(*const Identity,i32),
    confirm:unsafe extern "C" fn(*const Identity,i32)->i32,
}
#[repr(C)] struct Files {
    read:unsafe extern "C" fn(*const c_char,u32,*mut u8,u32)->i32,
    write:unsafe extern "C" fn(*const c_char,u32,*const u8,u32)->i32,
    size:unsafe extern "C" fn(*const c_char)->i32,
}
type Get=unsafe extern "C" fn(*const Identity,i32,*const Callbacks)->*mut c_void;
type Destroy=unsafe extern "C" fn(*mut *mut c_void);
type Receive=unsafe extern "C" fn(*mut c_void,*const Buffer)->i32;
type Start=unsafe extern "C" fn(*mut c_void,*const Parameters)->i32;
struct Store{directory:File,udid:[u8;32]}
static STORE:Mutex<Option<Store>>=Mutex::new(None);
static INITIALIZED:AtomicBool=AtomicBool::new(false);
const LIMIT:usize=1048576;
fn file(name:*const c_char,write:bool)->Result<File>{
    if name.is_null(){return Err("null HUKS filename".into());}
    let name=unsafe{CStr::from_ptr(name)};
    if ![b"info1.data".as_slice(),b"info2.data",b"hks_keystore"].contains(&name.to_bytes()){return Err("unexpected HUKS filename".into());}
    let store=STORE.lock().map_err(|_|"HUKS store unavailable")?;
    let store=store.as_ref().ok_or("HUKS store uninitialized")?;
    let mode=if write{libc::O_RDWR|libc::O_CREAT}else{libc::O_RDONLY};
    let fd=unsafe{libc::openat(store.directory.as_raw_fd(),name.as_ptr(),mode|libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK,0o600)};
    if fd<0{return Err(if std::io::Error::last_os_error().kind()==std::io::ErrorKind::NotFound{"missing"}else{"cannot open private HUKS file"}.into());}
    let f=unsafe{File::from_raw_fd(fd)};let meta=f.metadata().map_err(|_|"cannot stat HUKS file")?;
    if !meta.is_file()||meta.len()>LIMIT as u64||meta.permissions().mode()&0o077!=0{return Err("invalid private HUKS file".into());}Ok(f)
}
unsafe extern "C" fn read_file(name:*const c_char,offset:u32,buffer:*mut u8,length:u32)->i32{
    let result=std::panic::catch_unwind(||->Result<i32>{
        if offset as u64+length as u64>LIMIT as u64||buffer.is_null(){return Err("invalid read range".into());}
        let mut f=match file(name,false){Ok(f)=>f,Err(e) if e=="missing"=>return Ok(0),Err(e)=>return Err(e)};
        f.seek(SeekFrom::Start(offset as u64)).map_err(|_|"HUKS seek failed")?;
        f.read(std::slice::from_raw_parts_mut(buffer,length as usize)).map(|n|n as i32).map_err(|_|"HUKS read failed".into())
    });result.ok().and_then(std::result::Result::ok).unwrap_or(-1)
}
unsafe extern "C" fn write_file(name:*const c_char,offset:u32,buffer:*const u8,length:u32)->i32{
    let result=std::panic::catch_unwind(||->Result<i32>{
        if offset as u64+length as u64>LIMIT as u64||buffer.is_null(){return Err("invalid write range".into());}
        let mut f=file(name,true)?;f.seek(SeekFrom::Start(offset as u64)).map_err(|_|"HUKS seek failed")?;
        f.write_all(std::slice::from_raw_parts(buffer,length as usize)).map_err(|_|"HUKS write failed")?;
        f.sync_all().map_err(|_|"HUKS sync failed")?;Ok(0)
    });result.ok().and_then(std::result::Result::ok).unwrap_or(-1)
}
unsafe extern "C" fn file_size(name:*const c_char)->i32{
    std::panic::catch_unwind(||match file(name,false){Ok(f)=>f.metadata().map(|m|m.len() as i32).unwrap_or(-1),Err(e) if e=="missing"=>0,_=>-1}).unwrap_or(-1)
}
unsafe extern "C" fn udid(buffer:*mut u8,length:u32)->i32{
    if buffer.is_null()||length!=32{return -1;}
    let Ok(store)=STORE.lock() else{return -1;};let Some(store)=store.as_ref() else{return -1;};
    std::ptr::copy_nonoverlapping(store.udid.as_ptr(),buffer,32);0
}
static FILES:Files=Files{read:read_file,write:write_file,size:file_size};

pub struct Runtime {
    _library:Library,crypto:Crypto,get:Get,destroy:Destroy,receive:Receive,start:Start,authenticate:Start,
    _thread:PhantomData<Rc<()>>,
}
impl Runtime {
    pub fn open(library:&Path,store:&Path,hardware_seed:&str)->Result<Self>{
        if INITIALIZED.compare_exchange(false,true,Ordering::SeqCst,Ordering::SeqCst).is_err(){return Err("one HUKS runtime per process".into());}
        if hardware_seed.is_empty()||hardware_seed.len()>256{return Err("invalid hardware identity".into());}
        if !store.exists(){fs::DirBuilder::new().recursive(true).mode(0o700).create(store).map_err(|_|"cannot create private HUKS store")?;}
        let directory=OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC).open(store).map_err(|_|"cannot open private HUKS store")?;
        if directory.metadata().map_err(|_|"cannot stat store")?.permissions().mode()&0o077!=0{return Err("HUKS store must be private".into());}
        let crypto=Crypto::load()?;let seed=crypto.sha256(hardware_seed.as_bytes())?;
        let l=unsafe{Library::new(library)}.map_err(|_|"cannot load HiChain library")?;
        unsafe{
            let size:libloading::Symbol<unsafe extern "C" fn(*const c_char)->usize>=l.get(b"carlink_abi_size\0").map_err(|_|"missing ABI size guard")?;
            for (name,n) in [(b"session_identity\0".as_slice(),std::mem::size_of::<Identity>()),
                (b"hc_call_back\0",std::mem::size_of::<Callbacks>()),(b"operation_parameter\0",std::mem::size_of::<Parameters>()),
                (b"hc_pin\0",std::mem::size_of::<Blob<16>>()),(b"hc_session_key\0",std::mem::size_of::<Blob<128>>()),(b"uint8_buff\0",std::mem::size_of::<Buffer>())]{
                if size(name.as_ptr().cast())!=n{return Err("incompatible HiChain ABI".into());}
            }
            let reg:libr::Register=l.get::<libr::Register>(b"hks_register_file_callbacks\0").map(|v|*v).map_err(|_|"missing file registration")?;
            let reg_udid:libr::RegisterUdid=l.get::<libr::RegisterUdid>(b"hks_register_get_hardware_udid_callback\0").map(|v|*v).map_err(|_|"missing UDID registration")?;
            *STORE.lock().map_err(|_|"store lock failed")?=Some(Store{directory,udid:seed});
            if reg(&FILES)!=0||reg_udid(udid)!=0{return Err("native callback registration failed".into());}
            Ok(Self{get:*l.get(b"get_instance\0").map_err(|_|"missing get_instance")?,destroy:*l.get(b"destroy\0").map_err(|_|"missing destroy")?,
                receive:*l.get(b"receive_data\0").map_err(|_|"missing receive_data")?,start:*l.get(b"start_pake\0").map_err(|_|"missing start_pake")?,
                authenticate:*l.get(b"authenticate_peer\0").map_err(|_|"missing authenticate_peer")?,_library:l,crypto,_thread:PhantomData})
        }
    }
}
// Named aliases keep the loaded function types adjacent to registration.
mod libr {
    use super::*;
    pub type Register=unsafe extern "C" fn(*const Files)->i32;
    pub type RegisterUdid=unsafe extern "C" fn(unsafe extern "C" fn(*mut u8,u32)->i32)->i32;
}
impl Drop for Runtime{fn drop(&mut self){if let Ok(mut s)=STORE.lock(){if let Some(s)=s.as_mut(){wipe(&mut s.udid);}*s=None;}}}

struct State {params:Parameters,pin:Blob<16>,pending:Vec<Vec<u8>>,results:Vec<i32>,key:Vec<u8>,failed:bool}
impl Drop for State{fn drop(&mut self){wipe(&mut self.pin.value);wipe(&mut self.key);for p in &mut self.pending{wipe(p);}}}
thread_local!{static CURRENT:Cell<*mut State>=const{Cell::new(std::ptr::null_mut())};}
struct Scope(*mut State);
impl Scope{fn enter(state:*mut State)->Self{Self(CURRENT.with(|c|c.replace(state)))}}
impl Drop for Scope{fn drop(&mut self){CURRENT.with(|c|c.set(self.0));}}
fn callback(f:impl FnOnce(&mut State)){
    CURRENT.with(|c|{let p=c.get();if !p.is_null(){let s=unsafe{&mut *p};
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(||f(s))).is_err(){s.failed=true;}
    }});
}
unsafe extern "C" fn transmit(_: *const Identity,data:*const u8,length:u32){callback(|s|{
    if data.is_null()||length==0||length>65536||s.pending.len()>=8{s.failed=true;return;}
    let bytes=std::slice::from_raw_parts(data,length as usize);
    let result=json::parse(bytes).and_then(|mut v|{
        if !v.is_object(){return Err("auth output must be object".into());}
        if let Some(p)=v.get_mut("payload").and_then(|p|p.as_object_mut()){
            for name in ["peerUserType","keyLength"]{if let Some(value)=p.get_mut(name){if let Some(n)=value.as_str().filter(|v|matches!(*v,"0"|"1"|"16"|"32")){*value=n.parse::<u32>().unwrap().into();}}}
        }serde_json::to_vec(&v).map_err(|_|"invalid auth output".into())
    });match result{Ok(v)=>s.pending.push(v),Err(_)=>s.failed=true}
});}
unsafe extern "C" fn params(_: *const Identity,operation:i32,pin:*mut Blob<16>,parameters:*mut Parameters){callback(|s|{
    if !matches!(operation,0|1|2|99)||pin.is_null()||parameters.is_null(){s.failed=true;return;}
    std::ptr::copy_nonoverlapping(&s.pin,pin,1);std::ptr::copy_nonoverlapping(&s.params,parameters,1);
});}
unsafe extern "C" fn set_key(_: *const Identity,key:*const Blob<128>){callback(|s|{
    if key.is_null()||(*key).length==0||(*key).length>128{s.failed=true;return;}
    wipe(&mut s.key);s.key=(&(*key).value)[..(*key).length as usize].to_vec();
});}
unsafe extern "C" fn result(_: *const Identity,value:i32){callback(|s|{if s.results.len()>=64{s.failed=true;}else{s.results.push(value);}});}
unsafe extern "C" fn confirm(_: *const Identity,operation:i32)->i32{if matches!(operation,1|2){0}else{-1}}
static CALLBACKS:Callbacks=Callbacks{transmit,params,key:set_key,result,confirm};

pub struct Session<'a>{runtime:&'a Runtime,state:Box<State>,identity:Box<Identity>,handle:*mut c_void}
impl<'a> Session<'a>{
    pub fn new(runtime:&'a Runtime,own:&str,peer:&str,pin:&str,role:i32)->Result<Self>{
        if pin.len()!=6||!pin.bytes().all(|b|b.is_ascii_digit())||!matches!(role,1|2){return Err("invalid PIN or auth role".into());}
        let mut state=Box::new(State{params:Parameters{own:Blob::from(own.as_bytes())?,peer:Blob::from(peer.as_bytes())?,key_length:32},
            pin:Blob::from(pin.as_bytes())?,pending:vec![],results:vec![],key:vec![],failed:false});
        static NEXT:std::sync::atomic::AtomicU32=std::sync::atomic::AtomicU32::new(1);
        let identity=Box::new(Identity{session_id:NEXT.fetch_add(1,Ordering::Relaxed),package:Blob::from(b"com.huawei.hicar")?,service:Blob::from(b"CarDevice")?,context:std::ptr::null_mut()});
        let _scope=Scope::enter(&mut *state);let handle=unsafe{(runtime.get)(&*identity,role,&CALLBACKS)};
        if handle.is_null()||state.failed{
            if !handle.is_null(){let mut handle=handle;unsafe{(runtime.destroy)(&mut handle);}}
            return Err("HiChain instance initialization failed".into());
        }
        Ok(Self{runtime,state,identity,handle})
    }
    fn take(&mut self,code:i32)->Result<(i32,Vec<Vec<u8>>)>{if self.state.failed{return Err("invalid native callback".into());}Ok((code,std::mem::take(&mut self.state.pending)))}
    pub fn start(&mut self,trusted:bool)->Result<(i32,Vec<Vec<u8>>)>{
        self.state.params.key_length=if trusted{16}else{32};let _scope=Scope::enter(&mut *self.state);
        // C may synchronously call back into State. Pass a separate C-layout
        // value so no Rust reference into State spans that callback.
        let parameters=unsafe{std::ptr::read(&self.state.params)};
        let code=unsafe{(if trusted{self.runtime.authenticate}else{self.runtime.start})(self.handle,&parameters)};self.take(code)
    }
    pub fn receive(&mut self,bytes:&[u8])->Result<(i32,Vec<Vec<u8>>)>{
        let mut request=json::parse(bytes)?;
        if !request.is_object(){return Err("native input must be an object".into());}
        if let Some(p)=request.get_mut("payload").and_then(|v|v.as_object_mut()){
            if let Some(value)=p.get_mut("peerUserType"){if let Some(n)=value.as_str().filter(|v|matches!(*v,"0"|"1")){*value=n.parse::<u32>().unwrap().into();}}
        }
        if request.get("message").and_then(|v|v.as_u64())==Some(17){
            let value=&request["payload"]["keyLength"];
            let n=value.as_u64().or_else(||value.as_str().and_then(|s|match s{"16"=>Some(16),"32"=>Some(32),_=>None}));
            self.state.params.key_length=match n{Some(n @ (16|32))=>n as u32,_=>return Err("invalid STS key length".into())};
        }
        let mut raw=serde_json::to_vec(&request).map_err(|_|"invalid native input")?;
        if raw.len()>65536{return Err("native input exceeds limit".into());}
        let buffer=Buffer{value:raw.as_mut_ptr().cast(),size:raw.len() as u32,length:raw.len() as u32};
        let _scope=Scope::enter(&mut *self.state);let code=unsafe{(self.runtime.receive)(self.handle,&buffer)};wipe(&mut raw);self.take(code)
    }
    pub fn results(&self)->&[i32]{&self.state.results}
    /// Only the bounded private runtime IPC may export a key to the old media adapter.
    pub(super) fn key_for_bridge(&self)->Option<Vec<u8>>{
        if matches!(self.state.key.len(),16|32)&&self.state.results.contains(&0)&&!self.state.results.contains(&1){Some(self.state.key.clone())}else{None}
    }
    pub fn key_summary(&self)->Result<Option<(String,usize)>>{
        if self.state.key.is_empty(){Ok(None)}else{Ok(Some((super::hex(&self.runtime.crypto.sha256(&self.state.key)?),self.state.key.len())))}
    }
}
impl Drop for Session<'_>{fn drop(&mut self){let _scope=Scope::enter(&mut *self.state);unsafe{(self.runtime.destroy)(&mut self.handle);}
    // Keep the copied identity alive through destroy, matching the C contract.
    self.identity.context=std::ptr::null_mut();}}

#[cfg(test)]mod tests{
    use super::*;
    #[test]fn bounded_parameters_and_callback_policy(){
        assert!(Blob::<16>::from(&[1;17]).is_err());assert!(Blob::<16>::from(&[]).is_err());
        assert_eq!(unsafe{confirm(std::ptr::null(),1)},0);assert_eq!(unsafe{confirm(std::ptr::null(),99)},-1);
        assert_eq!(unsafe{read_file(std::ptr::null(),0,std::ptr::null_mut(),0)},-1);
    }
    #[test]fn private_store_callbacks_reject_links_permissions_and_overflow(){
        use std::{ffi::CString,os::unix::fs::symlink};
        let root=std::env::temp_dir().join(format!("hellocar-huks-{}-{}",std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        *STORE.lock().unwrap()=Some(Store{directory:File::open(&root).unwrap(),udid:[1;32]});
        let name=CString::new("info1.data").unwrap();let mut data=[0u8;8];
        assert_eq!(unsafe{write_file(name.as_ptr(),0,b"abc".as_ptr(),3)},0);
        assert_eq!(unsafe{read_file(name.as_ptr(),0,data.as_mut_ptr(),8)},3);
        assert_eq!(&data[..3],b"abc");assert_eq!(unsafe{file_size(name.as_ptr())},3);
        assert_eq!(unsafe{write_file(name.as_ptr(),u32::MAX,b"a".as_ptr(),1)},-1);
        fs::set_permissions(root.join("info1.data"),fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(unsafe{read_file(name.as_ptr(),0,data.as_mut_ptr(),8)},-1);
        symlink(root.join("info1.data"),root.join("info2.data")).unwrap();
        let link=CString::new("info2.data").unwrap();assert_eq!(unsafe{file_size(link.as_ptr())},-1);
        let traversal=CString::new("../info1.data").unwrap();assert_eq!(unsafe{file_size(traversal.as_ptr())},-1);
        *STORE.lock().unwrap()=None;fs::remove_dir_all(root).unwrap();
    }
}
