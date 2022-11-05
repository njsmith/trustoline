//#![feature(panic_info_message)]
#![no_std]
#![no_main]
#![windows_subsystem = "console"]

use core::{
    ffi::c_void,
    ptr::null_mut,
};
use windows_sys::Win32::{
    Storage::FileSystem::WriteFile,
    System::{
        Console::{GetStdHandle, STD_ERROR_HANDLE},
        Threading::ExitProcess,
    },
};
use ufmt_write::uWrite;
use ufmt::uwriteln;

#[no_mangle]
#[used]
static _fltused: i32 = 0;

// In dev builds, the linker expects this symbol to exist. The value doesn't matter, because
// it's never actually *used* when panic="abort". And in release builds, the optimizer is
// clever enough to realize this, and remove all references to it. But in dev builds, having
// it defined as *something* lets the link finish.
#[no_mangle]
#[used]
static __CxxFrameHandler3: i32 = 0;

struct StdErr;
impl uWrite for StdErr {
    type Error = ();

    fn write_str(&mut self, s: &str) -> Result<(), ()> {
        unsafe {
            let handle = GetStdHandle(STD_ERROR_HANDLE);
            let mut written: u32 = 0;
            let mut remaining = s;
            while !remaining.is_empty() {
                let ok = WriteFile(
                    handle,
                    remaining.as_ptr() as *const c_void,
                    remaining.len() as u32,
                    &mut written,
                    null_mut(),
                );
                if ok == 0 {
                    return Err(());
                }
                remaining = &remaining[written as usize..];
            }
            Ok(())
        }
    }
}

#[panic_handler]
pub extern "C" fn panic(info: &core::panic::PanicInfo) -> ! {
    //if let Some(location) = info.location() {
    //    _ = uwriteln!(&mut StdErr, "panic at {}:{}", location.file(), location.line());
    //}
    //if let Some(msg) = info.message() {
    //    if let Some(msg_str) = msg.as_str() {
    //        //_ = uwriteln!(&mut StdErr, "message: {}", msg_str);
    //    }
    //}
    unsafe {
        ExitProcess(128);
    }
}

// for subsystem = "windows", need to either rename this to WinMainCRTStartup, or
// somehow set /ENTRYPOINT in linker
#[no_mangle]
pub extern "C" fn mainCRTStartup() -> ! {
    _ = uwriteln!(StdErr, "hello world\n");
    panic!("outta here\n");
    //unsafe {
    //    ExitProcess(3);
    //}
}
