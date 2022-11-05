#![no_std]
#![no_main]
#![windows_subsystem = "console"]

use core::panic::PanicInfo;
use windows_sys::Win32::System::Threading::ExitProcess;

#[panic_handler]
pub extern fn panic(_info: &PanicInfo) -> ! { loop {} }

#[no_mangle]
pub extern fn mainCRTStartup() -> ! {
    unsafe { ExitProcess(3); }
}