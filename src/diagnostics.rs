use core::{ptr::null_mut, ffi::c_void};

use ufmt_write::uWrite;
use windows_sys::Win32::{System::Console::{GetStdHandle, STD_ERROR_HANDLE}, Storage::FileSystem::WriteFile};


pub struct StdErr;

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
                remaining = &remaining.get_unchecked(written as usize..);
            }
            Ok(())
        }
    }
}

#[macro_export]
macro_rules! eprintln {
    ($($tt:tt)*) => {{
        _ = ufmt::uwriteln!(crate::diagnostics::StdErr, $($tt)*);
    }}
}
