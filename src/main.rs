#![feature(panic_info_message, default_alloc_error_handler)]
#![no_std]
#![no_main]
#![windows_subsystem = "console"]

use core::mem::{size_of, MaybeUninit};
use core::{
    ffi::c_void,
    ptr::{addr_of, addr_of_mut, null, null_mut},
};
extern crate alloc;
use alloc::alloc::{GlobalAlloc, Layout};
use alloc::vec::Vec;
use ufmt_write::uWrite;
use windows_sys::w;
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::WriteFile,
    System::{
        Console::{GetStdHandle, STD_ERROR_HANDLE},
        Diagnostics::Debug::{
            FormatMessageA, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
            FORMAT_MESSAGE_IGNORE_INSERTS,
        },
        Environment::{GetCommandLineW, GetEnvironmentVariableW},
        JobObjects::*,
        Memory::{GetProcessHeap, HeapAlloc, HeapFree, HeapReAlloc, HEAP_ZERO_MEMORY},
        Threading::{ExitProcess, GetStartupInfoW, STARTUPINFOW},
    },
};

#[no_mangle]
#[used]
static _fltused: i32 = 0;

struct SystemAlloc;

#[global_allocator]
static SYSTEM_ALLOC: SystemAlloc = SystemAlloc;

unsafe impl Sync for SystemAlloc {}
unsafe impl GlobalAlloc for SystemAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        HeapAlloc(GetProcessHeap(), 0, layout.size()) as *mut u8
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        HeapFree(GetProcessHeap(), 0, ptr as *const c_void);
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, layout.size()) as *mut u8
    }
    unsafe fn realloc(&self, ptr: *mut u8, _layout: Layout, new_size: usize) -> *mut u8 {
        HeapReAlloc(GetProcessHeap(), 0, ptr as *const c_void, new_size) as *mut u8
    }
}

// In dev builds, the linker expects this symbol to exist. The value doesn't matter, because
// it's never actually *used* when panic="abort". And in release builds, the optimizer is
// clever enough to realize this, and remove all references to it. But in dev builds, having
// it defined as *something* lets the link finish.
// #[no_mangle]
// unsafe fn __CxxFrameHandler3(_rec: c_void, _node: c_void, _context: c_void, _pdc: c_void) -> i32 {
//     0
// }

struct StdErr;
impl StdErr {
    fn write_bytes(&mut self, s: &[u8]) -> Result<(), ()> {
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

impl uWrite for StdErr {
    type Error = ();

    fn write_str(&mut self, s: &str) -> Result<(), ()> {
        self.write_bytes(s.as_bytes())
    }
}

macro_rules! whine {
    ($($tt:tt)*) => {{
        _ = ufmt::uwriteln!(StdErr, $($tt)*);
    }}
}

#[panic_handler]
pub extern "C" fn panic(info: &core::panic::PanicInfo) -> ! {
    if let Some(location) = info.location() {
        whine!(
            "panic at {}:{} column {}",
            location.file(),
            location.line(),
            location.column()
        );
    }
    if let Some(msg) = info.message() {
        if let Some(msg_str) = msg.as_str() {
            whine!("message: {}", msg_str);
        }
    }
    unsafe {
        ExitProcess(128);
    }
}

macro_rules! check {
    ($e:expr) => {
        if $e != 0 {
            whine!(
        }
    }
}

fn check(ok: i32) {
    if ok == 0 {
        unsafe {
            let err = GetLastError();
            let mut msg_ptr: *mut u16 = null_mut();
            let size = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER
                    | FORMAT_MESSAGE_FROM_SYSTEM
                    | FORMAT_MESSAGE_IGNORE_INSERTS,
                null(),
                err,
                0,
                // Super weird calling convention: this argument is typed as *mut u16,
                // but if you pass FORMAT_MESSAGE_ALLOCATE_BUFFER then you have to
                // *actually* pass in a *mut *mut u16 and just lie about the type.
                addr_of_mut!(msg_ptr) as *mut _ as _,
                0,
                null(),
            );
            let msg = core::slice::from_raw_parts(msg_ptr, size as usize);
            _ = StdErr.write_bytes(msg);
            _ = StdErr.write_bytes(b"\n");
            panic!();
        }
    }
}

unsafe fn wstr_to_slice(start: *const u16) -> &'static [u16] {
    let mut len = 0usize;
    let mut ptr = start;
    while *ptr != 0 {
        len += 1;
        ptr = ptr.offset(1);
    }
    core::slice::from_raw_parts(start, len)
}

unsafe fn dump_wstr(wstr: &[u16]) {
    for char in wstr.iter() {
        if *char == 0 {
            break;
        }
        _ = StdErr.write_bytes(&[*char as u8]);
    }
    _ = StdErr.write_bytes(b"\n");
}

fn getenv(name: *const u16) -> Option<Vec<u16>> {
    unsafe {
        let count = GetEnvironmentVariableW(name, null_mut(), 0);
        if count == 0 {
            return None;
        }
        let mut value = Vec::<u16>::with_capacity(count as usize);
        GetEnvironmentVariableW(name, value.as_mut_ptr(), value.capacity() as u32);
        value.set_len((count - 1) as usize);
        return Some(value);
    }
}

const DQUOTE: u16 = '"' as u16;
const SPACE: u16 = ' ' as u16;

pub trait SizeOf {
    fn size_of(&self) -> u32;
}

impl<T: Sized> SizeOf for T {
    fn size_of(&self) -> u32 {
        size_of::<T>() as u32
    }
}

// for subsystem = "windows", need to either rename this to WinMainCRTStartup, or
// somehow set /ENTRYPOINT in linker
#[no_mangle]
pub extern "C" fn mainCRTStartup() -> ! {
    unsafe {
        let cmdline = wstr_to_slice(GetCommandLineW());
        whine!("chars in cmdline: {}", cmdline.len());
        dump_wstr(&cmdline);

        // ...don't actually need filename really, I guess!
        // if put script in a zip file with a single element named __main__.py, and
        // append that file to the executable, then can do 'python foo.exe' and it runs,
        // and has sys.argv[0] == 'foo.exe'. So as long as we can find python, don't
        // need to examine self at all. just prepend python path to cmdline and go.
        // (for different python-finding strategies: either have multiple trampoline
        // binaries, or put a unique blob into the binary and then search/replace it
        // when writing it out)
        // also lets us skip parsing the command line!

        // XX no unwrap
        let python_exe = getenv(w!["POSY_PYTHON"]).unwrap();
        dump_wstr(&python_exe.as_slice());

        let mut new_cmdline = Vec::<u16>::new();
        new_cmdline.push(DQUOTE);
        for char in python_exe {
            if char == DQUOTE {
                new_cmdline.extend(&[DQUOTE, DQUOTE, DQUOTE]);
            } else {
                new_cmdline.push(char);
            }
        }
        new_cmdline.push(DQUOTE);
        new_cmdline.push(SPACE);
        new_cmdline.extend(cmdline.iter());
        dump_wstr(new_cmdline.as_slice());

        let job = CreateJobObjectW(null(), null());
        let mut job_info = MaybeUninit::<JOBOBJECT_BASIC_LIMIT_INFORMATION>::uninit();
        let mut retlen = 0u32;
        let ok = QueryInformationJobObject(
            job,
            JobObjectBasicLimitInformation,
            job_info.as_mut_ptr() as *mut _,
            job_info.size_of(),
            &mut retlen as *mut _,
        );
        if ok == 0 || retlen != job_info.size_of() {
            panic!("QueryInformationJobObject failed");
        }
        let mut job_info = job_info.assume_init();
        job_info.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        job_info.LimitFlags |= JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
        check(SetInformationJobObject(
            job,
            JobObjectBasicLimitInformation,
            addr_of!(job_info) as *const _,
            job_info.size_of(),
        ));
        assert!(ok != 0, "SetInformationJobObject failed");

        let mut si = MaybeUninit::<STARTUPINFOW>::uninit();
        GetStartupInfoW(si.as_mut_ptr());

        // CreateJobObject
        // make handles inheritable
        // CreateProcessW
        // AssignProcessToJobObject
        // SetConsoleCtrlHandler
        // clear_app_starting_state
        // close handles, chdir

        ExitProcess(3);
    }
}
