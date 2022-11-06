#![feature(panic_info_message, default_alloc_error_handler)]
#![no_std]
#![no_main]
#![windows_subsystem = "console"]

use core::mem::{size_of, MaybeUninit};
use core::{
    ffi::{c_void, CStr},
    ptr::{addr_of, addr_of_mut, null, null_mut},
};
extern crate alloc;
use alloc::alloc::{GlobalAlloc, Layout};
use alloc::ffi::CString;
use alloc::vec::Vec;
use ufmt_write::uWrite;
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::Environment::SetCurrentDirectoryA;
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::WriteFile,
    System::{
        Console::{GetStdHandle, STD_ERROR_HANDLE},
        Diagnostics::Debug::{
            FormatMessageA, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
            FORMAT_MESSAGE_IGNORE_INSERTS,
        },
        Environment::{GetCommandLineA, GetEnvironmentVariableA},
        JobObjects::*,
        Memory::{GetProcessHeap, HeapAlloc, HeapFree, HeapReAlloc, HEAP_ZERO_MEMORY},
        Threading::*,
        WindowsProgramming::INFINITE,
    },
};

// Windows wants this symbol. It has something to do with floating point usage?
// idk, defining it gets rid of link errors.
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

macro_rules! eprintln {
    ($($tt:tt)*) => {{
        _ = ufmt::uwriteln!(StdErr, $($tt)*);
    }}
}

#[panic_handler]
pub extern "C" fn panic(info: &core::panic::PanicInfo) -> ! {
    if let Some(location) = info.location() {
        eprintln!(
            "panic at {}:{} column {}",
            location.file(),
            location.line(),
            location.column()
        );
    }
    if let Some(msg) = info.message() {
        if let Some(msg_str) = msg.as_str() {
            eprintln!("message: {}", msg_str);
        }
    }
    unsafe {
        ExitProcess(128);
    }
}

macro_rules! check {
    ($e:expr) => {
        if $e == 0 {
            let err = GetLastError();
            let mut msg_ptr: *mut u8 = null_mut();
            let size = FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER
                    | FORMAT_MESSAGE_FROM_SYSTEM
                    | FORMAT_MESSAGE_IGNORE_INSERTS,
                null(),
                err,
                0,
                // Weird calling convention: this argument is typed as *mut u16,
                // but if you pass FORMAT_MESSAGE_ALLOCATE_BUFFER then you have to
                // *actually* pass in a *mut *mut u16 and just lie about the type.
                // Getting Rust to do this requires some convincing.
                addr_of_mut!(msg_ptr) as *mut _ as _,
                0,
                null(),
            );
            let msg = core::slice::from_raw_parts(msg_ptr, size as usize);
            let msg = core::str::from_utf8_unchecked(msg);
            eprintln!("Error: {} (from {})", msg, stringify!($e));
            ExitProcess(1);
        }
    }
}

macro_rules! c {
    ($s:literal) => {
        CStr::from_bytes_with_nul_unchecked(concat!($s, "\0").as_bytes())
    };
}

fn getenv(name: &CStr) -> Option<CString> {
    unsafe {
        let count = GetEnvironmentVariableA(name.as_ptr() as _, null_mut(), 0);
        if count == 0 {
            return None;
        }
        let mut value = Vec::<u8>::with_capacity(count as usize);
        GetEnvironmentVariableA(
            name.as_ptr() as _,
            value.as_mut_ptr(),
            value.capacity() as u32,
        );
        value.set_len(count as usize);
        return Some(CString::from_vec_with_nul_unchecked(value));
    }
}

pub trait SizeOf {
    fn size_of(&self) -> u32;
}

impl<T: Sized> SizeOf for T {
    fn size_of(&self) -> u32 {
        size_of::<T>() as u32
    }
}

// build.rs passes a custom linker flag to make this the entrypoint to the executable
#[no_mangle]
pub extern "C" fn entry() -> ! {
    unsafe {
        let cmdline = CStr::from_ptr(GetCommandLineA() as _);

        // ...don't actually need filename really, I guess!
        // if put script in a zip file with a single element named __main__.py, and
        // append that file to the executable, then can do 'python foo.exe' and it runs,
        // and has sys.argv[0] == 'foo.exe'. So as long as we can find python, don't
        // need to examine self at all. just prepend python path to cmdline and go.
        // (for different python-finding strategies: either have multiple trampoline
        // binaries, or put a unique blob into the binary and then search/replace it
        // when writing it out)
        // also lets us skip parsing the command line!

        let python_exe = getenv(c!("POSY_PYTHON"));
        if python_exe.is_none() {
            eprintln!("need POSY_PYTHON to be set");
            ExitProcess(1);
        }
        let python_exe = python_exe.unwrap_unchecked();

        let mut new_cmdline = Vec::<u8>::new();
        new_cmdline.push('"' as u8);
        for byte in python_exe.as_bytes() {
            if *byte == '"' as u8 {
                // 3 double quotes: one to end the quoted span, one to become a literal double-quote,
                // and one to start a new quoted span.
                new_cmdline.extend(br#"""""#);
            } else {
                new_cmdline.push(*byte);
            }
        }
        new_cmdline.extend(br#"" "#);
        new_cmdline.extend(cmdline.to_bytes_with_nul());
        //eprintln!("new_cmdline: {}", core::str::from_utf8_unchecked(new_cmdline.as_slice()));

        let job = CreateJobObjectW(null(), null());
        let mut job_info = MaybeUninit::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>::uninit();
        let mut retlen = 0u32;
        check!(QueryInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            job_info.as_mut_ptr() as *mut _,
            job_info.size_of(),
            &mut retlen as *mut _,
        ));
        let mut job_info = job_info.assume_init();
        job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
        check!(SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            addr_of!(job_info) as *const _,
            job_info.size_of(),
        ));

        let mut si = MaybeUninit::<STARTUPINFOA>::uninit();
        GetStartupInfoA(si.as_mut_ptr());
        let si = si.assume_init();
        if si.dwFlags & STARTF_USESTDHANDLES == 0 {
            // ignore errors from these -- if the handle's not inheritable/not valid, then nothing
            // we can do
            SetHandleInformation(si.hStdInput, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
            SetHandleInformation(si.hStdOutput, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
            SetHandleInformation(si.hStdError, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        }
        let mut child_process_info = MaybeUninit::<PROCESS_INFORMATION>::uninit();
        check!(CreateProcessA(
            python_exe.as_ptr() as *const _,
            new_cmdline.as_mut_ptr(),
            null(),
            null(),
            1,
            0,
            null(),
            null(),
            addr_of!(si),
            child_process_info.as_mut_ptr(),
        ));
        let child_process_info = child_process_info.assume_init();
        check!(AssignProcessToJobObject(job, child_process_info.hProcess));
        
        CloseHandle(child_process_info.hThread);
        if let Some(tmp) = getenv(c!("TEMP")) {
            SetCurrentDirectoryA(tmp.as_ptr() as *const _);
        } else {
            SetCurrentDirectoryA(c!("c:\\").as_ptr() as *const _);
        }

        // We want to ignore control-C/control-Break/logout/etc.; the same event will
        // be delivered to the child, so we let them decide whether to exit or not.
        unsafe extern "system" fn control_key_handler(_: u32) -> BOOL {
            1
        }
        SetConsoleCtrlHandler(Some(control_key_handler), 1);

        WaitForSingleObject(child_process_info.hProcess, INFINITE);
        let mut exit_code = 0u32;
        check!(GetExitCodeProcess(child_process_info.hProcess, addr_of_mut!(exit_code)));
        ExitProcess(exit_code);

        // still need to:
        // - close inherited handles (stdio + lpReserved2)

        // and for GUI support:
        // - feature flag I guess?
        // - POSY_PYTHONW instead of POSY_PYTHON
        // - pump messages after child started
    }
}
