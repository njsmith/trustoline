use core::mem::MaybeUninit;
use core::{
    ffi::CStr,
    ptr::{addr_of, addr_of_mut, null, null_mut},
};
extern crate alloc;
use crate::helper::SizeOf;
use crate::{c, check, eprintln};
use alloc::{ffi::CString, vec::Vec};
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::Environment::SetCurrentDirectoryA;
use windows_sys::Win32::{
    Foundation::*,
    System::{
        Environment::{GetCommandLineA, GetEnvironmentVariableA},
        JobObjects::*,
        Threading::*,
        WindowsProgramming::INFINITE,
    },
};

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

fn make_child_cmdline(is_gui: bool) -> Vec<u8> {
    unsafe {
        let my_cmdline = CStr::from_ptr(GetCommandLineA() as _);

        let envvar = if is_gui {
            c!("POSY_PYTHONW")
        } else {
            c!("POSY_PYTHON")
        };
        let python_exe = getenv(&envvar);
        if python_exe.is_none() {
            eprintln!(
                "need {} to be set",
                core::str::from_utf8_unchecked(envvar.to_bytes())
            );
            ExitProcess(1);
        }
        let python_exe = python_exe.unwrap_unchecked();

        let mut child_cmdline = Vec::<u8>::new();
        child_cmdline.push('"' as u8);
        for byte in python_exe.as_bytes() {
            if *byte == '"' as u8 {
                // 3 double quotes: one to end the quoted span, one to become a literal double-quote,
                // and one to start a new quoted span.
                child_cmdline.extend(br#"""""#);
            } else {
                child_cmdline.push(*byte);
            }
        }
        child_cmdline.extend(br#"" "#);
        child_cmdline.extend(my_cmdline.to_bytes_with_nul());
        //eprintln!("new_cmdline: {}", core::str::from_utf8_unchecked(new_cmdline.as_slice()));
        child_cmdline
    }
}

fn make_job_object() -> HANDLE {
    unsafe {
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
        job
    }
}

fn spawn_child(si: &STARTUPINFOA, child_cmdline: &mut [u8]) -> HANDLE {
    unsafe {
        if si.dwFlags & STARTF_USESTDHANDLES == 0 {
            // ignore errors from these -- if the handle's not inheritable/not valid, then nothing
            // we can do
            SetHandleInformation(si.hStdInput, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
            SetHandleInformation(si.hStdOutput, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
            SetHandleInformation(si.hStdError, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        }
        let mut child_process_info = MaybeUninit::<PROCESS_INFORMATION>::uninit();
        check!(CreateProcessA(
            null(),
            // Why does this have to be mutable? Who knows. But it's not a mistake --
            // MS explicitly documents that this buffer might be mutated by CreateProcess.
            child_cmdline.as_mut_ptr(),
            null(),
            null(),
            1,
            0,
            null(),
            null(),
            addr_of!(*si),
            child_process_info.as_mut_ptr(),
        ));
        let child_process_info = child_process_info.assume_init();
        CloseHandle(child_process_info.hThread);
        child_process_info.hProcess
    }
}

pub fn bounce(is_gui: bool) -> ! {
    unsafe {
        let mut child_cmdline = make_child_cmdline(is_gui);
        let job = make_job_object();

        let mut si = MaybeUninit::<STARTUPINFOA>::uninit();
        GetStartupInfoA(si.as_mut_ptr());
        let si = si.assume_init();

        let child_handle = spawn_child(&si, child_cmdline.as_mut_slice());
        check!(AssignProcessToJobObject(job, child_handle));

        // (best effort) Switch to some innocuous directory so we don't hold the original
        // cwd open.
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

        WaitForSingleObject(child_handle, INFINITE);
        let mut exit_code = 0u32;
        check!(GetExitCodeProcess(child_handle, addr_of_mut!(exit_code)));
        ExitProcess(exit_code);

        // still need to:
        // - close inherited handles (stdio + lpReserved2)

        // and for GUI support:
        // - pump messages after child started
    }
}
