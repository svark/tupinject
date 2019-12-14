extern crate detours_sys as detours;

// #[cfg(windows)]
// extern crate ntapi;
// extern crate kernel32;
// extern crate advapi32;

#[cfg(windows)]
#[macro_use]
extern crate winapi;

// pub mod injectdylib;
use std::io::Error;
#[cfg(windows)]
use winapi::{
    shared::minwindef::{BOOL, DWORD, FALSE, HINSTANCE, LPVOID, TRUE,
                        HMODULE
    },
    um::processthreadsapi::GetCurrentThread,
    um::winnt::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
};
pub mod traps;

pub trait IHookProcessor {
    fn need_skip(&self) -> bool;
    fn attach_hooks(&self) -> Result<(), Error>;
    fn detach_hooks(&self);
}
// type HookMapT = Vec<(*mut LPVOID, LPVOID)>;
// use std::collections::HashMap;
// type FunctionMapT = HashMap<LPVOID, *mut LPVOID>;
struct DetoursProcessor {
    trap_info : traps::TrapInfo,
    // m_function_map: FunctionMapT,
}
struct DetoursTransaction;
impl DetoursTransaction {
    pub fn new() -> Result<DetoursTransaction, Error> {
        if unsafe { detours::DetourTransactionBegin() } != 0 {
            return Err(Error::last_os_error());
        }
        if unsafe { detours::DetourUpdateThread(GetCurrentThread() as _) } != 0 {
            return Err(Error::last_os_error());
        }
        Ok(DetoursTransaction)
    }
}
impl Drop for DetoursTransaction {
    fn drop(&mut self) {
        unsafe { detours::DetourTransactionCommit() };
    }
}

impl DetoursProcessor {
    pub fn new(hmod: HMODULE) -> DetoursProcessor {
        let processor = DetoursProcessor {
            trap_info: traps::TrapInfo::new(hmod),
        };
        // let functions: HookMapT = vec![];
        // for func in functions.iter() {
        //     processor.setup_trap(func.0, func.1);
        // }
        processor
    }
    pub fn attach(&self)
    {
        unsafe {self.trap_info.attach()};
    }
    pub fn detach(&self)
    {
        unsafe {self.trap_info.detach()};
    }
}
impl IHookProcessor for DetoursProcessor {
    fn need_skip(&self) -> bool {
        unsafe { detours::DetourIsHelperProcess() == 1 }
    }

    fn attach_hooks(&self) -> Result<(), Error> {
        if unsafe { detours::DetourRestoreAfterWith() == 0 } {
            return Err(Error::last_os_error());
        }

        let _ = DetoursTransaction::new();
        self.attach();
        Ok(())
    }
    fn detach_hooks(&self) {
        let _ = DetoursTransaction::new();
        self.detach();
    }
}
pub fn dll_processor(processor: &mut impl IHookProcessor, reason: DWORD) -> BOOL {
    if processor.need_skip() {
        return TRUE;
    }
    match reason {
        DLL_PROCESS_ATTACH => {
            if let Err(_) = processor.attach_hooks() {
                return FALSE;
            }
        }
        DLL_PROCESS_DETACH => {
            processor.detach_hooks();
        }
        _ => {
            return FALSE;
        }
    }

    return TRUE;
}
#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: DWORD, reserved: LPVOID) -> BOOL {
    let mut detours_processor: DetoursProcessor = DetoursProcessor::new(dll_module);
    dll_processor(&mut detours_processor, call_reason)
}
