extern crate detours_sys as detours;
extern crate named_pipe;
#[macro_use]
extern crate wstr;
#[cfg(windows)]
// #[macro_use]
extern crate winapi;
extern crate ntapi;
// pub mod injectdylib;
use std::io::Error;
#[cfg(windows)]
use winapi::{
    shared::minwindef::{BOOL, DWORD, FALSE, LPVOID, TRUE},
    um::processthreadsapi::GetCurrentThread,
    um::winnt::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
};
use detours::{HMODULE,HINSTANCE };
pub mod traps;

pub trait IHookProcessor {
    fn need_skip(&self) -> bool;
    fn attach_hooks(&self) -> Result<(), Error>;
    fn detach_hooks(&self) -> Result<(), Error>;
}

#[derive(Default)]
struct DetoursProcessor {
    trap_info: traps::TrapInfo,
}
struct DetoursTransaction;
impl DetoursTransaction {
    pub fn new() -> Result<DetoursTransaction, Error> {
        if unsafe { detours::DetourTransactionBegin() } != 0 {
            println!("error!");
            return Err(Error::last_os_error());
        }
        if unsafe { detours::DetourUpdateThread(GetCurrentThread() as _) } != 0 {
            return Err(Error::last_os_error());
        }
        Ok(DetoursTransaction)
    }

    pub fn commit(&self) {
        unsafe { detours::DetourTransactionCommit() };
    }
}
impl DetoursProcessor {
    pub fn new(hmod: HMODULE) -> DetoursProcessor {
        let processor = DetoursProcessor {
            trap_info: traps::TrapInfo::new(hmod),
        };
        processor
    }
    pub fn attach(&self, _: &DetoursTransaction) {
        unsafe { self.trap_info.attach() };
    }
    pub fn detach(&self, _: &DetoursTransaction) {
        unsafe { self.trap_info.detach() };
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

        let trans = DetoursTransaction::new()?;
        self.attach(&trans);
        trans.commit();
        Ok(())
    }
    fn detach_hooks(&self) -> Result<(), Error> {
        let trans = DetoursTransaction::new()?;
        self.detach(&trans);
        trans.commit();
        Ok(())
    }
}
pub fn dll_processor(dll_module: HINSTANCE, reason: DWORD) -> BOOL {
    // let inst :HMODULE = 0 as _;

    match reason {
        DLL_PROCESS_ATTACH => {
            let processor = DetoursProcessor::new(dll_module);
            if (processor).need_skip() {
                return TRUE;
            }
            if let Err(_) = (processor).attach_hooks() {
                return FALSE;
            }
        }
        DLL_PROCESS_DETACH => {
            let processor = DetoursProcessor::new(dll_module);
            if processor.need_skip() {
                return TRUE;
            }
            if let Err(_) = processor.detach_hooks() {
                return FALSE;
            }
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
    dll_processor(dll_module, call_reason)
}
