#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
//     //TODO:                          SetFileInformationByHandle
use detours::LPPROCESS_INFORMATION;
use detours::LPSTARTUPINFOA;
use detours::LPSTARTUPINFOW;
use detours::_PROCESS_INFORMATION as PROCESS_INFORMATION;
use named_pipe::PipeClient;
use std::io::Write;
use winapi::shared::ntdef::{NTSTATUS, PHANDLE, PLARGE_INTEGER, POBJECT_ATTRIBUTES};
use winapi::um::libloaderapi::{GetModuleFileNameW};
use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};
use winapi::um::processthreadsapi::{GetCurrentProcess, GetCurrentProcessId, GetCurrentThread};
use winapi::um::winnt::ACCESS_MASK;

use detours::LPSECURITY_ATTRIBUTES;
use detours::_GUID as GUID;
use detours::{HINSTANCE, HMODULE};
use ntapi::ntioapi::PIO_STATUS_BLOCK;
use winapi::um::fileapi::INVALID_FILE_ATTRIBUTES;
use winapi::um::winnt::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_TEMPORARY};
use winapi::{
    shared::minwindef::{BOOL, DWORD, FALSE, FARPROC, LPBOOL, LPVOID, TRUE, UINT, ULONG},
    um::minwinbase::GET_FILEEX_INFO_LEVELS,
    um::winbase::{COPYFILE2_EXTENDED_PARAMETERS, LPOFSTRUCT, LPPROGRESS_ROUTINE},
    um::winnt::{
        DELETE, FILE_APPEND_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
        GENERIC_WRITE, HANDLE, HRESULT, LPCSTR, LPCWSTR, LPSTR, LPWSTR, PCHAR, PCSTR, PCWSTR,
        PVOID, PWCHAR, WCHAR, WRITE_DAC, WRITE_OWNER,
    },
    // um::synchapi::{InitializeCriticalSection},
};
macro_rules! attach_proc {
    ($dll:ident, $lit:literal, $e:ident, $m:ident) => {
        let realapi = GetProcAddress($dll as _, $lit.as_ptr() as _);
        $e = std::mem::transmute(realapi);
        detours::DetourAttach(&$e as *const _ as _, ($m as *const ()) as _);
    };
}

macro_rules! detach_proc {
    ($e:ident, $m:ident) => {
        if $e != std::ptr::null_mut() {
            detours::DetourDetach(&$e as *const _ as _, ($m as *const ()) as _);
        }
    };
}
// use detours::

// {9640B7B0-CA4D-4D61-9A27-79C709A31EB0}
pub static S_TRAP_GUID: GUID = GUID {
    Data1: 0x9640b7b0,
    Data2: 0xca4d,
    Data3: 0x4d61,
    Data4: [0x9a, 0x27, 0x79, 0xc7, 0x9, 0xa3, 0x1e, 0xb0],
};

// pub fn attach() {}
// folllowing #defines from winbase.h are missing in winbase.rs
// const OF_READ:u32 = 0x00000000;
const OF_WRITE: u32 = 0x00000001;
const OF_READWRITE: u32 = 0x00000002;
// const OF_SHARE_COMPAT:u32 = 0x00000000;
const OF_SHARE_EXCLUSIVE: u32 = 0x00000010;
const OF_SHARE_DENY_WRITE: u32 = 0x00000020;
// const OF_SHARE_DENY_READ:u32 = 0x00000030;
// const OF_SHARE_DENY_NONE:u32 = 0x00000040;
// const OF_PARSE:u32 = 0x00000100;
const OF_DELETE: u32 = 0x00000200;
// const OF_VERIFY:u32 = 0x00000400;
const OF_CREATE: u32 = 0x00001000;
// const OF_EXIST:u32 = 0x00004000;
// const OF_REOPEN:u32 = 0x00008000;

pub const TUP_CREATE_WRITE_FLAGS: u32 = (GENERIC_WRITE
    | FILE_WRITE_DATA
    | FILE_WRITE_ATTRIBUTES
    | FILE_WRITE_EA
    | FILE_APPEND_DATA
    | WRITE_OWNER
    | WRITE_DAC);
pub const TUP_UNLINK_FLAGS: u32 = DELETE;
// use std::ptr;
use std::ffi::CStr;
use std::ffi::OsString;
use std::io::Error;
use std::os::windows::ffi::OsStringExt;
#[derive(Debug)]
pub(crate) enum FileEventType {
    Read,
    Write,
    Unlink,
    Exec,
    // ReadVar,
}
impl ToString for FileEventType {
    fn to_string(&self) -> String {
        format!("{:?}", self)
    }
}

static mut REAL_DELETEFILEA: FARPROC = std::ptr::null_mut() as _;
static mut REAL_DELETEFILEW: FARPROC = std::ptr::null_mut() as _;
static mut REAL_GETFILEATTRIBUTESA: FARPROC = std::ptr::null_mut() as _;
static mut REAL_GETFILEATTRIBUTESW: FARPROC = std::ptr::null_mut() as _;
static mut REAL_GETFILEATTRIBUTESEXA: FARPROC = std::ptr::null_mut() as _;
static mut REAL_GETFILEATTRIBUTESEXW: FARPROC = std::ptr::null_mut() as _;
static mut REAL_SETFILEATTRIBUTESA: FARPROC = std::ptr::null_mut() as _;
static mut REAL_SETFILEATTRIBUTESW: FARPROC = std::ptr::null_mut() as _;
static mut REAL_COPYFILE2: FARPROC = std::ptr::null_mut() as _;
static mut REAL_COPYFILEA: FARPROC = std::ptr::null_mut() as _;
static mut REAL_COPYFILEEXA: FARPROC = std::ptr::null_mut() as _;
static mut REAL_COPYFILEEXW: FARPROC = std::ptr::null_mut() as _;
static mut REAL_COPYFILETRANSACTEDA: FARPROC = std::ptr::null_mut() as _;
static mut REAL_COPYFILETRANSACTEDW: FARPROC = std::ptr::null_mut() as _;
static mut REAL_COPYFILEW: FARPROC = std::ptr::null_mut() as _;
static mut REAL_REPLACEFILEA: FARPROC = std::ptr::null_mut() as _;
static mut REAL_REPLACEFILEW: FARPROC = std::ptr::null_mut() as _;
static mut REAL_MOVEFILEA: FARPROC = std::ptr::null_mut() as _;
static mut REAL_MOVEFILEW: FARPROC = std::ptr::null_mut() as _;
static mut REAL_MOVEFILEEXA: FARPROC = std::ptr::null_mut() as _;
static mut REAL_MOVEFILEEXW: FARPROC = std::ptr::null_mut() as _;
static mut REAL_OPENFILE: FARPROC = std::ptr::null_mut() as _;
static mut REAL_CREATEPROCESSA: FARPROC = std::ptr::null_mut() as _;
static mut REAL_CREATEPROCESSW: FARPROC = std::ptr::null_mut() as _;
static mut REAL_NTCREATEFILE: FARPROC = std::ptr::null_mut() as _;
static mut REAL_NTOPENFILE: FARPROC = std::ptr::null_mut() as _;

// send file event in pipe back to server
fn record_event(lpFileName: LPCSTR, evt: FileEventType) -> std::result::Result<usize, Error> {
    let pid = unsafe { GetCurrentProcessId() };
    let fname = unsafe { CStr::from_ptr(lpFileName).to_str().unwrap() };
    let mut client = PipeClient::connect(TBLOG_PIPE_NAME)?;
    let mut readbuf = [0u8; 1];
    use std::io::Read;
    client.read(&mut readbuf[..])?;
    client.write(
        format!(
            "------\n{}\t{},\t{}----*----\n",
            fname,
            pid.to_string(),
            evt.to_string()
        )
        .as_bytes(),
    )
}

// wide string version of the above
fn record_event_wide(lpFileName: LPCWSTR, evt: FileEventType) -> std::result::Result<usize, Error> {
    let p = { lpFileName as *const u16 };
    let mut len = 0;
    unsafe {
        while *p.offset(len) != 0 {
            len += 1;
        }
    }
    record_event_wide_len(lpFileName, len, evt)
}
// writes the file sys event on lpFileName to the pipe
fn record_event_wide_len(
    lpFileName: LPCWSTR,
    len: isize,
    evt: FileEventType,
) -> std::result::Result<usize, Error> {
    let pid = unsafe { GetCurrentProcessId() };
    let name = unsafe { std::slice::from_raw_parts(lpFileName as *const u16, len as usize) };
    let u16str: OsString = OsStringExt::from_wide(name);
    let mut client = PipeClient::connect(TBLOG_PIPE_NAME)?;
    client.write(
        format!(
            "----\n{}\t{}\t{}----*-----\n",
            u16str.to_str().unwrap(),
            pid.to_string(),
            evt.to_string()
        )
        .as_bytes(),
    )
}

unsafe extern "system" fn TrapDeleteFileA(lpFileName: LPCSTR) -> BOOL {
    type ProcType = unsafe extern "system" fn(lpFileName: LPCSTR) -> BOOL;
    let realapi: ProcType = std::mem::transmute(REAL_DELETEFILEA);
    let ret = realapi(lpFileName);
    if ret != FALSE {
        let _ = record_event(lpFileName, FileEventType::Unlink);
    }
    ret
}

unsafe extern "system" fn TrapDeleteFileW(lpFileName: LPCWSTR) -> BOOL {
    type ProcType = unsafe extern "system" fn(lpFileName: LPCWSTR) -> BOOL;
    let realapi: ProcType = std::mem::transmute(REAL_DELETEFILEW);

    let ret = realapi(lpFileName);
    if ret != FALSE {
        let _ = record_event_wide(lpFileName, FileEventType::Unlink)
            .map_err(|x| eprintln!("record failed in deletefilew:{}", x));
    }
    ret
}

unsafe extern "system" fn TrapGetFileAttributesA(lpFileName: LPCSTR) -> DWORD {
    type ProcType = extern "system" fn(lpFileName: LPCSTR) -> DWORD;
    let realapi: ProcType = std::mem::transmute(REAL_GETFILEATTRIBUTESA);

    let ret = realapi(lpFileName);
    if ret != INVALID_FILE_ATTRIBUTES && (ret & FILE_ATTRIBUTE_DIRECTORY == 0) {
        let _ = record_event(lpFileName, FileEventType::Read)
            .map_err(|x| eprintln!("record failed in GetFileAttributesA:{}", x));
    }
    ret
}
unsafe extern "system" fn TrapGetFileAttributesW(lpFileName: LPCWSTR) -> DWORD {
    type ProcType = unsafe extern "system" fn(lpFileName: LPCWSTR) -> DWORD;
    let realapi: ProcType = std::mem::transmute(REAL_GETFILEATTRIBUTESW);

    let ret = realapi(lpFileName);
    if ret != INVALID_FILE_ATTRIBUTES && (ret & FILE_ATTRIBUTE_DIRECTORY == 0) {
        let _ = record_event_wide(lpFileName, FileEventType::Read)
            .map_err(|x| eprintln!("record failed in GetFileAttributesW:{}", x));
    }
    ret
}
unsafe extern "system" fn TrapGetFileAttributesExA(
    lpFileName: LPCSTR,
    fInfoLevelId: GET_FILEEX_INFO_LEVELS,
    lpFileInformation: LPVOID,
) -> BOOL {
    type ProcType = unsafe extern "system" fn(
        lpFileName: LPCSTR,
        fInfoLevelId: GET_FILEEX_INFO_LEVELS,
        lpFileInformation: LPVOID,
    ) -> BOOL;
    let realapi: ProcType = std::mem::transmute(REAL_GETFILEATTRIBUTESEXA);

    let ret = realapi(lpFileName, fInfoLevelId, lpFileInformation);
    if ret != FALSE {
        let attrib: *const DWORD = std::mem::transmute(lpFileInformation); // first field in WIN32_FILE_ATTRIBUTE_DATA is attib dword
        if (*attrib & FILE_ATTRIBUTE_DIRECTORY == 0) && (*attrib & FILE_ATTRIBUTE_TEMPORARY == 0) {
            let _ = record_event(lpFileName, FileEventType::Write)
                .map_err(|x| eprintln!("record failed in GetFileAttributesExA:{}", x));
        }
    }
    ret
}

unsafe extern "system" fn TrapGetFileAttributesExW(
    lpFileName: LPCWSTR,
    fInfoLevelId: GET_FILEEX_INFO_LEVELS,
    lpFileInformation: LPVOID,
) -> BOOL {
    type ProcType = unsafe extern "system" fn(
        lpFileName: LPCWSTR,
        fInfoLevelId: GET_FILEEX_INFO_LEVELS,
        lpFileInformation: LPVOID,
    ) -> BOOL;
    let realapi: ProcType = std::mem::transmute(REAL_GETFILEATTRIBUTESEXW);

    let ret = realapi(lpFileName, fInfoLevelId, lpFileInformation);
    if ret != FALSE {
        let attrib: *const DWORD = std::mem::transmute(lpFileInformation); // first field in WIN32_FILE_ATTRIBUTE_DATA is attib dword
        if (*attrib & FILE_ATTRIBUTE_DIRECTORY == 0) && (*attrib & FILE_ATTRIBUTE_TEMPORARY == 0) {
            let _ = record_event_wide(lpFileName, FileEventType::Write)
                .map_err(|x| eprintln!("record failed in GetFileAttributesExW:{}", x));
        }
    }
    ret
}

unsafe extern "system" fn TrapSetFileAttributesA(
    lpFileName: LPCSTR,
    dwFileAttributes: DWORD,
) -> BOOL {
    type ProcType = unsafe extern "system" fn(lpFileName: LPCSTR, dwFileAttributes: DWORD) -> BOOL;
    let realapi: ProcType = std::mem::transmute(REAL_SETFILEATTRIBUTESA);

    let ret = realapi(lpFileName, dwFileAttributes);
    if ret != FALSE {
        let _ = record_event(lpFileName, FileEventType::Write)
            .map_err(|x| eprintln!("record failed in SetFileAttributesA:{}", x));
    }
    ret
}

unsafe extern "system" fn TrapSetFileAttributesW(
    lpFileName: LPCWSTR,
    dwFileAttributes: DWORD,
) -> BOOL {
    type ProcType = unsafe extern "system" fn(lpFileName: LPCWSTR, dwFileAttributes: DWORD) -> BOOL;
    let realapi: ProcType = std::mem::transmute(REAL_SETFILEATTRIBUTESW);

    let ret = realapi(lpFileName, dwFileAttributes);
    if ret != FALSE {
        let _ = record_event_wide(lpFileName, FileEventType::Write)
            .map_err(|x| eprintln!("record failed in SetFileAttributesW:{}", x));
    }
    ret
}

pub unsafe extern "system" fn TrapCopyFile2(
    pwszExistingFileName: PCWSTR,
    pwszNewFileName: PCWSTR,
    pExtendedParameters: *mut COPYFILE2_EXTENDED_PARAMETERS,
) -> HRESULT {
    type ProcType = unsafe extern "system" fn(
        pwszExistingFileName: PCWSTR,
        pwszNewFileName: PCWSTR,
        pExtendedParameters: *mut COPYFILE2_EXTENDED_PARAMETERS,
    ) -> HRESULT;
    let realapi: ProcType = std::mem::transmute(REAL_COPYFILE2);
    let res = realapi(
        pwszExistingFileName,
        pwszNewFileName,
        pExtendedParameters as _,
    );
    if res != 0 {
        let _ = record_event_wide(pwszNewFileName, FileEventType::Write)
            .map_err(|x| eprintln!("record failed in CopyFile2:{}", x));
        let _ = record_event_wide(pwszExistingFileName, FileEventType::Read)
            .map_err(|x| eprintln!("record failed in CopyFile2:{}", x));
    }
    res
}
pub unsafe extern "system" fn TrapCopyFileA(
    lpExistingFileName: LPCSTR,
    lpNewFileName: LPCSTR,
    bFailIfExists: BOOL,
) -> BOOL {
    type ProcType = unsafe extern "system" fn(
        lpExistingFileName: LPCSTR,
        lpNewFileName: LPCSTR,
        bFailIfExists: BOOL,
    ) -> BOOL;
    let realapi: ProcType = std::mem::transmute(REAL_COPYFILEA);

    let res = realapi(lpExistingFileName, lpNewFileName, bFailIfExists);
    if res != 0 {
        let _ = record_event(lpNewFileName, FileEventType::Write)
            .map_err(|x| eprintln!("record failed in CopyFileA:{}", x));
        let _ = record_event(lpExistingFileName, FileEventType::Read)
            .map_err(|x| eprintln!("record failed in CopyFileA:{}", x));
    }
    res
}
pub unsafe extern "system" fn TrapCopyFileExA(
    lpExistingFileName: LPCSTR,
    lpNewFileName: LPCSTR,
    lpProgressRoutine: LPPROGRESS_ROUTINE,
    lpData: LPVOID,
    pbCancel: LPBOOL,
    dwCopyFlags: DWORD,
) -> BOOL {
    type ProcType = unsafe extern "system" fn(
        lpExistingFileName: LPCSTR,
        lpNewFileName: LPCSTR,
        lpProgressRoutine: LPPROGRESS_ROUTINE,
        lpData: LPVOID,
        pbCancel: LPBOOL,
        dwCopyFlags: DWORD,
    ) -> BOOL;
    let realapi: ProcType = std::mem::transmute(REAL_COPYFILEEXA);

    let ret = realapi(
        lpExistingFileName,
        lpNewFileName,
        lpProgressRoutine,
        lpData as _,
        pbCancel,
        dwCopyFlags,
    );
    if ret != FALSE {
        let _ = record_event(lpExistingFileName, FileEventType::Read)
            .map_err(|x| eprintln!("record failed in CopyFileExA:{}", x));
        let _ = record_event(lpNewFileName, FileEventType::Write)
            .map_err(|x| eprintln!("record failed in CopyFileExA:{}", x));
    }
    ret
}
pub unsafe extern "system" fn TrapCopyFileExW(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
    lpProgressRoutine: LPPROGRESS_ROUTINE,
    lpData: LPVOID,
    pbCancel: LPBOOL,
    dwCopyFlags: DWORD,
) -> BOOL {
    type ProcType = unsafe extern "system" fn(
        lpExistingFileName: LPCWSTR,
        lpNewFileName: LPCWSTR,
        lpProgressRoutine: LPPROGRESS_ROUTINE,
        lpData: LPVOID,
        pbCancel: LPBOOL,
        dwCopyFlags: DWORD,
    ) -> BOOL;
    let realapi: ProcType = std::mem::transmute(REAL_COPYFILEEXW);

    let ret = realapi(
        lpExistingFileName,
        lpNewFileName,
        lpProgressRoutine,
        lpData,
        pbCancel,
        dwCopyFlags,
    );
    if ret != FALSE {
        let _ = record_event_wide(lpExistingFileName, FileEventType::Read)
            .map_err(|x| eprintln!("record failed in CopyFileExW:{}", x));
        let _ = record_event_wide(lpNewFileName, FileEventType::Write)
            .map_err(|x| eprintln!("record failed in CopyFileExW:{}", x));
    }
    ret
}
pub unsafe extern "system" fn TrapCopyFileTransactedA(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
    lpProgressRoutine: LPPROGRESS_ROUTINE,
    lpData: LPVOID,
    pbCancel: LPBOOL,
    dwCopyFlags: DWORD,
    hTransaction: HANDLE,
) -> BOOL {
    type ProcType = unsafe extern "system" fn(
        lpExistingFileName: LPCWSTR,
        lpNewFileName: LPCWSTR,
        lpProgressRoutine: LPPROGRESS_ROUTINE,
        lpData: LPVOID,
        pbCancel: LPBOOL,
        dwCopyFlags: DWORD,
        hTransaction: HANDLE,
    ) -> BOOL;
    let realapi: ProcType = std::mem::transmute(REAL_COPYFILETRANSACTEDA);

    let ret = realapi(
        lpExistingFileName,
        lpNewFileName,
        lpProgressRoutine,
        lpData,
        pbCancel,
        dwCopyFlags,
        hTransaction,
    );
    if ret != FALSE {
        let _ = record_event_wide(lpExistingFileName, FileEventType::Read)
            .map_err(|x| eprintln!("record failed in CopyFileTransactedA:{}", x));
        let _ = record_event_wide(lpNewFileName, FileEventType::Write)
            .map_err(|x| eprintln!("record failed in CopyFileTransactedA:{}", x));
    }
    ret
}
pub unsafe extern "system" fn TrapCopyFileTransactedW(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
    lpProgressRoutine: LPPROGRESS_ROUTINE,
    lpData: LPVOID,
    pbCancel: LPBOOL,
    dwCopyFlags: DWORD,
    hTransaction: HANDLE,
) -> BOOL {
    type ProcType = unsafe extern "system" fn(
        lpExistingFileName: LPCWSTR,
        lpNewFileName: LPCWSTR,
        lpProgressRoutine: LPPROGRESS_ROUTINE,
        lpData: LPVOID,
        pbCancel: LPBOOL,
        dwCopyFlags: DWORD,
        hTransaction: HANDLE,
    ) -> BOOL;
    let realapi: ProcType = std::mem::transmute(REAL_COPYFILETRANSACTEDW);

    let ret = realapi(
        lpExistingFileName,
        lpNewFileName,
        lpProgressRoutine,
        lpData,
        pbCancel,
        dwCopyFlags,
        hTransaction,
    );
    if ret != FALSE {
        let _ = record_event_wide(lpExistingFileName, FileEventType::Read)
            .map_err(|x| eprintln!("record failed in CopyFileTransactedW:{}", x));
        let _ = record_event_wide(lpNewFileName, FileEventType::Write)
            .map_err(|x| eprintln!("record failed in CopyFileTransactedW:{}", x));
    }
    ret
}
pub unsafe extern "system" fn TrapCopyFileW(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
    bFailIfExists: BOOL,
) -> BOOL {
    type ProcType = unsafe extern "system" fn(
        lpExistingFileName: LPCWSTR,
        lpNewFileName: LPCWSTR,
        bFailIfExists: BOOL,
    ) -> BOOL;
    let realapi: ProcType = std::mem::transmute(REAL_COPYFILEW);

    let ret = realapi(lpExistingFileName, lpNewFileName, bFailIfExists);
    if ret != FALSE {
        let _ = record_event_wide(lpExistingFileName, FileEventType::Read)
            .map_err(|x| eprintln!("record failed in CopyFileW:{}", x));
        let _ = record_event_wide(lpNewFileName, FileEventType::Write)
            .map_err(|x| eprintln!("record failed in CopyFileW:{}", x));
    }
    ret
}

pub unsafe extern "system" fn TrapReplaceFileA(
    lpReplacedFileName: LPCSTR,
    lpReplacementFileName: LPCSTR,
    lpBackupFileName: LPCSTR,
    dwReplaceFlags: DWORD,
    lpExclude: LPVOID,
    lpReserved: LPVOID,
) {
    type ProcType = unsafe extern "system" fn(
        lpReplacedFileName: LPCSTR,
        lpReplacementFileName: LPCSTR,
        lpBackupFileName: LPCSTR,
        dwReplaceFlags: DWORD,
        lpExclude: LPVOID,
        lpReserved: LPVOID,
    );
    let realapi: ProcType = std::mem::transmute(REAL_REPLACEFILEA);

    realapi(
        lpReplacedFileName,
        lpReplacementFileName,
        lpBackupFileName,
        dwReplaceFlags,
        lpExclude as _,
        lpReserved as _,
    );
    {
        let _ = record_event(lpReplacedFileName, FileEventType::Unlink)
            .map_err(|x| eprintln!("record failed in ReplaceFileA:{}", x));
        let _ = record_event(lpReplacementFileName, FileEventType::Write)
            .map_err(|x| eprintln!("record failed in ReplaceFileA:{}", x));
    }
}
pub unsafe extern "system" fn TrapReplaceFileW(
    lpReplacedFileName: LPCWSTR,
    lpReplacementFileName: LPCWSTR,
    lpBackupFileName: LPCWSTR,
    dwReplaceFlags: DWORD,
    lpExclude: LPVOID,
    lpReserved: LPVOID,
) {
    type ProcType = unsafe extern "system" fn(
        lpReplacedFileName: LPCWSTR,
        lpReplacementFileName: LPCWSTR,
        lpBackupFileName: LPCWSTR,
        dwReplaceFlags: DWORD,
        lpExclude: LPVOID,
        lpReserved: LPVOID,
    );
    let realapi: ProcType = std::mem::transmute(REAL_REPLACEFILEW);
    realapi(
        lpReplacedFileName,
        lpReplacementFileName,
        lpBackupFileName,
        dwReplaceFlags,
        lpExclude,
        lpReserved,
    );
    {
        let _ = record_event_wide(lpReplacedFileName, FileEventType::Unlink)
            .map_err(|x| eprintln!("record failed in ReplaceFileW:{}", x));
        let _ = record_event_wide(lpReplacementFileName, FileEventType::Write)
            .map_err(|x| eprintln!("record failed in ReplaceFileW:{}", x));
    }
}

pub unsafe extern "system" fn TrapMoveFileA(
    lpExistingFileName: LPCSTR,
    lpNewFileName: LPCSTR,
) -> BOOL {
    type ProcType =
        unsafe extern "system" fn(lpExistingFileName: LPCSTR, lpNewFileName: LPCSTR) -> BOOL;
    let realapi: ProcType = std::mem::transmute(REAL_MOVEFILEA);
    let ret: BOOL = realapi(lpExistingFileName, lpNewFileName);
    if ret != FALSE {
        let _ = record_event(lpExistingFileName, FileEventType::Unlink)
            .map_err(|x| eprintln!("record failed in MoveFileA:{}", x));
        let _ = record_event(lpNewFileName, FileEventType::Write)
            .map_err(|x| eprintln!("record failed in MoveFileA:{}", x));
    }
    ret
}
pub unsafe extern "system" fn TrapMoveFileW(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
) -> BOOL {
    type ProcType =
        unsafe extern "system" fn(lpExistingFileName: LPCWSTR, lpNewFileName: LPCWSTR) -> BOOL;
    let realapi: ProcType = std::mem::transmute(REAL_MOVEFILEW);

    let ret = realapi(lpExistingFileName, lpNewFileName);
    if ret != FALSE {
        let _ = record_event_wide(lpExistingFileName, FileEventType::Unlink)
            .map_err(|x| eprintln!("record failed in MoveFileW:{}", x));
        let _ = record_event_wide(lpNewFileName, FileEventType::Write)
            .map_err(|x| eprintln!("record failed in MoveFileW:{}", x));
    }
    ret
}
pub unsafe extern "system" fn TrapMoveFileExA(
    lpExistingFileName: LPCSTR,
    lpNewFileName: LPCSTR,
    dwFlags: DWORD,
) -> BOOL {
    type ProcType = unsafe extern "system" fn(
        lpExistingFileName: LPCSTR,
        lpNewFileName: LPCSTR,
        dwFlags: DWORD,
    ) -> BOOL;
    let realapi: ProcType = std::mem::transmute(REAL_MOVEFILEEXA);

    let ret = realapi(lpExistingFileName, lpNewFileName, dwFlags);
    if ret != FALSE {
        let _ = record_event(lpExistingFileName, FileEventType::Unlink)
            .map_err(|x| eprintln!("record failed in MoveFileExA:{}", x));
        let _ = record_event(lpNewFileName, FileEventType::Write)
            .map_err(|x| eprintln!("record failed in MoveFileExA:{}", x));
    }
    ret
}
pub unsafe extern "system" fn TrapMoveFileExW(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
    dwFlags: DWORD,
) -> BOOL {
    type ProcType = unsafe extern "system" fn(
        lpExistingFileName: LPCWSTR,
        lpNewFileName: LPCWSTR,
        dwFlags: DWORD,
    ) -> BOOL;
    let realapi: ProcType = std::mem::transmute(REAL_MOVEFILEEXW);

    let ret = realapi(lpExistingFileName, lpNewFileName, dwFlags);
    if ret != FALSE {
        let _ = record_event_wide(lpExistingFileName, FileEventType::Unlink)
            .map_err(|x| eprintln!("record failed in MoveFileExW:{}", x));
        let _ = record_event_wide(lpNewFileName, FileEventType::Write)
            .map_err(|x| eprintln!("record failed in MoveFileExW:{}", x));
    }
    ret
}

pub unsafe extern "system" fn TrapOpenFile(
    lpFileName: LPCSTR,
    lpReOpenBuff: LPOFSTRUCT,
    uStyle: UINT,
) {
    type ProcType =
        unsafe extern "system" fn(lpFileName: LPCSTR, lpReOpenBuff: LPOFSTRUCT, uStyle: UINT);
    let realapi: ProcType = std::mem::transmute(REAL_OPENFILE);
    realapi(lpFileName, lpReOpenBuff, uStyle);

    if uStyle & OF_DELETE != 0 {
        let _ = record_event(lpFileName, FileEventType::Unlink)
            .map_err(|x| eprintln!("record failed in OpenFile:{}", x));
    } else if uStyle
        & (OF_READWRITE | OF_WRITE | OF_SHARE_DENY_WRITE | OF_SHARE_EXCLUSIVE | OF_CREATE)
        != 0
    {
        let _ = record_event(lpFileName, FileEventType::Write)
            .map_err(|x| eprintln!("record failed in OpenFile:{}", x));
    } else {
        let _ = record_event(lpFileName, FileEventType::Read)
            .map_err(|x| eprintln!("record failed in OpenFile:{}", x));
    }
}

pub type EntryPointType = unsafe extern "system" fn();
type BigPath = [WCHAR; 1024];
// type BigPathA = [CHAR; 1024];

const SIZEOFBIGPATH: u32 = 1024;
#[derive(Clone)]
pub struct Payload {
    depFile: BigPath,
    varDictFile: BigPath,
}
pub struct TrapInfo {
    hInst: HMODULE,
}

impl Default for TrapInfo {
    fn default() -> TrapInfo {
        let inst: HMODULE = 0 as _;
        TrapInfo { hInst: inst }
    }
}
static mut REALENTRYPOINT: FARPROC = std::ptr::null_mut();
pub const TBLOG_PIPE_NAME: &'static str = "\\\\.\\pipe\\tracebuild\0";

impl Payload {
    pub fn new() -> Payload {
        Payload {
            depFile: [0; SIZEOFBIGPATH as _],
            varDictFile: [0; SIZEOFBIGPATH as _],
        }
    }
    pub fn findPayLoad() -> Payload {
        const HMODNULL: HMODULE = std::ptr::null_mut() as _;
        let finder = || -> *const Payload {
            let mut hMod: HMODULE = std::ptr::null_mut() as _;
            while {
                hMod = unsafe { detours::DetourEnumerateModules(hMod as _) };
                hMod
            } != HMODNULL
            {
                let mut cbData: ULONG = 0;
                let pvData: *const Payload = unsafe {
                    detours::DetourFindPayload(hMod, &S_TRAP_GUID as _, &mut cbData as _) as _
                };
                if pvData != std::ptr::null() {
                    return pvData;
                }
            }
            std::ptr::null() as _
        };
        let pPayload = finder();
        if pPayload != std::ptr::null() {
            unsafe { (*pPayload).clone() }
        } else {
            unreachable!("Error: missing payload during dll injection");
            // Payload::new()
        }
    }
}
static mut S_HMSVCR: HINSTANCE = std::ptr::null_mut();
// static mut s_pszMsvcr: *const u8 = std::ptr::null_mut();
static S_RPSZMSVCRNAMES: [&'static str; 14] = [
    "msvcr80.dll",
    "msvcr80d.dll",
    "msvcr71.dll",
    "msvcr71d.dll",
    "msvcr70.dll",
    "msvcr70d.dll",
    "msvcr90.dll",
    "msvcr90d.dll",
    "msvcr100.dll",
    "msvcr100d.dll",
    "msvcr110.dll",
    "msvcr110d.dll",
    "msvcr120.dll",
    "msvcr120d.dll",
];

#[cfg(target_arch = "x86_64")]
pub unsafe extern "C" fn ImportFileCallback(_: PVOID, hFile: HINSTANCE, pszFile: PCSTR) -> BOOL {
    use std::ffi::CString;
    if pszFile != std::ptr::null() {
        let cpszFile = CStr::from_ptr(pszFile);
        if let Some(_s) = S_RPSZMSVCRNAMES
            .iter()
            .map(|s: &&str| CString::new(*s).expect("CString conversion failed"))
            .find(|cstr| cstr.as_c_str() == cpszFile)
        {
            S_HMSVCR = hFile;
            // s_pszMsvcr = (s.as_ptr()) as _;
            return FALSE;
        }
    }
    return TRUE;
}
#[cfg(target_arch = "x86")]
pub unsafe extern "stdcall" fn ImportFileCallback(
    _: PVOID,
    hFile: HINSTANCE,
    pszFile: PCSTR,
) -> BOOL {
    use std::ffi::CString;
    if pszFile != std::ptr::null() {
        let cpszFile = CStr::from_ptr(pszFile);
        if let Some(_s) = S_RPSZMSVCRNAMES
            .iter()
            .map(|s: &&str| CString::new(*s).expect("CString conversion failed"))
            .find(|cstr| cstr.as_c_str() == cpszFile)
        {
            S_HMSVCR = hFile;
            // s_pszMsvcr = (s.as_ptr()) as _;
            return FALSE;
        }
    }
    return TRUE;
}

pub unsafe extern "system" fn FindMsvcr() -> bool {
    detours::DetourEnumerateImportsEx(
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        Some(ImportFileCallback),
        None,
    );
    !S_HMSVCR.is_null()
}
static mut DLLPATHW: String = String::new();
impl TrapInfo {
    pub fn new(hModule: HMODULE) -> Self {
        unsafe {
            let mut dllpathw: BigPath = [0; SIZEOFBIGPATH as _];
            GetModuleFileNameW(hModule as _, (&mut dllpathw).as_mut_ptr(), SIZEOFBIGPATH);
            let p = { &dllpathw as *const u16 };
            let mut len = 0;
            while *p.offset(len) != 0 {
                len += 1;
            }

            let name = { std::slice::from_raw_parts(&dllpathw as *const u16, len as usize) };
            let u16str: OsString = OsStringExt::from_wide(name);
            DLLPATHW = u16str.to_str().unwrap().to_string();
        }
        TrapInfo {
            hInst: hModule,
            // zDllPath: dllPath,
            // payLoad: Payload::new()//Payload::findPayLoad(),
        }
    }

    pub fn valid(&self) -> bool {
        self.hInst == std::ptr::null_mut() as _
    }
    pub unsafe fn attach(&self) {
        use detours::DetourAttach;
        // std::thread::sleep_ms(20000); // uncomment for debug purposes
        detours::DetourUpdateThread(GetCurrentThread() as _);
        let kstr = wstr!("kernel32\0");
        let kbasestr = wstr!("kernelbase\0");
        let nstr = wstr!("ntdll\0");
        let k32 = GetModuleHandleW(kstr.as_ptr());
        let kbase = GetModuleHandleW(kbasestr.as_ptr());
        attach_proc!(k32, "DeleteFileA\0", REAL_DELETEFILEA, TrapDeleteFileA);
        attach_proc!(k32, "DeleteFileW\0", REAL_DELETEFILEW, TrapDeleteFileW);
        attach_proc!(
            k32,
            "GetFileAttributesA\0",
            REAL_GETFILEATTRIBUTESA,
            TrapGetFileAttributesA
        );
        attach_proc!(
            k32,
            "GetFileAttributesW\0",
            REAL_GETFILEATTRIBUTESW,
            TrapGetFileAttributesW
        );
        attach_proc!(
            k32,
            "GetFileAttributesExA\0",
            REAL_GETFILEATTRIBUTESEXA,
            TrapGetFileAttributesExA
        );
        attach_proc!(
            k32,
            "GetFileAttributesExW\0",
            REAL_GETFILEATTRIBUTESEXW,
            TrapGetFileAttributesExW
        );
        attach_proc!(
            k32,
            "SetFileAttributesA\0",
            REAL_SETFILEATTRIBUTESA,
            TrapSetFileAttributesA
        );
        attach_proc!(
            k32,
            "SetFileAttributesW\0",
            REAL_SETFILEATTRIBUTESW,
            TrapSetFileAttributesW
        );
        attach_proc!(k32, "CopyFile2\0", REAL_COPYFILE2, TrapCopyFile2);
        attach_proc!(k32, "CopyFileA\0", REAL_COPYFILEA, TrapCopyFileA);
        attach_proc!(k32, "CopyFileW\0", REAL_COPYFILEW, TrapCopyFileW);
        attach_proc!(k32, "CopyFileExA\0", REAL_COPYFILEEXA, TrapCopyFileExA);
        attach_proc!(k32, "CopyFileExW\0", REAL_COPYFILEEXW, TrapCopyFileExW);
        attach_proc!(
            k32,
            "CopyFileTransactedA\0",
            REAL_COPYFILETRANSACTEDA,
            TrapCopyFileTransactedA
        );
        attach_proc!(
            k32,
            "CopyFileTransactedW\0",
            REAL_COPYFILETRANSACTEDW,
            TrapCopyFileTransactedW
        );
        attach_proc!(k32, "ReplaceFileA\0", REAL_REPLACEFILEA, TrapReplaceFileA);
        attach_proc!(k32, "ReplaceFileW\0", REAL_REPLACEFILEW, TrapReplaceFileW);
        attach_proc!(k32, "MoveFileA\0", REAL_MOVEFILEA, TrapMoveFileA);
        attach_proc!(k32, "MoveFileW\0", REAL_MOVEFILEW, TrapMoveFileW);
        attach_proc!(k32, "MoveFileExA\0", REAL_MOVEFILEEXA, TrapMoveFileExA);
        attach_proc!(kbase, "MoveFileExW\0", REAL_MOVEFILEEXW, TrapMoveFileExW);
        attach_proc!(k32, "OpenFile\0", REAL_OPENFILE, TrapOpenFile);
        attach_proc!(
            k32,
            "CreateProcessA\0",
            REAL_CREATEPROCESSA,
            TrapCreateProcessA
        );
        attach_proc!(
            k32,
            "CreateProcessW\0",
            REAL_CREATEPROCESSW,
            TrapCreateProcessW
        );
        let ep = detours::DetourGetEntryPoint(std::ptr::null_mut() as _);
        REALENTRYPOINT = ep as _;
        DetourAttach(
            &REALENTRYPOINT as *const _ as _,
            (TrapEntryPoint as *const ()) as _,
        );
        let ntapi = GetModuleHandleW(nstr.as_ptr());
        attach_proc!(ntapi, "NtCreateFile\0", REAL_NTCREATEFILE, TrapNtCreateFile);
        attach_proc!(ntapi, "NtOpenFile\0", REAL_NTOPENFILE, TrapNtOpenFile);
        // attach_proc!(ntapi, "NtCreateUserProcess\0", REAL_NTOPENFILE, TrapNtOpenFile);
    }

    pub unsafe fn detach(&self) {
        detach_proc!(REAL_DELETEFILEA, TrapDeleteFileA);
        detach_proc!(REAL_DELETEFILEW, TrapDeleteFileW);

        detach_proc!(REAL_GETFILEATTRIBUTESA, TrapGetFileAttributesA);
        detach_proc!(REAL_GETFILEATTRIBUTESW, TrapGetFileAttributesW);

        detach_proc!(REAL_GETFILEATTRIBUTESEXA, TrapGetFileAttributesExA);
        detach_proc!(REAL_GETFILEATTRIBUTESEXW, TrapGetFileAttributesExW);

        detach_proc!(REAL_SETFILEATTRIBUTESA, TrapSetFileAttributesA);
        detach_proc!(REAL_SETFILEATTRIBUTESW, TrapSetFileAttributesW);

        detach_proc!(REAL_COPYFILE2, TrapCopyFile2);
        detach_proc!(REAL_COPYFILEA, TrapCopyFileA);
        detach_proc!(REAL_COPYFILEW, TrapCopyFileW);

        detach_proc!(REAL_COPYFILEEXA, TrapCopyFileExA);
        detach_proc!(REAL_COPYFILEEXW, TrapCopyFileExW);

        detach_proc!(REAL_COPYFILETRANSACTEDA, TrapCopyFileTransactedA);
        detach_proc!(REAL_COPYFILETRANSACTEDW, TrapCopyFileTransactedW);

        detach_proc!(REAL_REPLACEFILEA, TrapReplaceFileA);
        detach_proc!(REAL_REPLACEFILEW, TrapReplaceFileW);

        detach_proc!(REAL_MOVEFILEA, TrapMoveFileA);
        detach_proc!(REAL_MOVEFILEW, TrapMoveFileW);

        detach_proc!(REAL_MOVEFILEEXA, TrapMoveFileExA);
        detach_proc!(REAL_MOVEFILEEXW, TrapMoveFileExW);

        detach_proc!(REAL_OPENFILE, TrapOpenFile);

        detach_proc!(REAL_CREATEPROCESSA, TrapCreateProcessA);
        detach_proc!(REAL_CREATEPROCESSW, TrapCreateProcessW);

        detach_proc!(REALENTRYPOINT, TrapEntryPoint);
        detach_proc!(REAL_NTCREATEFILE, TrapNtCreateFile);
        detach_proc!(REAL_NTOPENFILE, TrapNtOpenFile);

        detach_proc!(REAL_GETENV, Trap_getenv);
        detach_proc!(REAL_WGETENV, Trap_wgetenv);
        detach_proc!(REAL_GETENV_S, Trap_getenv_s);
        detach_proc!(REAL_WGETENV_S, Trap_wgetenv_s);
        detach_proc!(REAL_DUPENV_S, Trap_dupenv_s);
        detach_proc!(REAL_WDUPENV_S, Trap_wdupenv_s);
    }
}
type Real_wgetenvType = unsafe extern "C" fn(var: PCWSTR) -> PCWSTR;
type Real_getenvType = unsafe extern "C" fn(var: PCSTR) -> PCSTR;
type Real_getenv_sType = unsafe extern "C" fn(
    pValue: *mut DWORD,
    pBuffer: PCHAR,
    cBuffer: DWORD,
    varname: PCSTR,
) -> DWORD;
type Real_wgetenv_sType = unsafe extern "C" fn(
    pValue: *mut DWORD,
    pBuffer: PWCHAR,
    cBuffer: DWORD,
    varname: PCWSTR,
) -> DWORD;
type Real_dupenv_sType =
    unsafe extern "C" fn(ppBuffer: *mut PCHAR, pcBuffer: *mut DWORD, varname: PCSTR) -> DWORD;
type Real_wdupenv_sType =
    unsafe extern "C" fn(ppBuffer: *mut PWCHAR, pcBuffer: *mut DWORD, varname: PCWSTR) -> DWORD;
static mut REAL_GETENV: *mut Real_getenvType = std::ptr::null_mut() as _;
static mut REAL_WGETENV: *mut Real_wgetenvType = std::ptr::null_mut() as _;
static mut REAL_GETENV_S: *mut Real_getenv_sType = std::ptr::null_mut() as _;
static mut REAL_WGETENV_S: *mut Real_wgetenv_sType = std::ptr::null_mut() as _;
static mut REAL_DUPENV_S: *mut Real_dupenv_sType = std::ptr::null_mut() as _;
static mut REAL_WDUPENV_S: *mut Real_wdupenv_sType = std::ptr::null_mut() as _;
fn record_env(var: PCSTR) -> std::result::Result<usize, Error> {
    let pid = unsafe { GetCurrentProcessId() };
    use std::fs::File;
    use std::fs::OpenOptions;
    // use std::io::Write;
    let mut file: File = OpenOptions::new()
        .append(true)
        .open(format!("evts-env-{}.txt", pid))?;
    let fname = unsafe { CStr::from_ptr(var).to_str().unwrap() };
    file.write(fname.as_bytes())?;
    file.write(b"\n")
}

fn record_env_wide(var: PCWSTR) -> std::result::Result<usize, Error> {
    let pid = unsafe { GetCurrentProcessId() };
    use std::fs::File;
    use std::fs::OpenOptions;
    // use std::io::Write;
    let mut file: File = OpenOptions::new()
        .append(true)
        .open(format!("evts-env-{}.txt", pid))?;

    let p = { var as *const u16 };
    let mut len = 0;
    unsafe {
        while *p.offset(len) != 0 {
            len += 1;
        }
    }
    let name = unsafe { std::slice::from_raw_parts(p as *const u16, len as usize) };
    let u16str: OsString = OsStringExt::from_wide(name);
    file.write(u16str.to_str().unwrap().as_bytes())?;
    file.write(b"\n")
}
pub unsafe extern "C" fn Trap_wgetenv(var: PCWSTR) -> PCWSTR {
    let _ = record_env_wide(var);
    (*REAL_WGETENV)(var)
}
pub unsafe extern "C" fn Trap_getenv(var: PCSTR) -> PCSTR {
    let _ = record_env(var);
    (*REAL_GETENV)(var)
}

pub unsafe extern "C" fn Trap_getenv_s(
    pValue: *mut DWORD,
    pBuffer: PCHAR,
    cBuffer: DWORD,
    varname: PCSTR,
) -> DWORD {
    let _ = record_env(varname);
    (*REAL_GETENV_S)(pValue, pBuffer, cBuffer, varname)
}
pub unsafe extern "C" fn Trap_wgetenv_s(
    pValue: *mut DWORD,
    pBuffer: PWCHAR,
    cBuffer: DWORD,
    varname: PCWSTR,
) -> DWORD {
    let _ = record_env_wide(varname);
    (*REAL_WGETENV_S)(pValue, pBuffer, cBuffer, varname)
}
unsafe extern "C" fn Trap_dupenv_s(
    ppBuffer: *mut PCHAR,
    pcBuffer: *mut DWORD,
    varname: PCSTR,
) -> DWORD {
    let _ = record_env(varname);
    (*REAL_DUPENV_S)(ppBuffer, pcBuffer, varname)
}
unsafe extern "C" fn Trap_wdupenv_s(
    ppBuffer: *mut PWCHAR,
    pcBuffer: *mut DWORD,
    varname: PCWSTR,
) -> DWORD {
    let _ = record_env_wide(varname);
    (*REAL_WDUPENV_S)(ppBuffer, pcBuffer, varname)
}
unsafe extern "system" fn TrapEntryPoint() {
    type Proctype = fn();
    let realapi: Proctype = std::mem::transmute(REALENTRYPOINT);
    if FindMsvcr() {
        detours::DetourTransactionBegin();
        detours::DetourUpdateThread(GetCurrentThread() as _);

        attach_proc!(S_HMSVCR, "getenv\0", REAL_GETENV, Trap_getenv);
        attach_proc!(S_HMSVCR, "getenv_s\0", REAL_GETENV_S, Trap_getenv_s);
        attach_proc!(S_HMSVCR, "_wgetenv\0", REAL_WGETENV, Trap_wgetenv);
        attach_proc!(S_HMSVCR, "_wgetenv_s\0", REAL_WGETENV_S, Trap_wgetenv_s);
        attach_proc!(S_HMSVCR, "_dupenv_s\0", REAL_DUPENV_S, Trap_dupenv_s);
        attach_proc!(S_HMSVCR, "_wdupenv_s\0", REAL_WDUPENV_S, Trap_wdupenv_s);

        detours::DetourTransactionCommit();
    }
    realapi();
}
pub unsafe extern "system" fn TrapCreateProcessA(
    lpApplicationName: LPCSTR,
    lpCommandLine: LPSTR,
    lpProcessAttributes: LPSECURITY_ATTRIBUTES,
    lpThreadAttributes: LPSECURITY_ATTRIBUTES,
    bInheritHandles: BOOL,
    dwCreationFlags: DWORD,
    lpEnvironment: LPVOID,
    lpCurrentDirectory: LPCSTR,
    lpStartupInfo: LPSTARTUPINFOA,
    lpProcessInformation: LPPROCESS_INFORMATION,
) -> BOOL {
    use winapi::um::handleapi::CloseHandle;
    let mut ppi: LPPROCESS_INFORMATION = lpProcessInformation;
    let null = std::ptr::null_mut();
    let mut pi: PROCESS_INFORMATION = PROCESS_INFORMATION {
        hProcess: null as _,
        hThread: null as _,
        dwProcessId: 0,
        dwThreadId: 0,
    };
    if ppi == null {
        ppi = &mut pi;
    }
    let mut paths = match std::env::var_os("PATH") {
        Some(path) => std::env::split_paths(&path).collect::<Vec<_>>(),
        None => vec![],
    };
    let iswow: BOOL = FALSE;
    winapi::um::wow64apiset::IsWow64Process(GetCurrentProcess(), &iswow as *const _ as _);
    let mut PXX: &'static str = "tupinject64.dll";
    if iswow != FALSE {
        PXX = "tupinject32.dll";
    }
    if let Some(dllpath) = std::path::PathBuf::from(DLLPATHW.as_str()).parent()
    {
        // println!("dllpath is:{:?}", dllpath);
        paths.push(dllpath.to_path_buf());
    }
    let paths = paths
        .iter()
        .map(|pb| pb.as_path().join(PXX))
        .find(|x| x.is_file())
        .expect(format!("{} not found in path", PXX).as_str());
    let dllpath = std::ffi::CString::new(paths.to_str().unwrap());
    let dllpathptr = dllpath.unwrap();
    #[cfg(target_arch = "x86")]
    type Proctype = unsafe extern "stdcall" fn(
        lpApplicationName: LPCSTR,
        lpCommandLine: LPSTR,
        lpProcessAttributes: LPSECURITY_ATTRIBUTES,
        lpThreadAttributes: LPSECURITY_ATTRIBUTES,
        bInheritHandles: BOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: LPVOID,
        lpCurrentDirectory: LPCSTR,
        lpStartupInfo: LPSTARTUPINFOA,
        lpProcessInformation: LPPROCESS_INFORMATION,
    ) -> BOOL;
    #[cfg(target_arch = "x86_64")]
    type Proctype = unsafe extern "C" fn(
        lpApplicationName: LPCSTR,
        lpCommandLine: LPSTR,
        lpProcessAttributes: LPSECURITY_ATTRIBUTES,
        lpThreadAttributes: LPSECURITY_ATTRIBUTES,
        bInheritHandles: BOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: LPVOID,
        lpCurrentDirectory: LPCSTR,
        lpStartupInfo: LPSTARTUPINFOA,
        lpProcessInformation: LPPROCESS_INFORMATION,
    ) -> BOOL;

    let dllpaths: [*const i8; 1] = [dllpathptr.as_bytes_with_nul().as_ptr() as _];
    let realapi: Proctype = std::mem::transmute(REAL_CREATEPROCESSA);
    if detours::DetourCreateProcessWithDllsA(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        ppi,
        1,
        dllpaths.as_ptr() as _,
        Some(realapi),
    ) != TRUE
    {
        eprintln!(
            "TRAPS: DetourCreateProcessWithDllEx failed with {}\n",
            winapi::um::errhandlingapi::GetLastError()
        );
        return FALSE;
    }
    if lpCommandLine != std::ptr::null_mut() {
        let _ = record_event(lpCommandLine, FileEventType::Exec)
            .map_err(|x| eprintln!("record failed in detouring process:{}", x));
    } else {
        let _ = record_event(lpApplicationName, FileEventType::Exec)
            .map_err(|x| eprintln!("record failed in detouring process:{}", x));
    }

    if ppi == &mut pi as *mut _ {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    return TRUE;
}

pub unsafe extern "system" fn TrapCreateProcessW(
    lpApplicationName: LPCWSTR,
    lpCommandLine: LPWSTR,
    lpProcessAttributes: LPSECURITY_ATTRIBUTES,
    lpThreadAttributes: LPSECURITY_ATTRIBUTES,
    bInheritHandles: BOOL,
    dwCreationFlags: DWORD,
    lpEnvironment: LPVOID,
    lpCurrentDirectory: LPCWSTR,
    lpStartupInfo: LPSTARTUPINFOW,
    lpProcessInformation: LPPROCESS_INFORMATION,
) -> BOOL {
    use winapi::um::handleapi::CloseHandle;
    #[cfg(target_arch = "x86")]
    type Proctype = unsafe extern "stdcall" fn(
        lpApplicationName: LPCWSTR,
        lpCommandLine: LPWSTR,
        lpProcessAttributes: LPSECURITY_ATTRIBUTES,
        lpThreadAttributes: LPSECURITY_ATTRIBUTES,
        bInheritHandles: BOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: LPVOID,
        lpCurrentDirectory: LPCWSTR,
        lpStartupInfo: LPSTARTUPINFOW,
        lpProcessInformation: LPPROCESS_INFORMATION,
    ) -> BOOL;
    #[cfg(target_arch = "x86_64")]
    type Proctype = unsafe extern "C" fn(
        lpApplicationName: LPCWSTR,
        lpCommandLine: LPWSTR,
        lpProcessAttributes: LPSECURITY_ATTRIBUTES,
        lpThreadAttributes: LPSECURITY_ATTRIBUTES,
        bInheritHandles: BOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: LPVOID,
        lpCurrentDirectory: LPCWSTR,
        lpStartupInfo: LPSTARTUPINFOW,
        lpProcessInformation: LPPROCESS_INFORMATION,
    ) -> BOOL;
    let realapi: Proctype = std::mem::transmute(REAL_CREATEPROCESSW);
    let mut ppi: LPPROCESS_INFORMATION = lpProcessInformation;
    let null = std::ptr::null_mut();
    let mut pi: PROCESS_INFORMATION = PROCESS_INFORMATION {
        hProcess: null as _,
        hThread: null as _,
        dwProcessId: 0,
        dwThreadId: 0,
    };
    if ppi == null {
        ppi = &mut pi;
    }
    let mut paths = match std::env::var_os("PATH") {
        Some(path) => std::env::split_paths(&path).collect::<Vec<_>>(),
        None => vec![],
    };
    let iswow: BOOL = FALSE;
    winapi::um::wow64apiset::IsWow64Process(GetCurrentProcess(), &iswow as *const _ as _);
    if let Some(dllpath) = std::path::PathBuf::from(DLLPATHW.as_str()).parent() {
        // println!("dllpath is:{:?}", dllpath);
        paths.push(dllpath.to_path_buf());
    }
    let mut PXX: &'static str = "tupinject64.dll";
    if iswow != FALSE {
        PXX = "tupinject32.dll";
    }

    let paths = paths
        .iter()
        .map(|pb| pb.as_path().join(PXX))
        .find(|x| x.is_file())
        .expect(format!("{} not found in path", PXX).as_str());
    let dllpath = std::ffi::CString::new(paths.to_str().unwrap());
    let dllpathptr = dllpath.unwrap();

    let dllpaths: [*const i8; 1] = [dllpathptr.as_bytes_with_nul().as_ptr() as _];
    if detours::DetourCreateProcessWithDllsW(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        ppi,
        1,
        dllpaths.as_ptr() as _,
        Some(realapi),
    ) != TRUE
    {
        eprintln!(
            "TRAPS: DetourCreateProcessWithDllEx failed with {}\n",
            winapi::um::errhandlingapi::GetLastError()
        );
        return FALSE;
    }
    if ppi == &mut pi as *mut _ {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    if lpCommandLine != std::ptr::null_mut() {
        let _ = record_event_wide(lpCommandLine, FileEventType::Exec)
            .map_err(|x| eprintln!("record failed in detouring process:{}", x));
    } else {
        let _ = record_event_wide(lpApplicationName, FileEventType::Exec)
            .map_err(|x| eprintln!("record failed in detouring process:{}", x));
    }

    return TRUE;
}
pub unsafe extern "system" fn TrapNtOpenFile(
    FileHandle: PHANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    IoStatusBlock: PIO_STATUS_BLOCK,
    ShareAccess: ULONG,
    OpenOptions: ULONG,
) -> NTSTATUS {
    type Proctype = unsafe extern "system" fn(
        FileHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        IoStatusBlock: PIO_STATUS_BLOCK,
        ShareAccess: ULONG,
        OpenOptions: ULONG,
    ) -> NTSTATUS;
    let realapi: Proctype = std::mem::transmute(REAL_NTOPENFILE);
    let ret = realapi(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        ShareAccess,
        OpenOptions,
    );
    let uni = (*ObjectAttributes).ObjectName;
    if ret == winapi::shared::ntstatus::STATUS_SUCCESS
        && *FileHandle != std::ptr::null_mut()
        && winapi::um::fileapi::GetFileType(*FileHandle) == winapi::um::winbase::FILE_TYPE_DISK
        && Some(false) == is_directory(*FileHandle)
    {
        let buf = (*uni).Buffer;
        let write = DesiredAccess & TUP_CREATE_WRITE_FLAGS != 0;
        let unlink = (DesiredAccess & TUP_UNLINK_FLAGS != 0)
            || (OpenOptions & ntapi::ntioapi::FILE_DELETE_ON_CLOSE != 0);
        if write {
            let _ = record_event_wide_len(buf, ((*uni).Length >> 1) as isize, FileEventType::Write)
                .map_err(|x| eprintln!("record failed in write:trapntopenfile:{}", x));
        } else if unlink {
            let _ =
                record_event_wide_len(buf, ((*uni).Length >> 1) as isize, FileEventType::Unlink)
                    .map_err(|x| eprintln!("record failed in unlink:trapntopenfile:{}", x));
        } else {
            let _ = record_event_wide_len(buf, ((*uni).Length >> 1) as isize, FileEventType::Read)
                .map_err(|x| eprintln!("record failed in read:trapntopenfile:{}", x));
        }
    }
    ret
}

// unsafe fn GetFileName(FileHandle : PHANDLE)
// {
//     use winapi::um::fileapi::{
//         BY_HANDLE_FILE_INFORMATION,
//         GetFileInformationByHandle, GetFileType,
//     };
//     use winapi::um::winnt;
//     use winapi::um::fileapi::FILE_NAME_INFO;
//     use winapi::um::minwinbase::FileNameInfo;
//     use std::ffi::OsString;
//     use std::mem;
//     use std::os::raw::c_void;
//     use std::os::windows::ffi::OsStringExt;
//     use std::slice;
//     let size = mem::size_of::<FILE_NAME_INFO>();
//     let mut name_info_bytes = vec![0u8; size + (1<<15)];
//     let res = GetFileInformationByHandle(handle,
//                                            FileNameInfo,
//                                            &mut *name_info_bytes as *mut _ as *mut c_void,
//                                            name_info_bytes.len() as u32);
//     if res == 0 {
//         return true;
//     }
//     let name_info: FILE_NAME_INFO = *(name_info_bytes[0..size]
//                                       .as_ptr() as *const FILE_NAME_INFO);
//     let name_bytes = &name_info_bytes[size..size + name_info.FileNameLength as usize];
//     let name_u16 = slice::from_raw_parts(name_bytes.as_ptr() as *const u16,
//                                          name_bytes.len() / 2);
//     let name = OsString::from_wide(name_u16)
//         .as_os_str()
//         .to_string_lossy()
//         .into_owned();
// }
fn is_directory(filehandle: HANDLE) -> Option<bool> {
    use winapi::um::fileapi::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};

    unsafe {
        let mut info: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        let rc = GetFileInformationByHandle(filehandle, &mut info);
        if rc == 0 {
            return None;
        }
        return Some(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY) != 0);
    }
}

pub unsafe extern "system" fn TrapNtCreateFile(
    FileHandle: PHANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    IoStatusBlock: PIO_STATUS_BLOCK,
    AllocationSize: PLARGE_INTEGER,
    FileAttributes: ULONG,
    ShareAccess: ULONG,
    CreateDisposition: ULONG,
    CreateOptions: ULONG,
    EaBuffer: PVOID,
    EaLength: ULONG,
) -> NTSTATUS {
    type Proctype = unsafe extern "system" fn(
        FileHandle: PHANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: POBJECT_ATTRIBUTES,
        IoStatusBlock: PIO_STATUS_BLOCK,
        AllocationSize: PLARGE_INTEGER,
        FileAttributes: ULONG,
        ShareAccess: ULONG,
        CreateDisposition: ULONG,
        CreateOptions: ULONG,
        EaBuffer: PVOID,
        EaLength: ULONG,
    ) -> NTSTATUS;
    let realapi: Proctype = std::mem::transmute(REAL_NTCREATEFILE);
    let ret = realapi(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        AllocationSize,
        FileAttributes,
        ShareAccess,
        CreateDisposition,
        CreateOptions,
        EaBuffer,
        EaLength,
    );
    if ret == winapi::shared::ntstatus::STATUS_SUCCESS
        && *FileHandle != std::ptr::null_mut()
        && winapi::um::fileapi::GetFileType(*FileHandle) == winapi::um::winbase::FILE_TYPE_DISK
        && Some(false) == is_directory(*FileHandle)
    {
        let uni = (*ObjectAttributes).ObjectName;
        let buf = (*uni).Buffer; //todo: use ObjectAttributes.RootDirectory for rel paths
        let write = DesiredAccess & TUP_CREATE_WRITE_FLAGS != 0;
        let unlink = (DesiredAccess & TUP_UNLINK_FLAGS != 0)
            || (CreateOptions & ntapi::ntioapi::FILE_DELETE_ON_CLOSE != 0);
        if write {
            let _ = record_event_wide_len(buf, ((*uni).Length >> 1) as isize, FileEventType::Write)
                .map_err(|x| eprintln!("record failed in write:trapntcreatefile:{}", x));
        } else if unlink {
            let _ =
                record_event_wide_len(buf, ((*uni).Length >> 1) as isize, FileEventType::Unlink)
                    .map_err(|x| eprintln!("record failed in unlink:trapntcreatefile:{}", x));
        } else {
            let _ = record_event_wide_len(buf, ((*uni).Length >> 1) as isize, FileEventType::Read)
                .map_err(|x| eprintln!("record failed in read:trapntcreatefile:{}", x));
        }
    }
    ret
}
