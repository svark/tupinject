#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
// use winapi::um::fileapi::{CreateFileA, CreateFileW};
// use winapi::um::fileapi::{DeleteFileA, DeleteFileW};
// use winapi::um::fileapi::{FindFirstFileA, FindFirstFileW};
// use winapi::um::fileapi::{FindFirstFileExA, FindFirstFileExW};
// use winapi::um::fileapi::{GetFileAttributesA, GetFileAttributesW};
// use winapi::um::fileapi::{GetFileAttributesExA, GetFileAttributesExW};
// use winapi::um::fileapi::{
//     SetFileAttributesA,
//     SetFileAttributesW,
//     //TODO:                          SetFileInformationByHandle
// };
use winapi::um::processthreadsapi::{
    GetCurrentProcessId, GetCurrentThread};
use winapi::um::processthreadsapi::{LPPROCESS_INFORMATION, LPSTARTUPINFOA, LPSTARTUPINFOW};
// use winapi::um::winbase::{
//     CopyFile2, CopyFileA, CopyFileExA, CopyFileExW, CopyFileTransactedA, CopyFileTransactedW,
//     CopyFileW, MoveFileA, MoveFileExA, MoveFileExW, MoveFileW, OpenFile, ReplaceFileA,
//     ReplaceFileW};
 use named_pipe::PipeClient;
 use std::io::{Write};
use winapi::{
    shared::minwindef::{
        BOOL,
        DWORD,
        FALSE,
        HMODULE, //PDWORD, PUCHAR,
        HINSTANCE,
        LPBOOL,
        LPVOID,
        TRUE,
        // TRUE, UCHAR,
        UINT,
        ULONG,
        FARPROC
    },
    um::minwinbase::{
        // CRITICAL_SECTION,
        FINDEX_INFO_LEVELS, FINDEX_SEARCH_OPS, GET_FILEEX_INFO_LEVELS,
        LPSECURITY_ATTRIBUTES, LPWIN32_FIND_DATAA, LPWIN32_FIND_DATAW,
    },
    um::winbase::{COPYFILE2_EXTENDED_PARAMETERS, LPOFSTRUCT, LPPROGRESS_ROUTINE},
    um::winnt::{
        DELETE, FILE_GENERIC_WRITE, GENERIC_WRITE, HANDLE, HRESULT, LPCSTR, LPCWSTR, LPSTR, LPWSTR,
        PCHAR, PCSTR, PCWSTR, PWCHAR, WCHAR, WRITE_DAC, WRITE_OWNER, PVOID,
    },
    // um::synchapi::{InitializeCriticalSection},
};
use winapi::{
    // um::fileapi::{
    //     CREATEFILE2_EXTENDED_PARAMETERS, LPBY_HANDLE_FILE_INFORMATION,
    // },
    // um::fileapi::{CREATE_ALWAYS, CREATE_NEW, OPEN_ALWAYS, OPEN_EXISTING, TRUNCATE_EXISTING},
    um::handleapi::INVALID_HANDLE_VALUE,
    um::libloaderapi::{GetProcAddress, GetModuleHandleW},
    shared::guiddef::GUID,
};
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

pub const TUP_CREATE_WRITE_FLAGS: u32 =
    (GENERIC_WRITE | FILE_GENERIC_WRITE | WRITE_OWNER | WRITE_DAC);
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
    // ReadVar,
}
impl ToString for FileEventType {
    fn to_string(&self) -> String {
        format!("{:?}", self)
    }
}

static mut REAL_DELETEFILEA : FARPROC = std::ptr::null_mut() as _;
static mut REAL_DELETEFILEW  : FARPROC = std::ptr::null_mut() as _;
static mut REAL_FINDFIRSTFILEA : FARPROC = std::ptr::null_mut() as _;
static mut REAL_FINDFIRSTFILEW : FARPROC = std::ptr::null_mut() as _;
static mut REAL_FINDFIRSTFILEEXA : FARPROC = std::ptr::null_mut() as _;
static mut REAL_FINDFIRSTFILEEXW : FARPROC = std::ptr::null_mut() as _;
static mut REAL_GETFILEATTRIBUTESA : FARPROC = std::ptr::null_mut() as _;
static mut REAL_GETFILEATTRIBUTESW : FARPROC = std::ptr::null_mut() as _;
static mut REAL_GETFILEATTRIBUTESEXA: FARPROC = std::ptr::null_mut() as _;
static mut REAL_GETFILEATTRIBUTESEXW: FARPROC = std::ptr::null_mut() as _;
static mut REAL_SETFILEATTRIBUTESA: FARPROC = std::ptr::null_mut() as _;
static mut REAL_SETFILEATTRIBUTESW: FARPROC = std::ptr::null_mut() as _;
static mut REAL_CREATEFILEA: FARPROC = std::ptr::null_mut() as _;
static mut REAL_CREATEFILEW: FARPROC = std::ptr::null_mut() as _;
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
static mut RRECORD : bool = true;
//
fn record_event(lpFileName: LPCSTR, evt: FileEventType) -> std::result::Result<usize, Error> {
    unsafe {
    if !RRECORD {
	      return Ok(0);
    }
    }
    let pid = unsafe { GetCurrentProcessId() };
    let fname = unsafe { CStr::from_ptr(lpFileName).to_str().unwrap() };
	  // println!("{}from pid:{}", fname, pid);
    // use std::fs::File;
    // use std::fs::OpenOptions;
    // use std::io::Write;
    // let mut file: File = OpenOptions::new()
    //     .append(true)
    //     .open(format!("c:\\temp\\evts-{}.txt", pid))?;
    // let name = std::str::from_utf8(lpFileName).unwrap();
    let mut client = PipeClient::connect_ms(TBLOG_PIPE_NAME, 0)?;
    // file.write(fname.as_bytes())?;
    // file.write(b"\n")?;
    // file.write(evt.to_string().as_bytes())
    client.write(fname.as_bytes())?;
    client.write("\n".as_bytes())?;
    client.write(pid.to_string().as_bytes())?;
    client.write("\n".as_bytes())?;
    client.write(evt.to_string().as_bytes())?;
    client.write("\n".as_bytes())
    // Ok(1)
}
// wide string version of the above
fn record_event_wide(lpFileName: LPCWSTR, evt: FileEventType) -> std::result::Result<usize, Error> {
    unsafe {if !RRECORD {
	      return Ok(0);
    }
    }
    let pid = unsafe { GetCurrentProcessId() };
    // use std::io::Write;
    let p = { lpFileName as *const u16 };
    let mut len = 0;
	//println("{}", lpFileName);
     unsafe {
         while *p.offset(len) != 0 {
             len += 1;
         }
    }
     let name = unsafe { std::slice::from_raw_parts(p as *const u16, len as usize) };
     let u16str: OsString = OsStringExt::from_wide(name);
	 // println!("{}", u16str.to_str().unwrap());
    let mut client = PipeClient::connect_ms(TBLOG_PIPE_NAME, 0)?;
    client.write(u16str.to_str().unwrap().as_bytes())?;
    client.write("\n".as_bytes())?;
    client.write(pid.to_string().as_bytes())?;
    client.write("\n".as_bytes())?;
    client.write(evt.to_string().as_bytes())?;
    client.write("\n".as_bytes())
    // Ok(1)
}

unsafe extern "system" fn TrapDeleteFileA(lpFileName: LPCSTR) -> BOOL {
    type ProcType = unsafe extern "system" fn (lpFileName: LPCSTR) -> BOOL ;
    let realapi : ProcType = std::mem::transmute(REAL_DELETEFILEA);
    let ret = realapi(lpFileName);
    if ret != FALSE {
        let _ = record_event(lpFileName,  FileEventType::Unlink);
    }
    ret
}

unsafe extern "system" fn TrapDeleteFileW(lpFileName: LPCWSTR) -> BOOL {
    type ProcType =unsafe extern "system" fn (lpFileName: LPCWSTR) -> BOOL ;
    let realapi : ProcType = std::mem::transmute(REAL_DELETEFILEW);

    let ret = realapi(lpFileName);
    if ret != FALSE {
        let _ = record_event_wide(lpFileName, FileEventType::Unlink);
    }
    ret
}
unsafe extern "system" fn TrapFindFirstFileA(
    lpFileName: LPCSTR,
    lpFindFileData: LPWIN32_FIND_DATAA,
) -> HANDLE {
    type ProcType = extern "system" fn (
        lpFileName: LPCSTR,
        lpFindFileData: LPWIN32_FIND_DATAA,
    ) -> HANDLE ;
    let realapi : ProcType = std::mem::transmute(REAL_FINDFIRSTFILEA);

    let ret = realapi(lpFileName, lpFindFileData);
    if ret != INVALID_HANDLE_VALUE {
        let _ = record_event(lpFileName, FileEventType::Read);
    }
    ret
}
unsafe extern "system" fn TrapFindFirstFileW(
    lpFileName: LPCWSTR,
    lpFindFileData: LPWIN32_FIND_DATAW,
) -> HANDLE {
    type ProcType =unsafe extern "system" fn (
        lpFileName: LPCWSTR,
        lpFindFileData: LPWIN32_FIND_DATAW,
    ) -> HANDLE ;
    let realapi : ProcType = std::mem::transmute(REAL_FINDFIRSTFILEW);

    let ret = realapi(lpFileName, lpFindFileData);
    let _ = record_event_wide(lpFileName, FileEventType::Read);
    ret
}
unsafe extern "system" fn TrapFindFirstFileExA(
    lpFileName: LPCSTR,
    fInfoLevelId: FINDEX_INFO_LEVELS,
    lpFindFileData: LPVOID,
    fSearchOp: FINDEX_SEARCH_OPS,
    lpSearchFilter: LPVOID,
    dwAdditionalFlags: DWORD,
) -> HANDLE {
    type ProcType = extern "system" fn (
        lpFileName: LPCSTR,
        fInfoLevelId: FINDEX_INFO_LEVELS,
        lpFindFileData: LPVOID,
        fSearchOp: FINDEX_SEARCH_OPS,
        lpSearchFilter: LPVOID,
        dwAdditionalFlags: DWORD,
    ) -> HANDLE ;
    let realapi : ProcType = std::mem::transmute(REAL_FINDFIRSTFILEEXA);

    let ret = realapi(
        lpFileName,
        fInfoLevelId,
        lpFindFileData,
        fSearchOp,
        lpSearchFilter,
        dwAdditionalFlags,
    );
    if ret != INVALID_HANDLE_VALUE {
        let _ = record_event(lpFileName, FileEventType::Read);
    }
    ret
}
unsafe extern "system" fn TrapFindFirstFileExW(
    lpFileName: LPCWSTR,
    fInfoLevelId: FINDEX_INFO_LEVELS,
    lpFindFileData: LPVOID,
    fSearchOp: FINDEX_SEARCH_OPS,
    lpSearchFilter: LPVOID,
    dwAdditionalFlags: DWORD,
) -> HANDLE {
    type ProcType =unsafe extern "system" fn (
        lpFileName: LPCWSTR,
        fInfoLevelId: FINDEX_INFO_LEVELS,
        lpFindFileData: LPVOID,
        fSearchOp: FINDEX_SEARCH_OPS,
        lpSearchFilter: LPVOID,
        dwAdditionalFlags: DWORD,
    ) -> HANDLE ;
    let realapi : ProcType = std::mem::transmute(REAL_FINDFIRSTFILEEXW);

    let ret = realapi(
        lpFileName,
        fInfoLevelId,
        lpFindFileData,
        fSearchOp,
        lpSearchFilter,
        dwAdditionalFlags,
    );
    if ret != INVALID_HANDLE_VALUE {
        let _ = record_event_wide(lpFileName, FileEventType::Read);
    }
    ret
}
unsafe extern "system" fn TrapGetFileAttributesA(lpFileName: LPCSTR) -> DWORD {
    type ProcType = extern "system" fn (lpFileName: LPCSTR) -> DWORD ;
    let realapi : ProcType = std::mem::transmute(REAL_GETFILEATTRIBUTESA);

    let ret = realapi(lpFileName);
    let _ = record_event(lpFileName, FileEventType::Read);
    ret
}
unsafe extern "system" fn TrapGetFileAttributesW(lpFileName: LPCWSTR) -> DWORD {
    type ProcType =unsafe extern "system" fn (lpFileName: LPCWSTR) -> DWORD ;
    let realapi : ProcType = std::mem::transmute(REAL_GETFILEATTRIBUTESW);

    let ret = realapi(lpFileName);
    let _ = record_event_wide(lpFileName, FileEventType::Read);
    ret
}
unsafe extern "system" fn TrapGetFileAttributesExA(
    lpFileName: LPCSTR,
    fInfoLevelId: GET_FILEEX_INFO_LEVELS,
    lpFileInformation: LPVOID,
) -> BOOL {
    type ProcType =unsafe extern "system" fn (
        lpFileName: LPCSTR,
        fInfoLevelId: GET_FILEEX_INFO_LEVELS,
        lpFileInformation: LPVOID,
    ) -> BOOL ;
    let realapi : ProcType = std::mem::transmute(REAL_GETFILEATTRIBUTESEXA);

    let ret = realapi(lpFileName, fInfoLevelId, lpFileInformation);
    if ret != FALSE {
        let _ = record_event(lpFileName, FileEventType::Write);
    }
    ret
}
unsafe extern "system" fn TrapGetFileAttributesExW(
    lpFileName: LPCWSTR,
    fInfoLevelId: GET_FILEEX_INFO_LEVELS,
    lpFileInformation: LPVOID,
) -> BOOL {
    type ProcType =unsafe extern "system" fn (
        lpFileName: LPCWSTR,
        fInfoLevelId: GET_FILEEX_INFO_LEVELS,
        lpFileInformation: LPVOID,
    ) -> BOOL ;
    let realapi : ProcType = std::mem::transmute(REAL_GETFILEATTRIBUTESEXW);

    let ret = realapi(lpFileName, fInfoLevelId, lpFileInformation);
    if ret != FALSE {
        let _ = record_event_wide(lpFileName, FileEventType::Write);
    }
    ret
}
unsafe extern "system" fn TrapSetFileAttributesA(
    lpFileName: LPCSTR,
    dwFileAttributes: DWORD,
) -> BOOL {
    type ProcType =unsafe extern "system" fn (
        lpFileName: LPCSTR,
        dwFileAttributes: DWORD,
    ) -> BOOL ;
    let realapi : ProcType = std::mem::transmute(REAL_SETFILEATTRIBUTESA);

    let ret = realapi(lpFileName, dwFileAttributes);
    if ret != FALSE {
        let _ = record_event(lpFileName, FileEventType::Write);
    }
    ret
}

unsafe extern "system" fn TrapSetFileAttributesW(
    lpFileName: LPCWSTR,
    dwFileAttributes: DWORD,
) -> BOOL {
    type ProcType =unsafe extern "system" fn (
        lpFileName: LPCWSTR,
        dwFileAttributes: DWORD,
    ) -> BOOL ;
    let realapi : ProcType = std::mem::transmute(REAL_SETFILEATTRIBUTESW);

    let ret = realapi(lpFileName, dwFileAttributes);
    if ret != FALSE {
        let _ = record_event_wide(lpFileName, FileEventType::Write);
    }
    ret
}

pub unsafe extern "system" fn TrapCreateFileA(
    lpFileName: LPCSTR,
    dwDesiredAccess: DWORD,
    dwShareMode: DWORD,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
    dwCreationDisposition: DWORD,
    dwFlagsAndAttributes: DWORD,
    hTemplateFile: HANDLE,
) -> HANDLE {
    type ProcType = unsafe extern "system" fn (
        LPCSTR,
        DWORD,
        DWORD,
        LPSECURITY_ATTRIBUTES,
        DWORD,
        DWORD,
        HANDLE,
    ) -> HANDLE;
    let realapi : ProcType = std::mem::transmute(REAL_CREATEFILEA);
    let handle =  realapi(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile,
    );

    if handle != INVALID_HANDLE_VALUE && winapi::um::fileapi::GetFileType(handle as _) == winapi::um::winbase::FILE_TYPE_DISK  {
        if dwDesiredAccess & TUP_UNLINK_FLAGS != 0 || dwShareMode & TUP_UNLINK_FLAGS != 0 {
            let _ = record_event(lpFileName, FileEventType::Unlink).map_err(|x| {
                eprintln!("{}", x);
                0
            });
        } else if dwDesiredAccess & TUP_CREATE_WRITE_FLAGS != 0 {
            let _ = record_event(lpFileName, FileEventType::Write).map_err(|x| {
                eprintln!("{}", x);
                0
            });
        } else {
            let _ = record_event(lpFileName, FileEventType::Read).map_err(|x| {
                eprintln!("{}", x);
                0
            });
        }
    }
    handle
}
pub unsafe extern "system" fn TrapCreateFileW(
    lpFileName: LPCWSTR,
    dwDesiredAccess: DWORD,
    dwShareMode: DWORD,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
    dwCreationDisposition: DWORD,
    dwFlagsAndAttributes: DWORD,
    hTemplateFile: HANDLE,
) -> HANDLE {
    type ProcType = unsafe extern "system" fn (
        lpFileName: LPCWSTR,
        dwDesiredAccess: DWORD,
        dwShareMode: DWORD,
        lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
        dwCreationDisposition: DWORD,
        dwFlagsAndAttributes: DWORD,
        hTemplateFile: HANDLE,
    ) -> HANDLE ;
    let mut handle = std::ptr::null_mut();
    if  lpFileName != std::ptr::null_mut() {
        let realapi : ProcType = std::mem::transmute(REAL_CREATEFILEW);
        handle =  realapi(
            lpFileName,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile,
        );
    }

    if handle != INVALID_HANDLE_VALUE
        && winapi::um::fileapi::GetFileType(handle as _) == winapi::um::winbase::FILE_TYPE_DISK {
        if dwDesiredAccess & TUP_UNLINK_FLAGS != 0 || dwShareMode & TUP_UNLINK_FLAGS != 0 {
            let _ = record_event_wide(lpFileName, FileEventType::Unlink).map_err(|x| {
                eprintln!("{}", x);
                0
            });
        } else if dwDesiredAccess & TUP_CREATE_WRITE_FLAGS != 0 {
            let _ = record_event_wide(lpFileName, FileEventType::Write).map_err(|x| {
                eprintln!("{}", x);
                0
            });
        } else {
            let _ = record_event_wide(lpFileName, FileEventType::Read).map_err(|x| {
                eprintln!("{}", x);
                0
            });
        }
    }
    handle
}

pub unsafe extern "system" fn TrapCopyFile2(
    pwszExistingFileName: PCWSTR,
    pwszNewFileName: PCWSTR,
    pExtendedParameters: *mut COPYFILE2_EXTENDED_PARAMETERS,
) -> HRESULT {
    type ProcType = unsafe extern "system" fn (
        pwszExistingFileName: PCWSTR,
        pwszNewFileName: PCWSTR,
        pExtendedParameters: *mut COPYFILE2_EXTENDED_PARAMETERS,
    ) -> HRESULT ;
    let realapi : ProcType = std::mem::transmute(REAL_COPYFILE2);
    let res = realapi(
        pwszExistingFileName,
        pwszNewFileName,
        pExtendedParameters as _,
    );
    if res != 0 {
        let _ = record_event_wide(pwszNewFileName, FileEventType::Write);
        let _ = record_event_wide(pwszExistingFileName, FileEventType::Read);
    }
    res
}
pub unsafe extern "system" fn TrapCopyFileA(
    lpExistingFileName: LPCSTR,
    lpNewFileName: LPCSTR,
    bFailIfExists: BOOL,
) -> BOOL {
    type ProcType = unsafe extern "system" fn (
        lpExistingFileName: LPCSTR,
        lpNewFileName: LPCSTR,
        bFailIfExists: BOOL,
    ) -> BOOL ;
    let realapi : ProcType = std::mem::transmute(REAL_COPYFILEA);

    let res = realapi(lpExistingFileName, lpNewFileName, bFailIfExists);
    if res != 0 {
        let _ = record_event(lpNewFileName, FileEventType::Write);
        let _ = record_event(lpExistingFileName, FileEventType::Read);
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
    type ProcType = unsafe extern "system" fn (
        lpExistingFileName: LPCSTR,
        lpNewFileName: LPCSTR,
        lpProgressRoutine: LPPROGRESS_ROUTINE,
        lpData: LPVOID,
        pbCancel: LPBOOL,
        dwCopyFlags: DWORD,
    ) -> BOOL ;
    let realapi : ProcType = std::mem::transmute(REAL_COPYFILEEXA);

    let ret = realapi(
        lpExistingFileName,
        lpNewFileName,
        lpProgressRoutine,
        lpData as _,
        pbCancel,
        dwCopyFlags,
    );
    if ret != FALSE {
        let _ = record_event(lpExistingFileName, FileEventType::Read);
        let _ = record_event(lpNewFileName, FileEventType::Write);
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
    type ProcType = unsafe extern "system" fn (
        lpExistingFileName: LPCWSTR,
        lpNewFileName: LPCWSTR,
        lpProgressRoutine: LPPROGRESS_ROUTINE,
        lpData: LPVOID,
        pbCancel: LPBOOL,
        dwCopyFlags: DWORD,
    ) -> BOOL ;
    let realapi : ProcType = std::mem::transmute(REAL_COPYFILEEXW);

    let ret = realapi(
        lpExistingFileName,
        lpNewFileName,
        lpProgressRoutine,
        lpData,
        pbCancel,
        dwCopyFlags,
    );
    if ret != FALSE {
        let _ = record_event_wide(lpExistingFileName, FileEventType::Read);
        let _ = record_event_wide(lpNewFileName, FileEventType::Write);
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
    type ProcType = unsafe extern "system" fn (
        lpExistingFileName: LPCWSTR,
        lpNewFileName: LPCWSTR,
        lpProgressRoutine: LPPROGRESS_ROUTINE,
        lpData: LPVOID,
        pbCancel: LPBOOL,
        dwCopyFlags: DWORD,
        hTransaction: HANDLE,
    ) -> BOOL ;
    let realapi : ProcType = std::mem::transmute(REAL_COPYFILETRANSACTEDA);

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
        let _ = record_event_wide(lpExistingFileName, FileEventType::Read);
        let _ = record_event_wide(lpNewFileName, FileEventType::Write);
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
    type ProcType = unsafe extern "system" fn (
        lpExistingFileName: LPCWSTR,
        lpNewFileName: LPCWSTR,
        lpProgressRoutine: LPPROGRESS_ROUTINE,
        lpData: LPVOID,
        pbCancel: LPBOOL,
        dwCopyFlags: DWORD,
        hTransaction: HANDLE,
    ) -> BOOL ;
    let realapi : ProcType = std::mem::transmute(REAL_COPYFILETRANSACTEDW);

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
        let _ = record_event_wide(lpExistingFileName, FileEventType::Read);
        let _ = record_event_wide(lpNewFileName, FileEventType::Write);
    }
    ret
}
pub unsafe extern "system" fn TrapCopyFileW(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
    bFailIfExists: BOOL,
) -> BOOL {
    type ProcType = unsafe extern "system" fn (
        lpExistingFileName: LPCWSTR,
        lpNewFileName: LPCWSTR,
        bFailIfExists: BOOL,
    ) -> BOOL ;
    let realapi : ProcType = std::mem::transmute(REAL_COPYFILEW);

    let ret = realapi(lpExistingFileName, lpNewFileName, bFailIfExists);
    if ret != FALSE {
        let _ = record_event_wide(lpExistingFileName, FileEventType::Read);
        let _ = record_event_wide(lpNewFileName, FileEventType::Write);
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
    type ProcType = unsafe extern "system" fn (
        lpReplacedFileName: LPCSTR,
        lpReplacementFileName: LPCSTR,
        lpBackupFileName: LPCSTR,
        dwReplaceFlags: DWORD,
        lpExclude: LPVOID,
        lpReserved: LPVOID,
    );
    let realapi : ProcType = std::mem::transmute(REAL_REPLACEFILEA);

    realapi( lpReplacedFileName,
             lpReplacementFileName,
             lpBackupFileName,
             dwReplaceFlags,
             lpExclude as _,
             lpReserved as _);
    {
        let _ = record_event(lpReplacedFileName, FileEventType::Unlink);
        let _ = record_event(lpReplacementFileName, FileEventType::Write);
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
    type ProcType = unsafe extern "system" fn (
        lpReplacedFileName: LPCWSTR,
        lpReplacementFileName: LPCWSTR,
        lpBackupFileName: LPCWSTR,
        dwReplaceFlags: DWORD,
        lpExclude: LPVOID,
        lpReserved: LPVOID,
    ) ;
    let realapi : ProcType = std::mem::transmute(REAL_REPLACEFILEW);
    realapi(lpReplacedFileName, lpReplacementFileName, lpBackupFileName, dwReplaceFlags, lpExclude, lpReserved);
    {
        let _ = record_event_wide(lpReplacedFileName, FileEventType::Unlink);
        let _ = record_event_wide(lpReplacementFileName, FileEventType::Write);
    }
}

pub unsafe extern "system" fn TrapMoveFileA(lpExistingFileName: LPCSTR, lpNewFileName: LPCSTR) -> BOOL {
    type ProcType = unsafe extern "system" fn(lpExistingFileName: LPCSTR, lpNewFileName: LPCSTR) -> BOOL ;
    let realapi : ProcType = std::mem::transmute(REAL_MOVEFILEA);
    let ret : BOOL = realapi(lpExistingFileName, lpNewFileName, );
    if ret != FALSE
    {
        let _ = record_event(lpExistingFileName, FileEventType::Unlink);
        let _ = record_event(lpNewFileName, FileEventType::Write);
    }
    ret
}
pub unsafe extern "system" fn TrapMoveFileW(lpExistingFileName: LPCWSTR, lpNewFileName: LPCWSTR) -> BOOL {
    type ProcType = unsafe extern "system" fn(lpExistingFileName: LPCWSTR, lpNewFileName: LPCWSTR) -> BOOL ;
    let realapi : ProcType = std::mem::transmute(REAL_MOVEFILEW);

    let ret = realapi(lpExistingFileName, lpNewFileName);
    if ret != FALSE {
        let _ = record_event_wide(lpExistingFileName, FileEventType::Unlink);
        let _ = record_event_wide(lpNewFileName, FileEventType::Write);
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
    let realapi : ProcType = std::mem::transmute(REAL_MOVEFILEEXA);

    let ret = realapi(lpExistingFileName, lpNewFileName, dwFlags);
    if ret != FALSE {
        let _ = record_event(lpExistingFileName, FileEventType::Unlink);
        let _ = record_event(lpNewFileName, FileEventType::Write);
    }
    ret
}
pub unsafe extern "system" fn TrapMoveFileExW(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
    dwFlags: DWORD,
) -> BOOL {
    type ProcType = unsafe extern "system" fn (
        lpExistingFileName: LPCWSTR,
        lpNewFileName: LPCWSTR,
        dwFlags: DWORD,
    ) -> BOOL ;
    let realapi : ProcType = std::mem::transmute(REAL_MOVEFILEEXW);

    let ret = realapi(lpExistingFileName, lpNewFileName, dwFlags);
    if ret != FALSE {
        let _ = record_event_wide(lpExistingFileName, FileEventType::Unlink);
        let _ = record_event_wide(lpNewFileName, FileEventType::Write);
    }
    ret
}

pub unsafe extern "system" fn TrapOpenFile(
    lpFileName: LPCSTR,
    lpReOpenBuff: LPOFSTRUCT,
    uStyle: UINT,
) {
    type ProcType = unsafe extern "system" fn (
        lpFileName: LPCSTR,
        lpReOpenBuff: LPOFSTRUCT,
        uStyle: UINT,
    ) ;
    let realapi : ProcType = std::mem::transmute(REAL_OPENFILE);
    realapi(lpFileName, lpReOpenBuff, uStyle);

    if uStyle & OF_DELETE != 0 {
        let _ = record_event(lpFileName, FileEventType::Unlink);
    } else if uStyle
        & (OF_READWRITE | OF_WRITE | OF_SHARE_DENY_WRITE | OF_SHARE_EXCLUSIVE | OF_CREATE)
        != 0
    {
        let _ = record_event(lpFileName, FileEventType::Write);
    } else {
        let _ = record_event(lpFileName, FileEventType::Read);
    }
}

pub type EntryPointType = unsafe extern "system" fn();
// unsafe extern "system" fn empty_entry_point() {}
type BigPath = [WCHAR; 1024];

const SIZEOFBIGPATH: u32 = 1024;
#[derive(Clone)]
pub struct Payload {
    depFile: BigPath,
    varDictFile: BigPath,
}
pub struct TrapInfo {
    hInst: HMODULE,
    // hKernel32: HMODULE,
    // zDllPath: BigPath,
    // payLoad: Payload,
    // zExecDir : BigPath,
}

impl Default for TrapInfo {
    fn default() -> TrapInfo {
        let inst: HMODULE = 0 as _;
        TrapInfo {
            hInst: inst,
            // zDllPath: [0; 1024],
            // payLoad: Payload::new(),
        }
    }
}
static mut REALENTRYPOINT: FARPROC = std::ptr::null_mut();
// pub struct Comm {
//     csPipe: CRITICAL_SECTION, // Guards access to hPipe.
//     hPipe: HANDLE,
//     csChildPayLoad: CRITICAL_SECTION,
//     // nPipeCnt: u32
// }
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

pub unsafe extern "system" fn ImportFileCallback(
    _: PVOID,
    hFile: HINSTANCE,
    pszFile: PCSTR,
) -> BOOL {
    use std::ffi::CString;
    if pszFile != std::ptr::null() {
        let cpszFile = CStr::from_ptr(pszFile);
        if let Some(_s) = S_RPSZMSVCRNAMES
            .iter()
            .map(|s: &&str| CString::new(*s).expect("Cstring conversion failed"))
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

impl TrapInfo {
    pub fn new(hModule: HMODULE) -> Self {
        // let mut dllPath: BigPath = [0; SIZEOFBIGPATH as _];
        // unsafe {
        //     GetModuleFileNameW(hModule, (&mut dllPath).as_mut_ptr(), SIZEOFBIGPATH);
        // }
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
        detours::DetourUpdateThread(GetCurrentThread() as _);
        let kstr  = wstr!("kernel32\0");
        let  hkernel32 = GetModuleHandleW( kstr.as_ptr());
        let realapi = GetProcAddress(hkernel32, "DeleteFileA\0".as_ptr() as _, );
        REAL_DELETEFILEA = realapi;
        DetourAttach(
            &REAL_DELETEFILEA as *const _ as _,
            (TrapDeleteFileA as *const ()) as _,
        );
        let realapi = GetProcAddress(hkernel32, "DeleteFileW\0".as_ptr() as _, );
        REAL_DELETEFILEW = realapi;
        DetourAttach(
            &REAL_DELETEFILEW as *const _ as _,
            (TrapDeleteFileW as *const ()) as _,
        );
        let realapi = GetProcAddress(hkernel32, "FindFirstFileA\0".as_ptr() as _, );
        REAL_FINDFIRSTFILEA = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_FINDFIRSTFILEA as *const _ as _,
            (TrapFindFirstFileA as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "FindFirstFileW\0".as_ptr() as _,);
        REAL_FINDFIRSTFILEW = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_FINDFIRSTFILEW as *const _ as _,
            (TrapFindFirstFileW as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "FindFirstFileExA\0".as_ptr() as _,);
        REAL_FINDFIRSTFILEEXA = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_FINDFIRSTFILEEXA as *const _ as _,
            (TrapFindFirstFileExA as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "FindFirstFileExW\0".as_ptr() as _,);
        REAL_FINDFIRSTFILEEXW = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_FINDFIRSTFILEEXW as *const _ as _,
            (TrapFindFirstFileExW as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "GetFileAttributesA\0".as_ptr() as _,);
        REAL_GETFILEATTRIBUTESA = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_GETFILEATTRIBUTESA as *const _ as _,
            (TrapGetFileAttributesA as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "GetFileAttributesW\0".as_ptr() as _,);
        REAL_GETFILEATTRIBUTESW = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_GETFILEATTRIBUTESW as *const _ as _,
            (TrapGetFileAttributesW as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "GetFileAttributesExA\0".as_ptr() as _,);
        REAL_GETFILEATTRIBUTESEXA = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_GETFILEATTRIBUTESEXA as *const _ as _,
            (TrapGetFileAttributesExA as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "GetFileAttributesExW\0".as_ptr() as _,);
        REAL_GETFILEATTRIBUTESEXW = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_GETFILEATTRIBUTESEXW as *const _ as _,
            (TrapGetFileAttributesExW as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "SetFileAttributesA\0".as_ptr() as _,);
        REAL_SETFILEATTRIBUTESA = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_SETFILEATTRIBUTESA as *const _ as _,
            (TrapSetFileAttributesA as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "SetFileAttributesW\0".as_ptr() as _,);
        REAL_SETFILEATTRIBUTESW = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_SETFILEATTRIBUTESW as *const _ as _,
            (TrapSetFileAttributesW as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "CreateFileA\0".as_ptr() as _);
        REAL_CREATEFILEA = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_CREATEFILEA as *const _ as _,
            (TrapCreateFileA as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "CreateFileW\0".as_ptr() as _);
        REAL_CREATEFILEW = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_CREATEFILEW as *const _ as _,
            (TrapCreateFileW as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "CopyFile2\0".as_ptr() as _,);
        REAL_COPYFILE2 = std::mem::transmute(realapi);
        DetourAttach(&REAL_COPYFILE2 as *const _ as _,
                      (TrapCopyFile2 as *const ()) as _);

        let realapi = GetProcAddress(hkernel32, "CopyFileA\0".as_ptr() as _);
        REAL_COPYFILEA = std::mem::transmute(realapi);
        DetourAttach(&REAL_COPYFILEA as *const _ as _,
                     (TrapCopyFileA as *const ()) as _);

        let realapi = GetProcAddress(hkernel32, "CopyFileW\0".as_ptr() as _,);
        REAL_COPYFILEW = std::mem::transmute(realapi);
        DetourAttach(&REAL_COPYFILEW as *const _ as _,
                      (TrapCopyFileW as *const ()) as _);

        let realapi = GetProcAddress(hkernel32, "CopyFileExA\0".as_ptr() as _,);
        REAL_COPYFILEEXA = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_COPYFILEEXA as *const _ as _,
            (TrapCopyFileExA as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "CopyFileExW\0".as_ptr() as _,);
        REAL_COPYFILEEXW = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_COPYFILEEXW as *const _ as _,
            (TrapCopyFileExW as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "CopyFileTransactedA\0".as_ptr() as _,);
        REAL_COPYFILETRANSACTEDA = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_COPYFILETRANSACTEDA as *const _ as _,
            (TrapCopyFileTransactedA as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "CopyFileTransactedW\0".as_ptr() as _,);
        REAL_COPYFILETRANSACTEDW = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_COPYFILETRANSACTEDW as *const _ as _,
            (TrapCopyFileTransactedW as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "ReplaceFileA\0".as_ptr() as _,);
        REAL_REPLACEFILEA = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_REPLACEFILEA as *const _ as _,
            (TrapReplaceFileA as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "ReplaceFileW\0".as_ptr() as _,);
        REAL_REPLACEFILEW = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_REPLACEFILEW as *const _ as _,
            (TrapReplaceFileW as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "MoveFileA\0".as_ptr() as _,);
        REAL_MOVEFILEA = std::mem::transmute(realapi);
        DetourAttach(&REAL_MOVEFILEA as *const _ as _, (TrapMoveFileA as *const ()) as _);

        let realapi = GetProcAddress(hkernel32, "MoveFileW\0".as_ptr() as _,);
        REAL_MOVEFILEW = std::mem::transmute(realapi);
        DetourAttach(&REAL_MOVEFILEW as *const _ as _, (TrapMoveFileW as *const ()) as _);

        let realapi = GetProcAddress(hkernel32, "MoveFileExA\0".as_ptr() as _,);
        REAL_MOVEFILEEXA = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_MOVEFILEEXA as *const _ as _,
            (TrapMoveFileExA as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "MoveFileExW\0".as_ptr() as _,);
        REAL_MOVEFILEEXW = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_MOVEFILEEXW as *const _ as _,
            (TrapMoveFileExW as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "OpenFile\0".as_ptr() as _,);
        REAL_OPENFILE = std::mem::transmute(realapi);
        DetourAttach(&REAL_OPENFILE as *const _ as _, (TrapOpenFile as *const ()) as _);

        let realapi = GetProcAddress(hkernel32, "CreateProcessA\0".as_ptr() as _,);
        REAL_CREATEPROCESSA = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_CREATEPROCESSA as *const _ as _,
            (TrapCreateProcessA as *const ()) as _,
        );

        let realapi = GetProcAddress(hkernel32, "CreateProcessW\0".as_ptr() as _,);
        REAL_CREATEPROCESSW = std::mem::transmute(realapi);
        DetourAttach(
            &REAL_CREATEPROCESSW as *const _ as _,
            (TrapCreateProcessW as *const ()) as _,
        );
        let ep =
            detours::DetourGetEntryPoint(std::ptr::null_mut() as _)  ;
        REALENTRYPOINT = ep as _;
        DetourAttach(&REALENTRYPOINT as *const _  as _,
                     (TrapEntryPoint as *const ()) as _);


    }

    pub unsafe fn detach(&self) {
        use detours::DetourDetach;
        // let ptrap = TrapEntryPoint as *const ();
       DetourDetach(
            &REAL_DELETEFILEA as *const _ as _,
            (TrapDeleteFileA as *const ()) as _,
        );
        DetourDetach(
            &REAL_DELETEFILEW as *const _ as _,
            (TrapDeleteFileW as *const ()) as _,
        );
        DetourDetach(
            &REAL_FINDFIRSTFILEA as *const _ as _,
            (TrapFindFirstFileA as *const ()) as _,
        );

        DetourDetach(
            &REAL_FINDFIRSTFILEW as *const _ as _,
            (TrapFindFirstFileW as *const ()) as _,
        );

        DetourDetach(
            &REAL_FINDFIRSTFILEEXA as *const _ as _,
            (TrapFindFirstFileExA as *const ()) as _,
        );

        DetourDetach(
            &REAL_FINDFIRSTFILEEXW as *const _ as _,
            (TrapFindFirstFileExW as *const ()) as _,
        );

        DetourDetach(
            &REAL_GETFILEATTRIBUTESA as *const _ as _,
            (TrapGetFileAttributesA as *const ()) as _,
        );

        DetourDetach(
            &REAL_GETFILEATTRIBUTESW as *const _ as _,
            (TrapGetFileAttributesW as *const ()) as _,
        );

        DetourDetach(
            &REAL_GETFILEATTRIBUTESEXA as *const _ as _,
            (TrapGetFileAttributesExA as *const ()) as _,
        );

        DetourDetach(
            &REAL_GETFILEATTRIBUTESEXW as *const _ as _,
            (TrapGetFileAttributesExW as *const ()) as _,
        );

        DetourDetach(
            &REAL_SETFILEATTRIBUTESA as *const _ as _,
            (TrapSetFileAttributesA as *const ()) as _,
        );

        DetourDetach(
            &REAL_SETFILEATTRIBUTESW as *const _ as _,
            (TrapSetFileAttributesW as *const ()) as _,
        );

        DetourDetach(
            &REAL_CREATEFILEA as *const _ as _,
            (TrapCreateFileA as *const ()) as _,
        );

        DetourDetach(
            &REAL_CREATEFILEW as *const _ as _,
            (TrapCreateFileW as *const ()) as _,
        );

        DetourDetach(&REAL_COPYFILE2 as *const _ as _,
                      (TrapCopyFile2 as *const ()) as _);

        DetourDetach(&REAL_COPYFILEA as *const _ as _,
                     (TrapCopyFileA as *const ()) as _);

        DetourDetach(&REAL_COPYFILEW as *const _ as _,
                      (TrapCopyFileW as *const ()) as _);

        DetourDetach(
            &REAL_COPYFILEEXA as *const _ as _,
            (TrapCopyFileExA as *const ()) as _,
        );

        DetourDetach(
            &REAL_COPYFILEEXW as *const _ as _,
            (TrapCopyFileExW as *const ()) as _,
        );

        DetourDetach(
            &REAL_COPYFILETRANSACTEDA as *const _ as _,
            (TrapCopyFileTransactedA as *const ()) as _,
        );

        DetourDetach(
            &REAL_COPYFILETRANSACTEDW as *const _ as _,
            (TrapCopyFileTransactedW as *const ()) as _,
        );

        DetourDetach(
            &REAL_REPLACEFILEA as *const _ as _,
            (TrapReplaceFileA as *const ()) as _,
        );

        DetourDetach(
            &REAL_REPLACEFILEW as *const _ as _,
            (TrapReplaceFileW as *const ()) as _,
        );

        DetourDetach(&REAL_MOVEFILEA as *const _ as _, (TrapMoveFileA as *const ()) as _);

        DetourDetach(&REAL_MOVEFILEW as *const _ as _, (TrapMoveFileW as *const ()) as _);

        DetourDetach(
            &REAL_MOVEFILEEXA as *const _ as _,
            (TrapMoveFileExA as *const ()) as _,
        );

        DetourDetach(
            &REAL_MOVEFILEEXW as *const _ as _,
            (TrapMoveFileExW as *const ()) as _,
        );

        DetourDetach(&REAL_OPENFILE as *const _ as _, (TrapOpenFile as *const ()) as _);

        DetourDetach(
            &REAL_CREATEPROCESSA as *const _ as _,
            (TrapCreateProcessA as *const ()) as _,
        );

        DetourDetach(
            &REAL_CREATEPROCESSW as *const _ as _,
            (TrapCreateProcessW as *const ()) as _,
        );

        DetourDetach(&REALENTRYPOINT as *const _  as _,
                     (TrapEntryPoint as *const ()) as _);
         // msvc
        if REAL_GETENV != std::ptr::null_mut() {
            DetourDetach(
                &REAL_GETENV as *const _ as _,
                (Trap_getenv as *const ()) as _,
            );
        }
        if REAL_WGETENV != std::ptr::null_mut() {
            DetourDetach(
                &REAL_WGETENV as *const _ as _,
                (Trap_wgetenv as *const ()) as _,
            );
        }
        if REAL_GETENV_S != std::ptr::null_mut() {
            DetourDetach(
                &REAL_GETENV_S as *const _ as _,
                (Trap_getenv_s as *const ()) as _,
            );
        }
        if REAL_WGETENV_S != std::ptr::null_mut() {
            DetourDetach(
                &REAL_WGETENV_S as *const _ as _,
                (Trap_wgetenv_s as *const ()) as _,
            );
        }
        if REAL_DUPENV_S != std::ptr::null_mut() {
            DetourDetach(
                &REAL_DUPENV_S as *const _ as _,
                (Trap_dupenv_s as *const ()) as _,
            );
        }
        if REAL_WDUPENV_S != std::ptr::null_mut() {
            DetourDetach(
                &REAL_WDUPENV_S as *const _ as _,
                (Trap_wdupenv_s as *const ()) as _,
            );
        }
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
    // let name = std::str::from_utf8(lpFileName).unwrap();
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
    let realapi : Proctype = std::mem::transmute(REALENTRYPOINT);
    if FindMsvcr() {
        REAL_GETENV = GetProcAddress(S_HMSVCR as _, "getenv\0".as_ptr() as _) as _;
        REAL_WGETENV = GetProcAddress(S_HMSVCR as _, "_wgetenv\0".as_ptr() as _) as _;
        REAL_GETENV_S = GetProcAddress(S_HMSVCR as _, "getenv_s\0".as_ptr() as _) as _;
        REAL_WGETENV_S = GetProcAddress(S_HMSVCR as _, "_wgetenv_s\0".as_ptr() as _) as _;
        REAL_DUPENV_S = GetProcAddress(S_HMSVCR as _, "_dupenv_s\0".as_ptr() as _) as _;
        REAL_WDUPENV_S = GetProcAddress(S_HMSVCR as _, "_wdupenv_s\0".as_ptr() as _) as _;

        detours::DetourTransactionBegin();
        detours::DetourUpdateThread(GetCurrentThread() as _);

        detours::DetourAttach(&REAL_GETENV as *const _ as _, ((&Trap_getenv) as *const _) as _);
        detours::DetourAttach(&REAL_GETENV_S as *const _ as _, (&Trap_getenv_s as *const _) as _);
        detours::DetourAttach(&REAL_WGETENV as *const _ as _, (&Trap_wgetenv as *const _) as _);
        detours::DetourAttach(&REAL_WGETENV as *const _ as _, (&Trap_wgetenv_s as *const _) as _);
        detours::DetourAttach(&REAL_DUPENV_S as *const _ as _, (&Trap_dupenv_s as *const _) as _);
        detours::DetourAttach(&REAL_WDUPENV_S as *const _ as _, (&Trap_wdupenv_s as *const _) as _);
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
    type Proctype = unsafe extern "system" fn(
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
    let realapi : Proctype = std::mem::transmute(REAL_CREATEPROCESSA);
    realapi(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
    )
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
    println!("spwnedw!\n");
    type Proctype = unsafe extern "system" fn(
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
    let realapi : Proctype = std::mem::transmute(REAL_CREATEPROCESSW);
    realapi(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
    )
}
