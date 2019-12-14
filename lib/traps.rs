#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use winapi::{
    shared::minwindef::{
        BOOL, DWORD, FALSE, LPBOOL, LPVOID, HMODULE, //PDWORD, PUCHAR,
        // TRUE, UCHAR,
        UINT, TRUE },
    um::minwinbase::{
        FINDEX_INFO_LEVELS, FINDEX_SEARCH_OPS, GET_FILEEX_INFO_LEVELS,
        LPSECURITY_ATTRIBUTES, LPWIN32_FIND_DATAA,
        LPWIN32_FIND_DATAW, CRITICAL_SECTION,
},
    um::winbase::{
        COPYFILE2_EXTENDED_PARAMETERS, LPPROGRESS_ROUTINE,LPOFSTRUCT,
    },
    um::winnt::{
        DELETE, FILE_GENERIC_WRITE, GENERIC_WRITE, HANDLE, HRESULT, LPCSTR, LPCWSTR, LPSTR, LPWSTR, PCWSTR, WRITE_DAC,
        WRITE_OWNER,PCSTR, WCHAR, PCHAR, PWCHAR,
    },
    // um::synchapi::{InitializeCriticalSection},
};
use winapi::{
    // um::fileapi::{
    //     CREATEFILE2_EXTENDED_PARAMETERS, LPBY_HANDLE_FILE_INFORMATION,
    // },
    // um::fileapi::{CREATE_ALWAYS, CREATE_NEW, OPEN_ALWAYS, OPEN_EXISTING, TRUNCATE_EXISTING},
    um::handleapi::INVALID_HANDLE_VALUE,
    um::libloaderapi::{GetModuleFileNameW, GetProcAddress},
    // shared::guiddef::GUID,
};
use winapi::um::processthreadsapi::{LPSTARTUPINFOA, LPPROCESS_INFORMATION, LPSTARTUPINFOW};
use winapi::um::processthreadsapi::{GetCurrentProcessId, CreateProcessA, CreateProcessW, GetCurrentThread};
use winapi::um::fileapi::{CreateFileA, CreateFileW};
use winapi::um::fileapi::{DeleteFileA, DeleteFileW};
use winapi::um::fileapi::{FindFirstFileA, FindFirstFileW};
use winapi::um::fileapi::{FindFirstFileExA, FindFirstFileExW};
use winapi::um::fileapi::{GetFileAttributesA, GetFileAttributesW};
use winapi::um::fileapi::{GetFileAttributesExA, GetFileAttributesExW};
use winapi::um::fileapi::{SetFileAttributesA, SetFileAttributesW,
//TODO:                          SetFileInformationByHandle
};
use winapi::um::winbase::{
    CopyFile2, CopyFileA, CopyFileExA, CopyFileExW, CopyFileTransactedA, CopyFileTransactedW,
    CopyFileW, MoveFileA, MoveFileExA, MoveFileExW, MoveFileW, ReplaceFileA, ReplaceFileW, OpenFile};
// {9640B7B0-CA4D-4D61-9A27-79C709A31EB0}
pub static S_TRAP_GUID: detours::_GUID = detours::_GUID { Data1:0x9640b7b0, Data2: 0xca4d, Data3: 0x4d61, Data4 : [0x9a, 0x27, 0x79, 0xc7, 0x9, 0xa3, 0x1e, 0xb0]};

pub fn attach()
{

}
// folllowing #defines from winbase.h are missing in winbase.rs
// const OF_READ:u32 = 0x00000000;
const OF_WRITE:u32 = 0x00000001;
const OF_READWRITE:u32 = 0x00000002;
// const OF_SHARE_COMPAT:u32 = 0x00000000;
const OF_SHARE_EXCLUSIVE:u32 = 0x00000010;
const OF_SHARE_DENY_WRITE:u32 = 0x00000020;
// const OF_SHARE_DENY_READ:u32 = 0x00000030;
// const OF_SHARE_DENY_NONE:u32 = 0x00000040;
// const OF_PARSE:u32 = 0x00000100;
const OF_DELETE:u32 = 0x00000200;
// const OF_VERIFY:u32 = 0x00000400;
const OF_CREATE:u32 = 0x00001000;
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
//
fn record_event(lpFileName: LPCSTR, evt: FileEventType) -> std::result::Result<usize, Error> {
    let pid = unsafe { GetCurrentProcessId() };
    use std::fs::File;
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut file: File = OpenOptions::new()
        .append(true)
        .open(format!("evts-{}.txt", pid))?;
    // let name = std::str::from_utf8(lpFileName).unwrap();
    let fname = unsafe { CStr::from_ptr(lpFileName).to_str().unwrap() };
    file.write(fname.as_bytes())?;
    file.write(b"\n")?;
    file.write(evt.to_string().as_bytes())
}
// wide string version of the above
fn record_event_wide(lpFileName: LPCWSTR, evt: FileEventType) -> std::result::Result<usize, Error> {
    let pid = unsafe { GetCurrentProcessId() };
    use std::fs::File;
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut file: File = OpenOptions::new()
        .append(true)
        .open(format!("evts-{}.txt", pid))?;
    let p = { lpFileName as *const u16 };
    let mut len = 0;
    unsafe {
        while *p.offset(len) != 0 {
            len += 1;
        }
    }
    let name = unsafe { std::slice::from_raw_parts(p as *const u16, len as usize) };
    let u16str: OsString = OsStringExt::from_wide(name);
    file.write(u16str.to_str().unwrap().as_bytes())?;
    file.write(b"\n")?;
    file.write(evt.to_string().as_bytes())
}


unsafe extern "system" fn TrapDeleteFileA(lpFileName: LPCSTR) -> BOOL {
    let ret = DeleteFileA(lpFileName);
    if ret != FALSE {
        let _ = record_event(lpFileName, FileEventType::Unlink);
    }
    ret
}

unsafe extern "system" fn TrapDeleteFileW(lpFileName: LPCWSTR) -> BOOL {
    let ret = DeleteFileW(lpFileName);
    if ret != FALSE {
        let _ = record_event_wide(lpFileName, FileEventType::Unlink);
    }
    ret
}
unsafe extern "system" fn TrapFindFirstFileA(
    lpFileName: LPCSTR,
    lpFindFileData: LPWIN32_FIND_DATAA,
) -> HANDLE {
    let ret = FindFirstFileA(lpFileName, lpFindFileData);
    if ret != INVALID_HANDLE_VALUE {
        let _ = record_event(lpFileName, FileEventType::Read);
    }
    ret
}
unsafe extern "system" fn TrapFindFirstFileW(
    lpFileName: LPCWSTR,
    lpFindFileData: LPWIN32_FIND_DATAW,
) -> HANDLE {
    let ret = FindFirstFileW(lpFileName, lpFindFileData);
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
    let ret = FindFirstFileExA(
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
    let ret = FindFirstFileExW(
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
    let ret = GetFileAttributesA(lpFileName);
    let _ = record_event(lpFileName, FileEventType::Read);
    ret
}
unsafe extern "system" fn TrapGetFileAttributesW(lpFileName: LPCWSTR) -> DWORD {
    let ret = GetFileAttributesW(lpFileName);
    let _ = record_event_wide(lpFileName, FileEventType::Read);
    ret
}
unsafe extern "system" fn TrapGetFileAttributesExA(
    lpFileName: LPCSTR,
    fInfoLevelId: GET_FILEEX_INFO_LEVELS,
    lpFileInformation: LPVOID,
) -> BOOL {
    let ret = GetFileAttributesExA(lpFileName, fInfoLevelId, lpFileInformation);
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
    let ret = GetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation);
    if ret != FALSE {
        let _ = record_event_wide(lpFileName, FileEventType::Write);
    }
    ret
}
unsafe extern "system" fn TrapSetFileAttributesA(
    lpFileName: LPCSTR,
    dwFileAttributes: DWORD,
) -> BOOL {
    let ret = SetFileAttributesA(lpFileName, dwFileAttributes);
    if ret != FALSE  {
        let _ = record_event(lpFileName, FileEventType::Write);
    }
    ret
}

unsafe extern "system" fn TrapSetFileAttributesW(
    lpFileName: LPCWSTR,
    dwFileAttributes: DWORD,
) -> BOOL {
    let ret = SetFileAttributesW(lpFileName, dwFileAttributes);
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
    let handle = CreateFileA(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile,
    );

    if handle != INVALID_HANDLE_VALUE {
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
    let handle = CreateFileW(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile,
    );

    if handle != INVALID_HANDLE_VALUE {
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
    let res = CopyFile2(
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
    let res = CopyFileA(lpExistingFileName, lpNewFileName, bFailIfExists);
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
    let ret = CopyFileExA(
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
    let ret = CopyFileExW(
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
    let ret = CopyFileTransactedA(
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
    let ret = CopyFileTransactedW(
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
    let ret = CopyFileW(lpExistingFileName, lpNewFileName, bFailIfExists);
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
    ReplaceFileA(
        lpReplacedFileName,
        lpReplacementFileName,
        lpBackupFileName,
        dwReplaceFlags,
        lpExclude as _,
        lpReserved as _,
    );
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
    ReplaceFileW(
        lpReplacedFileName,
        lpReplacementFileName,
        lpBackupFileName,
        dwReplaceFlags,
        lpExclude as _,
        lpReserved as _,
    );
    {
        let _ = record_event_wide(lpReplacedFileName, FileEventType::Unlink);
        let _ = record_event_wide(lpReplacementFileName, FileEventType::Write);
    }
}

pub unsafe extern "system" fn TrapMoveFileA(lpExistingFileName: LPCSTR, lpNewFileName: LPCSTR) {
    let ret = MoveFileA(lpExistingFileName, lpNewFileName);
    if ret != FALSE {
        let _ = record_event(lpExistingFileName, FileEventType::Unlink);
        let _ = record_event(lpNewFileName, FileEventType::Write);
    }
}
pub unsafe extern "system" fn TrapMoveFileW(lpExistingFileName: LPCWSTR, lpNewFileName: LPCWSTR) {
    let ret = MoveFileW(lpExistingFileName, lpNewFileName);
    if ret != FALSE {
        let _ = record_event_wide(lpExistingFileName, FileEventType::Unlink);
        let _ = record_event_wide(lpNewFileName, FileEventType::Write);
    }
}
pub unsafe extern "system" fn TrapMoveFileExA(
    lpExistingFileName: LPCSTR,
    lpNewFileName: LPCSTR,
    dwFlags: DWORD,
) {
    let ret = MoveFileExA(lpExistingFileName, lpNewFileName, dwFlags);
    if ret != FALSE {
        let _ = record_event(lpExistingFileName, FileEventType::Unlink);
        let _ = record_event(lpNewFileName, FileEventType::Write);
    }
}
pub unsafe extern "system" fn TrapMoveFileExW(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
    dwFlags: DWORD,
) {
    let ret = MoveFileExW(lpExistingFileName, lpNewFileName, dwFlags);
    if ret != FALSE {
        let _ = record_event_wide(lpExistingFileName, FileEventType::Unlink);
        let _ = record_event_wide(lpNewFileName, FileEventType::Write);
    }
}

pub unsafe extern "system" fn TrapOpenFile(
    lpFileName :LPCSTR,
    lpReOpenBuff : LPOFSTRUCT,
    uStyle : UINT)
{
    if uStyle & OF_DELETE != 0 {
        let _ =  record_event(lpFileName, FileEventType::Unlink);
    }else if uStyle & (OF_READWRITE | OF_WRITE | OF_SHARE_DENY_WRITE | OF_SHARE_EXCLUSIVE | OF_CREATE) != 0 {
        let _ = record_event(lpFileName, FileEventType::Write);
    }else {
        let _ = record_event(lpFileName, FileEventType::Read);
    }
    OpenFile(lpFileName, lpReOpenBuff, uStyle);
}

pub type EntryPointType = unsafe extern "system" fn ();
// unsafe extern "system" fn empty_entry_point() {}
type BigPath = [WCHAR;1024];

const sizeofBigPath : u32= 1024;
#[derive(Clone)]
pub struct Payload {
    depFile :BigPath,
    varDictFile :BigPath,
}
pub struct TrapInfo
{
    hInst: HMODULE,
    // hKernel32: HMODULE,
    zDllPath: BigPath,
    payLoad : Payload,
    // zExecDir : BigPath,
    realentrypoint: *mut EntryPointType,
}
pub struct Comm
{
    csPipe : CRITICAL_SECTION, // Guards access to hPipe.
    hPipe : HANDLE,
    csChildPayLoad: CRITICAL_SECTION,
    // nPipeCnt: u32
}
pub const TBLOG_PIPE_NAME: &'static str =   "\\\\.\\pipe\\tracebuild\0";


impl Payload
{
    pub fn new() -> Payload {
        Payload
        {
            depFile : [0;sizeofBigPath as _],
            varDictFile : [0;sizeofBigPath as _]
        }
    }
    pub fn findPayLoad() -> Payload {
        const hModNull:detours::HMODULE = std::ptr::null_mut() as _;
        let finder = || -> * const Payload {
            let mut hMod:detours::HMODULE = std::ptr::null_mut() as _;
            while {hMod = unsafe{detours::DetourEnumerateModules(hMod as _)}; hMod} !=  hModNull
            {
                let mut cbData:detours::ULONG = 0;
                let pvData : * const Payload = unsafe {detours::DetourFindPayload(hMod, &S_TRAP_GUID as _, &mut cbData as _) as _};
                if pvData != std::ptr::null()
                {
                    return pvData;
                }
            }
            std::ptr::null() as _
        };
        let pPayload = finder();
        if pPayload != std::ptr::null() {
            unsafe{
                (*pPayload).clone()
            }
        }else {
            unreachable!("Error: missing payload during dll injection");
            // Payload::new()
        }
    }
}
static mut s_hMsvcr : detours::HINSTANCE= std::ptr::null_mut();
static mut s_pszMsvcr : * const u8 = std::ptr::null_mut();
static s_rpszMsvcrNames: [&'static str; 14] = [
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
    "msvcr120d.dll"
];

pub unsafe extern "C" fn ImportFileCallback(_ :detours::PVOID, hFile :detours::HINSTANCE, pszFile :PCSTR) -> BOOL
{
    use std::ffi::CString ;
    if pszFile != std::ptr::null()  {
        let cpszFile  = CStr::from_ptr(pszFile);
        if let Some(s) = s_rpszMsvcrNames.iter().map(|s:&&str| CString::new(*s).expect("Cstring conversion failed"))
            .find(|cstr|  { cstr.as_c_str() == cpszFile} )
        {
            s_hMsvcr = hFile;
            s_pszMsvcr = (s.as_ptr() ) as _;
            return FALSE;
        }
    }
    return TRUE;
}

pub unsafe extern "system" fn FindMsvcr() -> bool
{
    detours::DetourEnumerateImportsEx(std::ptr::null_mut(), std::ptr::null_mut(), Some( ImportFileCallback), None);
    !s_hMsvcr.is_null()
}

impl TrapInfo
{
    pub fn new(hModule: HMODULE) -> Self
    {
        let ep : *mut EntryPointType = unsafe {detours::DetourGetEntryPoint(std::ptr::null_mut() as _) as _};
        let mut dllPath : BigPath = [0;sizeofBigPath as _];
        unsafe {GetModuleFileNameW(hModule, (&mut dllPath).as_mut_ptr(),   sizeofBigPath );}
        TrapInfo{hInst: std::ptr::null_mut(), zDllPath: dllPath, payLoad : Payload::findPayLoad(), realentrypoint: ep}
    }

    pub unsafe fn attach(&self) 
    {
        detours::DetourUpdateThread(GetCurrentThread() as _);
        use detours::DetourAttach;
        let ptrap = &TrapEntryPoint as *const _;
        DetourAttach(self.realentrypoint as _, ptrap as _ );
        DetourAttach(&CopyFileExA as *const _  as _, (&TrapCopyFileExA as *const _) as _ );

    }

    pub unsafe fn detach(&self)
    {

    }
}
type Real_wgetenvType =  unsafe extern "C" fn(var: PCWSTR) ->PCWSTR;
type Real_getenvType =  unsafe extern "C" fn(var :PCSTR) ->PCSTR;
type Real_getenv_sType =  unsafe extern "C" fn(pValue :*mut DWORD, pBuffer :PCHAR, cBuffer :DWORD, varname :PCSTR) ->DWORD;
type Real_wgetenv_sType =  unsafe extern "C" fn(pValue :*mut DWORD, pBuffer :PWCHAR, cBuffer: DWORD, varname :PCWSTR) ->DWORD;
type Real_dupenv_sType =  unsafe extern "C" fn(ppBuffer :*mut PCHAR, pcBuffer :*mut DWORD, varname :PCSTR) ->DWORD;
type Real_wdupenv_sType =  unsafe extern "C" fn(ppBuffer :*mut PWCHAR, pcBuffer :*mut DWORD, varname: PCWSTR) ->DWORD;
static mut real_getenv: *mut Real_getenvType = std::ptr::null_mut() as _;
static mut real_wgetenv:*mut Real_wgetenvType = std::ptr::null_mut() as _;
static mut real_getenv_s : *mut Real_getenv_sType = std::ptr::null_mut() as _;
static mut real_wgetenv_s: *mut Real_wgetenv_sType = std::ptr::null_mut() as _;
static mut real_dupenv_s: *mut Real_dupenv_sType = std::ptr::null_mut() as _;
static mut real_wdupenv_s: *mut Real_wdupenv_sType = std::ptr::null_mut() as _;

pub unsafe extern "C" fn Mine_wgetenv(var : PCWSTR) -> PCWSTR
{
    (*real_wgetenv)(var)
}
pub unsafe extern "C" fn Mine_getenv(var: PCSTR)-> PCSTR
{
    (*real_getenv)(var)
}

pub unsafe extern "C" fn Mine_getenv_s(pValue : *mut DWORD, pBuffer: PCHAR, cBuffer : DWORD, varname : PCSTR)-> DWORD
{
    (*real_getenv_s)(pValue, pBuffer, cBuffer, varname)
}
pub unsafe extern "C" fn Mine_wgetenv_s(pValue : *mut DWORD, pBuffer: PWCHAR, cBuffer : DWORD, varname : PCWSTR)-> DWORD
{
    (*real_wgetenv_s)(pValue, pBuffer, cBuffer, varname)
}
unsafe extern "C" fn Mine_dupenv_s(ppBuffer :*mut PCHAR, pcBuffer :*mut DWORD, varname :PCSTR) ->DWORD
{
    (*real_dupenv_s)(ppBuffer, pcBuffer, varname)
}
unsafe extern "C" fn Mine_wdupeenv_s(ppBuffer :*mut PWCHAR, pcBuffer :*mut DWORD, varname: PCWSTR) ->DWORD
{
    (*real_wdupenv_s)(ppBuffer, pcBuffer, varname)
}
 unsafe extern "system" fn TrapEntryPoint ()
{
    if FindMsvcr()  {
        real_getenv = GetProcAddress(s_hMsvcr as _, "getenv\0".as_ptr() as _) as _;
        real_wgetenv = GetProcAddress(s_hMsvcr as _, "_wgetenv\0".as_ptr() as _ ) as _;
        real_getenv_s = GetProcAddress(s_hMsvcr as _, "getenv_s\0".as_ptr() as _) as _;
        real_wgetenv_s = GetProcAddress(s_hMsvcr as _, "_wgetenv_s\0".as_ptr() as _) as _;
        real_dupenv_s = GetProcAddress(s_hMsvcr as _, "_dupenv_s\0".as_ptr() as _) as _;
        real_wdupenv_s = GetProcAddress(s_hMsvcr as _, "_wdupenv_s\0".as_ptr() as _) as _;

        detours::DetourTransactionBegin();
        detours::DetourUpdateThread(GetCurrentThread() as _);

        detours::DetourAttach(real_getenv as _, ((&Mine_getenv) as *const _) as _);
        detours::DetourAttach(real_getenv_s as _, (&Mine_getenv_s as *const _) as _);
        detours::DetourAttach(real_wgetenv as _, (&Mine_wgetenv as *const _) as _);
        detours::DetourAttach(real_wgetenv as _, (&Mine_wgetenv_s as *const _) as _);
        detours::DetourAttach(real_dupenv_s as _, (&Mine_dupenv_s as *const _) as _);
        detours::DetourAttach(real_wdupenv_s as _, (&Mine_wdupeenv_s as *const _) as _);
        detours::DetourTransactionCommit();
    }
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
) -> BOOL{
    CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
                   bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
                   lpStartupInfo, lpProcessInformation)
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
) -> BOOL{
    CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
                   lpThreadAttributes, bInheritHandles, dwCreationFlags,
                   lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)
}
