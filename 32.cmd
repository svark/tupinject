@setlocal
pushd %~pd0
set LIBCLANG_PATH=%LIBCLANG32_PATH%
if "%LIBCLANG_PATH%"=="" (
echo please provide libclang32_path -32bit version of llvm\bin
popd
exit /b 0
)
call rustup default nightly-i686-pc-windows-msvc
call cargo build --verbose --target=i686-pc-windows-msvc 
call copy ..\target\i686-pc-windows-msvc\debug\tupinject.dll ..\target\debug\tupinject32.dll
popd