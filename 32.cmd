@setlocal
pushd %~pd0
set LIBCLANG_PATH=d:\apps\llvm32\bin
call rustup default nightly-i686-pc-windows-msvc
call cargo build --verbose --target=i686-pc-windows-msvc 
call copy ..\target\i686-pc-windows-msvc\debug\tupinject.dll ..\target\debug\tupinject32.dll
popd