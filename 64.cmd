@setlocal
pushd %~pd0
rustup default nightly-x86_64-pc-windows-msvc
cargo build --verbose
copy ..\target\debug\tupinject.dll ..\target\debug\tupinject64.dll
popd

