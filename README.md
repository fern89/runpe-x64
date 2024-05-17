# runpe-x64
RunPE adapted for x64 and written in C, does not use RWX. Based on the original RunPE at https://github.com/Zer0Mem0ry/RunPE. Mostly because too many RunPE implementations use RWX, is terrible for evasion.

## Changes made
- Written purely in C, no C++
- Adapted for x64
- No RWX regions

## Compilation
Compiled with mingw gcc. Use `x86_64-w64-mingw32-gcc runpe.c -o runpe.exe` and `x86_64-w64-mingw32-gcc stub.c -o stub.exe -mwindows` for RunPE and stub respectively
