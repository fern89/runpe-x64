# runpe-x64
RunPE adapted for x64 and written in C, does not use RWX. Based on the original RunPE at https://github.com/Zer0Mem0ry/RunPE. Mostly because too many RunPE implementations use RWX, is terrible for evasion.

## Changes made
- Written purely in C, no C++
- Adapted for x64
- No RWX regions
