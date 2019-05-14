#include <Windows.h>
#include <stdarg.h>
#include <stdio.h>

#include "utils.h"


PROXY_INFO proxy_info = {WINHTTP_ACCESS_TYPE_NAMED_PROXY,PROXY_STRING,WINHTTP_NO_PROXY_BYPASS};

void DBG_printf(const char* format, ...) {
#ifdef ENABLE_DEBUG
    char s[8192];
    va_list args;
    ZeroMemory(s, 8192 * sizeof(s[0]));
    va_start(args, format);
    vsnprintf(s, 8191, format, args);
    va_end(args);
    s[8191] = 0;
    OutputDebugStringA(s);
#endif
}

// Patch an IAT entry to replace any calls to it with a new function by name.
BOOL Hook_IAT_Name (char* dll_name, char* func_name,DWORD replacement_function_ptr){
    IMAGE_DOS_HEADER *pDOSHeader;
    IMAGE_NT_HEADERS *pNTHeader;
    IMAGE_IMPORT_DESCRIPTOR *ImportDirectory;
    DWORD *OriginalFirstThunk;
    DWORD *FirstThunk;
    DWORD *address;
    DWORD *func_address;
    char *module_name="";
    DWORD overwrite;
    char *name;
    HANDLE hHandle;
    DWORD oldProtect;
    DWORD PEHeaderOffset;
    int i=0;

    hHandle = GetModuleHandle(NULL);

    if(hHandle == NULL){
        OutputDebugStr("there was an error in retrieving the handle");
       return FALSE;
    }

    pDOSHeader = (IMAGE_DOS_HEADER *) hHandle;

    PEHeaderOffset = (DWORD) pDOSHeader->e_lfanew;

    pNTHeader = (IMAGE_NT_HEADERS *) ((DWORD) hHandle + PEHeaderOffset);

    ImportDirectory = (IMAGE_IMPORT_DESCRIPTOR *) ((DWORD) pNTHeader->OptionalHeader.DataDirectory[1].VirtualAddress + (DWORD) hHandle);
    module_name = (char *)(ImportDirectory->Name + (DWORD) hHandle);

    while(stricmp(module_name, dll_name) != 0){
        ImportDirectory++;
        module_name = (char *)(ImportDirectory->Name + (DWORD) hHandle);
    }


    OriginalFirstThunk = (DWORD *)((DWORD) ImportDirectory->OriginalFirstThunk + (DWORD) hHandle);
    FirstThunk = (DWORD *)((DWORD) ImportDirectory->FirstThunk + (DWORD) hHandle);


    while(*(OriginalFirstThunk+i) != 0x00000000){
        name = (char *) (*(OriginalFirstThunk+i) + (DWORD) hHandle + 0x2);

        if(stricmp(name, func_name) == 0)
        {
            address=OriginalFirstThunk+i;
            break;
        }
        i++;
    }

    func_address = FirstThunk - OriginalFirstThunk + address;
    VirtualProtect(func_address, 0x4, 0x40, &oldProtect);
    overwrite = (DWORD) replacement_function_ptr;
    WriteProcessMemory(0xffffffff, func_address, &overwrite, 0x4, NULL);
    VirtualProtect(func_address, 0x4, 0x20, &oldProtect);
    return TRUE;
}


void* dyn_bind(const char* lib_name, const char* func_name){
    HMODULE hlib = LoadLibraryA(lib_name);
    if(!hlib){return NULL;}
    void* func_addr = GetProcAddress(hlib,func_name);
    if(!func_addr){return NULL;}
    return func_addr;
}

// Binding Export
EXPORTABLE void swim_with_me(){}
