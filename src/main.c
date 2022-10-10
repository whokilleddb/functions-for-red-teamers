//cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcmain.c /I "headers" /link /OUT:test.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 
#include <windows.h>
#include "rewrite.h"

int main(void){
    char func[] = "AcquireSRWLockExclusive";
    HMODULE _kernel32 = LoadLibrary((LPCWSTR)"kernel32.dll");
    printf("__get_proc_address: %x\n", __get_proc_address(_kernel32, "AcquireSRWLockExclusive"));
    printf("GetProcAddress:  %x\n", GetProcAddress(_kernel32, "AcquireSRWLockExclusive"));
}