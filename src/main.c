#include <windows.h>
#include "rewrite.h"

int main(void){
    char func[] = "AcquireSRWLockExclusive";
    HMODULE _kernel32 = LoadLibrary((LPCWSTR)"kernel32.dll");

    assert(__get_proc_address(_kernel32, "AcquireSRWLockExclusive"), GetProcAddress(_kernel32, "AcquireSRWLockExclusive"));
    
    return 0;
}