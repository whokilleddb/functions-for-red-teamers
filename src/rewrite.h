#include <stdio.h>
#include <string.h>
#include <windows.h>
#define VERBOSE 
#pragma once 

extern FARPROC WINAPI __get_proc_address(HMODULE hModule, LPCSTR  lpProcName);