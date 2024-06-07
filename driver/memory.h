#pragma once
#include "definitions.h"
PVOID GetSystemModuleBase(const char* module_name);
PVOID GetSystemModuleExport(const char* module_name,LPCSTR routing_name);
BOOL WriteMemory(void* address, void* buffer, size_t size);
BOOL WriteReadOnlyMemory(void* address, void* buffer, size_t size);
BOOL myWriteProcessMemory(HANDLE pid,PVOID address, PVOID buffer,DWORD size);
BOOL myReadProcessMemory(HANDLE pid,PVOID address, PVOID buffer, DWORD size);
PVOID AllocateVirtualMemory(HANDLE pid,ULONGLONG size, DWORD protect);
VOID FreeVirtualMemory(HANDLE pid, PVOID base);
BOOL ProtectVirtualMemory(HANDLE pid, UINT_PTR base, ULONGLONG size,DWORD protection);
PVOID GetProcessHandle(HANDLE pid);
BOOL myWriteProcessMemory64(HANDLE pid, PVOID64 address, PVOID64 buffer, DWORD size);
BOOL myReadProcessMemory64(HANDLE pid, PVOID64 address, PVOID64 buffer, DWORD size);