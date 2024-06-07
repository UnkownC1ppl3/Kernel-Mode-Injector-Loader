#pragma once
#include "memory.h"
namespace pysenhook
{
	BOOL CallKernelFunction(void* kernel_function_addr);
	NTSTATUS HookHandler(PVOID called_param);
}
enum INSTRUCTIONS
{
    WRITE_KERNEL_MEMORY,
    WRITE_PROCESS_MEMORY,
    READ_KERNEL_MEMORY,
    READ_PROCESS_MEMORY,
    ALLOCATE_MEMORY,
    FREE_MEMORY,
    PROTECT_MEMORY,
    ATTACH_PROCESS,
    OPEN_PROCESS,
    READ_PROCESS_MEMORY64,
    WRITE_PROCESS_MEMORY64
};
typedef struct _NULL_MEMORY
{
    ULONG instruction;
    void* buffer_address;
    UINT_PTR address;
    ULONGLONG size;
    ULONG pid;
    BOOLEAN read;
    BOOLEAN req_base;
    void* output;
    const char* module_name;
    PVOID allocate_base;//分配得到的地址
    DWORD protect;
    PVOID64 address64;
    PVOID64 buffer_address64;
}NULL_MEMORY, * PNULL_MEMORY;

