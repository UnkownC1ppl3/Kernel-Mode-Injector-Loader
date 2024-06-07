#include "memory.h"
PVOID GetSystemModuleBase(const char* module_name)
{
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation,NULL,bytes,&bytes);
	if (!bytes)
		return NULL;
	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool,bytes,0x4e554c4c);//"NULL"
	status = ZwQuerySystemInformation(SystemModuleInformation,modules,bytes,&bytes);
	if (!NT_SUCCESS(status))
		return NULL;
	PRTL_PROCESS_MODULE_INFORMATION Module = modules->Modules;
	PVOID module_base = 0, module_size = 0;
	for (ULONG i = 0;i < modules->NumberOfModules;i++)
	{
		
		
		if (strcmp(Module[i].FullPathName, module_name)==0)
		{
			module_base = Module[i].ImageBase;
			module_size = (PVOID)Module[i].ImageBase;
			break;
		}
	}
	if (modules)
		ExFreePoolWithTag(modules, NULL);
	if (module_base <= NULL)
		return NULL;
	return module_base;

	

}

PVOID GetSystemModuleExport(const char* module_name, LPCSTR routing_name)
{
	PVOID lpModule = GetSystemModuleBase(module_name);

	if (!lpModule)
		return NULL;
	return RtlFindExportedRoutineByName(lpModule, routing_name);
	
	
}

BOOL WriteMemory(void* address, void* buffer, size_t size)
{
	if (!RtlCopyMemory(address, buffer, size))
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

BOOL WriteReadOnlyMemory(void* address, void* buffer, size_t size)
{
	PMDL Mdl =IoAllocateMdl(address,size,FALSE,FALSE,NULL);
	if (!Mdl)
		return false;
	MmProbeAndLockPages(Mdl,KernelMode,IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl,KernelMode,MmNonCached,NULL,FALSE,NormalPagePriority);
	MmProtectMdlSystemAddress(Mdl,PAGE_READWRITE);
	WriteMemory(Mapping,buffer,size);
	MmUnmapLockedPages(Mapping,Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);
	return TRUE;

}


BOOL myWriteProcessMemory(HANDLE pid,PVOID address, PVOID buffer, DWORD size)
{
	DbgPrint("myWriteProcessMemory");

	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);
	if (process == NULL)
	{
		DbgPrint("Process获取失败");
		return FALSE;
	} 
	SIZE_T real_size;

	status = MmCopyVirtualMemory(PsGetCurrentProcess(), buffer, process, address, size, KernelMode, &real_size);

	




	ObDereferenceObject(process);
	return TRUE;


}
BOOL myWriteProcessMemory64(HANDLE pid, PVOID64 address, PVOID64 buffer, DWORD size)
{
	

	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);
	if (process == NULL)
	{
		
		return FALSE;
	}
	
	SIZE_T real_size;
	status = MmCopyVirtualMemory(PsGetCurrentProcess(), buffer, process, address, size, KernelMode, &real_size);
	

	ObDereferenceObject(process);
	return TRUE;


}
BOOL myReadProcessMemory(HANDLE pid,PVOID address, PVOID buffer, DWORD size)
{


	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);
	if (process == NULL)
	{
	

		return FALSE;
	}
	SIZE_T real_size;


	status = MmCopyVirtualMemory(process, address, PsGetCurrentProcess(), buffer, size, KernelMode, &real_size);
	

	
	
	
	ObDereferenceObject(process);
	return TRUE;

}
BOOL myReadProcessMemory64(HANDLE pid, PVOID64 address, PVOID64 buffer, DWORD size)
{
	

	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);
	if (process == NULL)
	{
	

		return FALSE;
	}
	SIZE_T real_size;
	status = MmCopyVirtualMemory(process, address, PsGetCurrentProcess(), buffer, size, KernelMode, &real_size);
	


	ObDereferenceObject(process);
	return TRUE;

}
PVOID AllocateVirtualMemory(HANDLE pid,ULONGLONG size, DWORD protect)
{
	
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);
	if (process == NULL)
	{
		

		return NULL;
	}
	PVOID base_address = NULL;
	KAPC_STATE apc;
	
	size_t real_size = size;
	KeStackAttachProcess(process,&apc);
	status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &base_address,0,&real_size,MEM_COMMIT,protect);
	
	KeUnstackDetachProcess(&apc);
	ObDereferenceObject(process);
	return base_address;

}

VOID FreeVirtualMemory(HANDLE pid, PVOID base)
{
	
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);
	if (process == NULL)
	{
	

		return;
	}
	PVOID base_address = base;
	KAPC_STATE apc;

	KeStackAttachProcess(process, &apc);
	SIZE_T region_size = 0;
	status = ZwFreeVirtualMemory(ZwCurrentProcess(),&base_address,&region_size,MEM_RELEASE);
	DbgPrint("FreeVirtualMemory Status:%x", status);
	KeUnstackDetachProcess(&apc);
	ObDereferenceObject(process);
	return;

}

BOOL ProtectVirtualMemory(HANDLE pid, UINT_PTR base, ULONGLONG size, DWORD protection)
{
	DbgPrint("ProtectVirtualMemory");
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);
	if (process == NULL)
	{
		DbgPrint("Process获取失败");
		return FALSE;
	}
	KAPC_STATE apc;
	PVOID base_address = (PVOID)base;
	SIZE_T protect_size = size;
	ULONG old_protect;
	KeStackAttachProcess(process, &apc);
	status= ZwProtectVirtualMemory(ZwCurrentProcess(),&base_address,&protect_size,protection,&old_protect);
	DbgPrint("ProtectVirtualMemory Status:%x", status);
	KeUnstackDetachProcess(&apc);
	ObDereferenceObject(process);
	
	return TRUE;
}
PVOID GetProcessHandle(HANDLE pid)
{
	DbgPrint("GetProcessHandle");
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);
	if (process == NULL)
	{
		DbgPrint("Process获取失败");
		return NULL;
	}
	UNICODE_STRING Unicode;

	PVOID hProcess = NULL;
	status = ObOpenObjectByPointer(
		process,
		0,
		NULL,
		PROCESS_ALL_ACCESS,
		*PsProcessType,
		KernelMode,
		&hProcess
	);
	DbgPrint("GetProcessHandle Status:%x", status);
	ObDereferenceObject(process);
	return hProcess;


}