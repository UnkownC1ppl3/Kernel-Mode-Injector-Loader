#include "driver.h"
#include "hook.h"
#include "cleaner.h"
VOID MyThread()
{

   
    PsTerminateSystemThread(STATUS_SUCCESS);




}

NTSTATUS RealEntry(PDRIVER_OBJECT  DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    clean_piddbcachetalbe();
    BOOL status =pysenhook::CallKernelFunction(&pysenhook::HookHandler);

    

    return STATUS_SUCCESS;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject, PUNICODE_STRING RegistryPath
)


{
 

    return STATUS_SUCCESS;

}