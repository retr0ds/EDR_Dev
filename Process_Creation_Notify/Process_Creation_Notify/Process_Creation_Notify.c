#include <ntddk.h>



void process_create_notify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);
    if (CreateInfo) {
        if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer) {
            DbgPrint("[*][*][*] Process created: PID=%lu | Image : %wZ\n", ProcessId, CreateInfo->ImageFileName);
        }
        else {
            DbgPrint("[*][*][*] Process created: PID=%lu with unkown Image Name.\n", ProcessId);
        }
        if (CreateInfo->CommandLine && CreateInfo->CommandLine->Buffer) {
            DbgPrint("[*][*][*] Process Command Line : %wZ\n", CreateInfo->CommandLine);
        }

    }
    else {
        DbgPrint("[*][*][*] Process exited: PID=%lu\n", ProcessId);
    }
}

void unload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    PsSetCreateProcessNotifyRoutineEx(process_create_notify, TRUE);
    DbgPrint("RDS unloaded\n");
}
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = unload;
    DbgPrint("RDS loaded\n");
    NTSTATUS status;
    status = PsSetCreateProcessNotifyRoutineEx(process_create_notify, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to register process creation notify routine: 0x%X\n", status);
        return status;
    }
    return STATUS_SUCCESS;
}
