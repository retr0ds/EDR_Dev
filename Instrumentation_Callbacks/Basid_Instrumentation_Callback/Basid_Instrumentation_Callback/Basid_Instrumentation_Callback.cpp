#include <windows.h>
#include <io.h>
#include <iostream>

extern "C" void InstrumentationCallbackRoutine();

struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
};
extern "C" NTSTATUS NTAPI NtSetInformationProcess(
    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);
#pragma comment(lib, "ntdll.lib")

extern "C" void LogSyscall() {

    _write(1, "Syscall Return Intercepted!\n", 28);
}

int main() {
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info;
    info.Version = 0; // x64 version
    info.Reserved = 0;
    info.Callback = (PVOID)InstrumentationCallbackRoutine;


    NTSTATUS status = NtSetInformationProcess(
        GetCurrentProcess(),
        (PROCESS_INFORMATION_CLASS)40, // ProcessInstrumentationCallback
        &info,
        sizeof(info)
    );

    if (status == 0) {
        std::cout << "Callback registered! Triggering a syscall..." << std::endl;
        Sleep(1); 
    }

    return 0;
}