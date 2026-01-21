#include <windows.h>
#include <iostream>
#include <io.h>


#pragma comment(lib, "ntdll.lib")
extern "C" UINT32 syscall_count = 0;
extern "C" {

    void InstrumentationCallbackRoutine();

    // The Guard (Thread-local to handle multiple threads safely)
    extern "C" bool Global_InsideCallback = false;


    void LogSyscall(unsigned int num, LONG status) {
        if (num > 0) {
            char buf[64];
            int len = sprintf_s(buf, "Syscall: 0x%u | Status: 0x%X\n", num, status);
            _write(1, buf, len);
        }
    }
}


struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
};

extern "C" NTSTATUS NTAPI NtSetInformationProcess(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);

int main() {
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info = { 0 };
    info.Version = 0;
    info.Callback = (PVOID)InstrumentationCallbackRoutine;


    NTSTATUS status = NtSetInformationProcess(
        GetCurrentProcess(),
        40,
        &info,
        sizeof(info)
    );

    if (status == 0) {
        std::cout << "Successfully hooked! Watch the console..." << std::endl;

        
        Sleep(100);
        GetTickCount();
        printf("Total syscalls intercepted: %u\n", syscall_count);
    }
    else {
        std::cout << "Failed to register callback. Status: " << std::hex << status << std::endl;
    }


    Sleep(1000);
    return 0;
}