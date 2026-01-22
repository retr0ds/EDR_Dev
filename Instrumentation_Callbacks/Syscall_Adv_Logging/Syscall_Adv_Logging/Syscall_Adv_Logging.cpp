#include <windows.h>
#include <iostream>
#include <io.h>
#include <array>
#include <Dbghelp.h>
#include <cstddef> 
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "dbghelp.lib")
extern "C" NTSTATUS NTAPI NtWaitForSingleObject(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);
extern "C" UINT32 syscall_count = 0;
extern "C" {

    void instrumentation_adapter();

    extern "C" bool  Global_InsideCallback = false;



    extern "C" uint64_t instrumentation_callback(uint64_t original_rsp, uint64_t return_addr, uint64_t return_val) {
        char buf[512];
        int len = 0;
        std::array<byte, sizeof(SYMBOL_INFO) + MAX_SYM_NAME> buffer{ 0 };
        const auto symbol_info = reinterpret_cast<SYMBOL_INFO*>(buffer.data());
        symbol_info->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol_info->MaxNameLen = MAX_SYM_NAME;
        uint64_t displacement = 0;
        //_write(1,"Entered instrumentation callback!\n",34);
        if (!SymFromAddr(reinterpret_cast<HANDLE>(-1), return_addr, &displacement, symbol_info)) {
            printf("[-] SymFromAddr failed: %lu", GetLastError());
            return return_val;
        }
        if (symbol_info->Name)
            _write(1, symbol_info->Name, strlen(symbol_info->Name));
        return return_val;
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
    info.Callback = (PVOID)instrumentation_adapter;

    SymSetOptions(SYMOPT_UNDNAME);
    if (!SymInitialize(reinterpret_cast<HANDLE>(-1), nullptr, TRUE)) {
        std::printf("SymInitialize failed");
        return -1;
    }

    NTSTATUS status = NtSetInformationProcess(
        GetCurrentProcess(),
        40,
        &info,
        sizeof(info)
    );

    if (status == 0) {
        std::cout << "Successfully hooked! Watch the console...\n" << std::endl;


        Sleep(100);
        //NtCurrentTeb();
		NtWaitForSingleObject(0, FALSE, 0);
        //printf("First");
        GetTickCount();
        //printf("here");
        //Sleep(10000);
    }
    else {
        std::cout << "Failed to register callback. Status: " << std::hex << status << std::endl;
    }

    printf("Total syscalls intercepted: %u\n", syscall_count);
    return 0;
}