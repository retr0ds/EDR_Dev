
EXTERN LogSyscall:PROC
EXTERN Global_InsideCallback:BYTE ; External reference to our C++ bool
EXTERN syscall_count:DWORD
.code
InstrumentationCallbackRoutine PROC
    ; R10 = Original Return RIP
    ; R11 = Original RFLAGS
    ; RAX = Syscall Return Status (NTSTATUS)

    ; 1. Quick Guard Check (Check if we are already in a callback)
    ; GS:[0x30] is the TEB. We use a simple C++ thread_local instead for compatibility.
    inc syscall_count
    cmp Global_InsideCallback, 1
    je skip_callback

    ; 2. Set Guard
    mov Global_InsideCallback, 1


    push r10
    push r11
    push rax            ; Save the return status
    sub rsp, 32         ; Shadow space for x64 calling convention


    mov eax, gs:[2D8h]  ; TypicalSyscallNumber offset for Win10/11
    

    mov rcx, rax        ; 1st arg: Syscall Number (RCX)
    mov rdx, [rsp+32]   ; 2nd arg: Saved Status (RDX)
    
    call LogSyscall

    ; 6. Cleanup and Reset Guard
    add rsp, 32
    pop rax
    pop r11
    pop r10
    mov Global_InsideCallback, 0

skip_callback:
    jmp r10             
InstrumentationCallbackRoutine ENDP
END