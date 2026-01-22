EXTERN instrumentation_callback: PROC

EXTERN  Global_InsideCallback:BYTE ; External reference to our C++ bool
EXTERN syscall_count:DWORD
.code
instrumentation_adapter PROC
    ; R10 = Original Return RIP
    ; R11 = Original RFLAGS
    ; RAX = Syscall Return Status (NTSTATUS)

    ; Quick Guard Check (Check if we are already in a callback)

    inc syscall_count
    cmp Global_InsideCallback, 1
    je skip_callback

    ;Set guard and save state
    mov Global_InsideCallback, 1
    
    ; We must preserve the volatile registers that the original 
    ; syscall return might be using (RAX, RCX, RDX, R8-R11)
    pushfq          ; Save flags
    push rax        ; Save return value
    push rcx        ; Save RCX
    push rdx
    push r8
    push r9
    push r10
    push r11

    ;Setup Stack for C++ 
    sub rsp, 20h    

    ;  Identify the Original RSP
    ; Since we pushed 8 registers (8 * 8 = 64 bytes) + the 2 items 
    ; already on the stack (16 bytes), the Original RSP is now at:
    ; [rsp + 64 + 8]
    mov rcx, [rsp + 72] ; Original RSP (pushed 3rd)
    mov rdx, r10         ; Return address
    mov r8,  rax         ; Return value

    call instrumentation_callback

    ; Restore state
    add rsp, 20h
    popfq
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    pop r10         ; Get original R10 back

    ; Clear guard and return
    mov Global_InsideCallback, 0
    jmp r10

skip_callback:
    jmp r10
instrumentation_adapter ENDP
END