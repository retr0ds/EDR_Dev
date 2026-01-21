EXTERN LogSyscall:PROC 

.code
InstrumentationCallbackRoutine PROC
    ; R10 contains the original return RIP
    ; R11 contains the original RFLAGS
    
    ; 1. Save state
    push r10
    push r11
    sub rsp, 40      

    ; 2. Call the C function
    call LogSyscall

    ; 3. Restore and jump back
    add rsp, 40
    pop r11
    pop r10
    jmp r10          ; Return to original execution flow
InstrumentationCallbackRoutine ENDP
END