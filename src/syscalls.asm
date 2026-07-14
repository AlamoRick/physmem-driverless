.code

DoSyscall PROC
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, [rsp+28h]
    syscall
    ret
DoSyscall ENDP

DoSyscallEx PROC
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, [rsp+28h]

    mov rcx, [rsp+30h]
    mov [rsp+28h], rcx
    mov rcx, [rsp+38h]
    mov [rsp+30h], rcx
    mov rcx, [rsp+40h]
    mov [rsp+38h], rcx
    mov rcx, [rsp+48h]
    mov [rsp+40h], rcx
    mov rcx, [rsp+50h]
    mov [rsp+48h], rcx
    mov rcx, [rsp+58h]
    mov [rsp+50h], rcx
    mov rcx, [rsp+60h]
    mov [rsp+58h], rcx

    syscall
    ret
DoSyscallEx ENDP

end
