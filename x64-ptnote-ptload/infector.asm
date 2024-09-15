;; -*- mode: nasm -*-

global _start

SYS_EXIT       equ 60
SYS_GETDENTS64 equ 217
SYS_OPEN       equ 2

LINUX_DIRENT_OFF_DNAME equ 18
LINUX_DIRENT_OFF_DOFF  equ 8

O_RDONLY equ 0

ST_DIRENT_SIZE_OFF 1024

SECTION .data

	;; empty

SECTION .text

exit:
    mov rax, SYS_EXIT 
	mov rdi, 0
	syscall
    ret

_start:
    push rdx
    push rsp
    sub  rsp, 5000
    mov  r15, rsp

load_dir:
    push "."
    mov rax, SYS_OPEN
    mov rdi, rsp
    mov rsi, O_RDONLY
    xor rdx, rdx
    syscall

    pop rdi
    cmp rax, 0
    jbe exit
    
    mov rdi, rax
    mov rsi, [r15]
    mov rdx, 1024
    mov rax, SYS_GETDENTS64
    syscall

    test rax, rax
    js   exit

    mov qword [r15 + ST_DIRENT_SIZE_OFF], rax

    xor ecx, ecx

loop_dir_entries:
    cmp ecx, [r15 + ecx]
    jl  end

    mov rax, SYS_OPEN
    mov rdi, [r15 + ecx + LINUX_DIRENT_D_NAME_OFF]
    mov rsi, O_RDONLY
    xor rdx, rdx
    syscall

    ;; TODO(gora): check SYS_OPEN exit status
    
    add ecx, qword [r15 + ecx + LINUX_DIRENT_OFF_DOFF]

end:
    jmp exit
    
    pop rsp
    pop rdx
    ret
