;; -*- mode: nasm -*-

global _start

SYS_EXIT       equ 60
SYS_GETDENTS64 equ 217
SYS_OPEN       equ 2
SYS_CLOSE      equ 3
SYS_FSTAT      equ 5
SYS_MMAP       equ 9

DIRENT_OFF_DRECLEN equ 8 + 8         ; dirent.d_reclen
DIRENT_OFF_DTYPE   equ 8 + 8 + 2     ; dirent.d_type
DIRENT_OFF_DNAME   equ 8 + 8 + 2 + 1 ; dirent.d_name

STAT_OFF_STSIZE equ 48          ; stat.st_size

O_RDONLY equ 0
O_RDWR   equ 2
DT_REG   equ 8

ST_DIRENT_SIZE_OFF equ 1024     ; size: long
ST_OPEN_FILE_FD    equ 1032     ; size: int
ST_OPEN_FILE_STAT  equ 1040     ; size: 144 bytes
ST_OPEN_FILE_ADDR  equ 1184     ; size: ptr

PROT_READ  equ 1
PROT_WRITE equ 2
MAP_SHARED equ 1

ELFCLASS64 equ 2

SECTION .data

	;; empty

SECTION .text

_start:
    push rdx
    push rsp
    sub  rsp, 5000
    mov  r15, rsp

load_dir:
    ; calls getdents64 to get a list of all the files of the current
    ; directory. does not recurse.
    ;
    ; NOTE(phos): i believe it won't work on directories with a
    ; considerable amount of files (e.g. /bin/) since it's only
    ; allocating 1024 bytes for the array of results.
    push "."
    mov rax, SYS_OPEN
    mov rdi, rsp
    mov rsi, O_RDONLY
    xor rdx, rdx
    syscall

    pop  rdi
    test rax, rax
    js   exit
    
    mov rdi, rax
    lea rsi, [r15]
    mov rdx, 1024
    mov rax, SYS_GETDENTS64
    syscall

    test rax, rax
    js   exit

    mov qword [r15 + ST_DIRENT_SIZE_OFF], rax

    mov rax, SYS_CLOSE
    syscall

    xor rcx, rcx
file_loop:
    ; loop over each dirent structure
    push rcx

    cmp byte [r15 + rcx + DIRENT_OFF_DTYPE], DT_REG
    jne file_loop_continue      ; if the file is not a regular file,
                                ; skip it

open_file:
    ; open() the file pointed by dirent.d_name, then fstat() it in
    ; order to get its size. The size is needed to mmap() the file
    ; into memory.
    mov rax, SYS_OPEN
    lea rdi, byte [r15 + rcx + DIRENT_OFF_DNAME]
    mov rsi, O_RDONLY
    xor rdx, rdx
    syscall

    test rax, rax
    js   file_loop_continue
    mov qword [r15 + ST_OPEN_FILE_FD], rax

    mov rdi, rax
    lea rsi, qword [r15 + ST_OPEN_FILE_STAT]
    mov rax, SYS_FSTAT
    syscall

    test rax, rax
    js file_loop_continue
    
    xor rax, rax
    mov rax, SYS_MMAP
    mov rdi, 0
    mov rsi, 8096
    ; qword [r15 + ST_OPEN_FILE_STAT + STAT_OFF_STSIZE]
    mov rdx, PROT_READ | PROT_WRITE
    mov r10, MAP_SHARED
    mov r8,  qword [r15 + ST_OPEN_FILE_FD]
    mov r9,  0
    syscall

    cmp rax, -1
    je  exit

    cmp rax, -13
    je  exit_fail

    mov qword [r15 + ST_OPEN_FILE_ADDR], rax

is_elf:
    cmp dword [r15 + ST_OPEN_FILE_ADDR], 0x464c457f
    jne close_file

is_x64:
    cmp byte [r15 + ST_OPEN_FILE_ADDR + 4], ELFCLASS64
    jne close_file

    ; TODO(phos): do stuff
    ; TODO(phos): munmap() mapped file
    
close_file:
    mov rax, SYS_CLOSE          ; once the file is mmap()'ed, it can
                                ; be closed without any side effects.
    mov rdi, qword [r15 + ST_OPEN_FILE_FD]
    syscall

file_loop_continue:
    pop rcx
    add cx,  word [r15 + rcx + DIRENT_OFF_DRECLEN]
    cmp rcx, [r15 + ST_DIRENT_SIZE_OFF]
    jne file_loop

end:
    mov  rdi, 0
    call exit
    
    pop rsp
    pop rdx
    ret

_exit:
    mov rax, SYS_EXIT 
	syscall
    ret

exit:
    mov rdi, 0
    call _exit

exit_fail:
    mov  rdi, 1
    call _exit
    
