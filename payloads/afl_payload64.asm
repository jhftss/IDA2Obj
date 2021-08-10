_data$payload segment para alias('.data') 'DATA'

public __afl_prev_locs
public __afl_area_ptr

__afl_prev_locs  dd 1000h dup(0)				; clear to zero by PRE() function in each fuzz iteration loop
__afl_area_ptr   dq 0							; __afl_area_ptr is a switch set by InitTarget() function inside the harness.

_data$payload ends


_text$payload segment para alias('.text') 'CODE'


__afl_maybe_log proc
                push    rax
                push    rbx
                push    rcx
                push    rdx
                pushfq
                mov     rdx, __afl_area_ptr
                test    rdx, rdx
                jz      skip

                mov     rcx, [rsp+30h]          ; Get the prev loc
                lea     rbx, __afl_prev_locs
                mov     eax, dword ptr gs:[48h] ; Get the tid from TEB
                and     rax, 0FFFh              ; Mask tid
                lea     rax, [rbx + rax*4]
                xor     ecx, dword ptr [rax]
                xor     dword ptr [rax], ecx
                shr     dword ptr [rax], 1
                lock    inc byte ptr [rdx+rcx]
skip:
                popfq
                pop     rdx
                pop     rcx
                pop     rbx
                pop     rax
                ret
__afl_maybe_log endp
align (10h)


_text$payload ends



end