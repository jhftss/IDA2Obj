_data$payload segment para alias('.data') 'DATA'

public __trace_cur_count_ptr
public __trace_max_count_ptr
public __trace_store_ptr

__trace_cur_count_ptr  dq 0
__trace_max_count_ptr  dq 0
__trace_store_ptr      dq 0 ; __afl_area_ptr is a switch set by INIT() function inside the harness.

_data$payload ends


_text$payload segment para alias('.text') 'CODE'


__trace_pc        proc
public __afl_maybe_log
__afl_maybe_log:: ; reuse the symbol from AFLTrampoline
                push    rax
                push    rbx
                push    rcx
                push    rdx
                pushfq
                mov     rdx, __trace_store_ptr
                test    rdx, rdx
                jz      skip

                mov     rbx, __trace_cur_count_ptr
                mov     rax, [rbx]               ; FIXME: use atomic operation instruction
                mov     rcx, __trace_max_count_ptr
                mov     rcx, [rcx]
                cmp     rax, rcx
                jae     skip

                mov     rcx, [rsp+28h]             ; Get return address
                mov     [rdx+rax*8], rcx
                lock    inc qword ptr [rbx]
skip:
                popfq
                pop     rdx
                pop     rcx
                pop     rbx
                pop     rax
                ret
__trace_pc        endp
align (10h)


_text$payload ends



end