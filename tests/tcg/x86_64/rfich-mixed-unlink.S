/* Standalone Linux guest: as --64 -o test.o this.S; ld -o test test.o.
 * Three learned targets, ordinary/RFICH mixed incoming lists, source and
 * destination SMC, plus fork after plan publication. No guest libc needed.
 */
.global _start
.text
_start:
    mov $100000, %edi
    xor %eax, %eax
    call self_loop
    cmp $100000, %rax
    jne fail
    mov $9, %eax                    /* mmap seven RWX pages */
    xor %edi, %edi
    mov $28672, %esi
    mov $7, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    syscall
    cmp $-4095, %rax
    jae fail
    mov %rax, %r12
    xor %ebx, %ebx
1:
    mov %ebx, %eax
    shl $12, %eax
    lea (%r12,%rax), %rsi
    movl $0x01478d48, (%rsi)         /* lea 1(%rdi),%rax; ret */
    movb $0xc3, 4(%rsi)
    lea 12288(%rsi), %rdi
    movw $0x9066, (%rdi)            /* nop; direct jmp target */
    movb $0xe9, 2(%rdi)
    movl $-12295, 3(%rdi)
    inc %ebx
    cmp $3, %ebx
    jne 1b
    movl $0xe6ff9066, 24576(%r12)    /* nop; jmp *%rsi */
    xor %r13d, %r13d                /* round */
    xor %ebp, %ebp                  /* child flag */
round:
    call warm
    /* Fork a process with an already frozen plan and linked TBs. */
    test %r13d, %r13d
    jnz mutate
    mov $57, %eax
    syscall
    test %rax, %rax
    js fail
    jz child
    mov %rax, %rdi
    sub $8, %rsp
    mov %rsp, %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax                   /* wait4 */
    syscall
    test %rax, %rax
    js fail
    cmpl $0, (%rsp)
    jne fail
    add $8, %rsp
    jmp mutate
child:
    mov $1, %ebp
mutate:
    mov $0x66, %eax
    test $1, %r13d
    jnz 2f
    mov $0x2e, %eax
2:
    mov %al, 24576(%r12)            /* invalidate RFICH source */
    mov %al, 12288(%r12)            /* invalidate ordinary sources */
    mov %al, 16384(%r12)
    mov %al, 20480(%r12)
    call warm                      /* rebuild the mixed incoming lists */
    mov %r13d, %eax
    inc %eax
    and $1, %eax
    inc %eax
    mov %al, 3(%r12)                /* invalidate all three destinations */
    mov %al, 4099(%r12)
    mov %al, 8195(%r12)
    inc %r13d
    cmp $64, %r13d
    jne round
    test %ebp, %ebp
    jnz success
    mov $1, %eax
    mov $1, %edi
    lea message(%rip), %rsi
    mov $message_end-message, %edx
    syscall
success:
    xor %edi, %edi
    jmp exit
fail:
    mov $1, %edi
exit:
    mov $60, %eax
    syscall

warm:
    xor %r14d, %r14d
    xor %r15d, %r15d
3:
    mov %r15d, %eax
    shl $12, %eax
    lea 12288(%r12,%rax), %r11
    mov %r14, %rdi
    call *%r11
    call check
    mov %r15d, %eax
    shl $12, %eax
    lea (%r12,%rax), %rsi
    lea 24576(%r12), %r11
    mov %r14, %rdi
    call *%r11                     /* one site learns the dispatch TB */
    call check                     /* dispatch learns target 0, 1, 2 */
    inc %r15d
    cmp $3, %r15d
    jne 4f
    xor %r15d, %r15d
4:
    inc %r14d
    cmp $300, %r14d
    jne 3b
    ret
check:
    mov %r13d, %edx
    and $1, %edx
    lea 1(%r14,%rdx), %rdx
    cmp %rdx, %rax
    jne fail
    ret

/* No conditional guest branch splits this TB. Its learned target is its
 * own TB entry, then the last iteration must fall back to a new target. */
self_loop:
    lea self_loop(%rip), %rsi
    lea self_done(%rip), %r10
    inc %rax
    dec %rdi
    cmovz %r10, %rsi
    jmp *%rsi
self_done:
    ret
.section .rodata
message:
    .ascii "mixed direct/RFICH three-slot unlink and fork: PASS\n"
message_end:
.section .note.GNU-stack,"",@progbits
