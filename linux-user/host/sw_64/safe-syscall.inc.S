/*
 * safe-syscall.inc.S : host-specific assembly fragment
 * to handle signals occurring at the same time as system calls.
 * This is intended to be included by linux-user/safe-syscall.S
 *
 * Written by Richard Henderson <rth@twiddle.net>
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

	.global safe_syscall_base
	.global safe_syscall_start
	.global safe_syscall_end

	/* This is the entry point for making a system call. The calling
	 * convention here is that of a C varargs function with the
	 * first argument an 'int *' to the signal_pending flag, the
	 * second one the system call number (as a 'long'), and all further
	 * arguments being syscall arguments (also 'long').
	 * We return a long which is the syscall's return value, which
	 * may be negative-errno on failure. Conversion to the
	 * -1-and-errno-set convention is done by the calling wrapper.
	 */
safe_syscall_base:
	.cfi_startproc
	/* The syscall calling convention isn't the same as the
	 * C one:
	 * we enter with x16 == *signal_pending
	 *               x17 == syscall number
	 *               x18 ... x21, (stack) == syscall arguments
	 *               and return the result in x0
	 * and the syscall instruction needs
	 *               x0 == syscall number
	 *               x16 ... x21 == syscall arguments
	 *               and returns the result in x0
	 * Shuffle everything around appropriately.
	 */
        ldgp $29,0($27) /* load gp */
	mov $16, $7 /* signal_pending pointer */
	mov $17,$0 /* syscall number */
	mov $18,$16/* syscall arguments */
	mov $19,$17
	mov $20,$18
	mov $21,$19
	ldl $20,0($sp)
	ldl $21,8($sp)

	/* This next sequence of code works in conjunction with the
	 * rewind_if_safe_syscall_function(). If a signal is taken
	 * and the interrupted PC is anywhere between 'safe_syscall_start'
	 * and 'safe_syscall_end' then we rewind it to 'safe_syscall_start'.
	 * The code sequence must therefore be able to cope with this, and
	 * the syscall instruction must be the final one in the sequence.
	 */
safe_syscall_start:
	/* if signal_pending is non-zero, don't do the call */
	ldw $1, 0($7)
	zapnot $1,0xf,$1
	bne  $1, 0f
	sys_call 0x83
safe_syscall_end:
	beq $19, ok
	subl $31,$0,$0
ok:
	ret
0:
	/* code path for having successfully executed the syscall */
	ldi $0, TARGET_ERESTARTSYS($31)
	subl $31,$0,$0
	ret
	.cfi_endproc

	.size	safe_syscall_base, .-safe_syscall_base
