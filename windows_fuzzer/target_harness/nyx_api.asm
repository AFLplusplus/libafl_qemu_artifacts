PUBLIC _kAFL_hypercall

.code

; Execute NYX backdoor (two arguments)
; Parameters:
;	[RAX, OUT] Hook return value
;	[RCX, IN]  NYX Backdorr operation
;	[RDX, IN]  Arg1
;	[R8,  IN]  Arg2
_kAFL_hypercall:
	push rbx
	push rcx

	mov rax, rcx
	mov rbx, rdx
	mov rcx, r8

	vmcall

	pop rcx
	pop rbx

	ret
END