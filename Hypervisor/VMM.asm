
.CODE

EXTERN Install_VMCS : PROC
EXTERN HandleVmExit : PROC
EXTERN _RtlWalkFrameChain : PROC
EXTERN InstrumentationCallback : PROC
EXTERN KMPnPEvt_DriverInit_Start : QWORD


__InstrumentationCallback PROC
	push QWORD PTR [rbp+0e8h]
	push rcx
	push rdx
	push rbx
	push rbp
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	sub rsp, 68h
    movaps xmmword ptr [rsp +  0h], xmm0
    movaps xmmword ptr [rsp + 10h], xmm1
    movaps xmmword ptr [rsp + 20h], xmm2
    movaps xmmword ptr [rsp + 30h], xmm3
    movaps xmmword ptr [rsp + 40h], xmm4
    movaps xmmword ptr [rsp + 50h], xmm5
    pushfq

	sub rsp, 40h
	mov rcx, rbp
	lea rdx, [rsp + 20h]
	mov r8, rax
	call InstrumentationCallback
	
	mov rcx, [rsp + 28h]
	mov rax, [rsp + 20h]
	add rsp, 40h

	popfq
	movaps xmm0, xmmword ptr [rsp +  0h]
    movaps xmm1, xmmword ptr [rsp + 10h]
    movaps xmm2, xmmword ptr [rsp + 20h]
    movaps xmm3, xmmword ptr [rsp + 30h]
    movaps xmm4, xmmword ptr [rsp + 40h]
    movaps xmm5, xmmword ptr [rsp + 50h]
    add rsp, 68h

	test rcx, rcx

	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	pop rdx
	pop rcx	

	jz Skip
	mov r10, [rsp]

Skip:
	add rsp, 8
	push rax
	ret
__InstrumentationCallback ENDP

__redirect_22xxx PROC
	mov rcx, r14
	mov rdx, rax
	sub rsp, 20h
	call _RtlWalkFrameChain
	add rsp, 20h
	mov rbx, [rsp + 50h]
	mov rbp, [rsp + 58h]
	mov rsi, [rsp + 60h]
	add rsp, 30h
	pop r15
	pop r14
	pop rdi
	ret
__redirect_22xxx ENDP

__redirect_1904x PROC
	mov rcx, r14
	mov rdx, rax
	sub rsp, 20h
	call _RtlWalkFrameChain
	add rsp, 20h
	mov rbx, [rsp + 50h]
	mov rbp, [rsp + 58h]
	mov rsi, [rsp + 60h]
	add rsp, 30h
	pop r15
	pop r14
	pop rdi
	ret
__redirect_1904x ENDP

__redirect_1836x PROC
	mov rcx, r14
	mov rdx, rax
	sub rsp, 20h
	call _RtlWalkFrameChain
	add rsp, 20h
	mov rbx, [rsp + 30h]
	mov rbp, [rsp + 38h]
	mov rsi, [rsp + 40h]
	mov rdi, [rsp + 48h]
	add rsp, 20h
	pop r14
	ret
__redirect_1836x ENDP

__redirect_17763 PROC
	mov rcx, r14
	mov rdx, rax
	sub rsp, 20h
	call _RtlWalkFrameChain
	add rsp, 20h
	mov rbx, [rsp + 30h]
	mov rbp, [rsp + 38h]
	mov rsi, [rsp + 40h]
	mov rdi, [rsp + 48h]
	add rsp, 20h
	pop r14
	ret
__redirect_17763 ENDP

__redirect_17134 PROC
	mov rcx, r14
	mov rdx, rax
	sub rsp, 20h
	call _RtlWalkFrameChain
	add rsp, 20h
	mov rbx, [rsp + 30h]
	mov rbp, [rsp + 38h]
	mov rsi, [rsp + 40h]
	mov rdi, [rsp + 48h]
	add rsp, 20h
	pop r14
	ret
__redirect_17134 ENDP

__redirect_16299 PROC
	mov rcx, r14
	mov rdx, rax
	sub rsp, 20h
	call _RtlWalkFrameChain
	add rsp, 20h
	mov rbx, [rsp + 30h]
	mov rbp, [rsp + 38h]
	mov rsi, [rsp + 40h]
	mov rdi, [rsp + 48h]
	add rsp, 20h
	pop r14
	ret
__redirect_16299 ENDP

__redirect_15063 PROC
	mov rcx, r14
	mov rdx, rax
	sub rsp, 20h
	call _RtlWalkFrameChain
	add rsp, 20h
	mov rbx, [rsp + 30h]
	mov rbp, [rsp + 38h]
	mov rsi, [rsp + 40h]
	mov rdi, [rsp + 48h]
	add rsp, 20h
	pop r14
	ret
__redirect_15063 ENDP

PUSHAQ MACRO
	push r15
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8
	push rdi
	push rsi
	push rbp
	sub rsp, 8
	push rbx
	push rdx
	push rcx
	push rax
ENDM

POPAQ MACRO
	pop	rax
	pop	rcx
	pop	rdx
	pop	rbx
	add	rsp, 8
	pop	rbp
	pop	rsi
	pop	rdi
	pop	r8
	pop	r9
	pop	r10
	pop	r11
	pop	r12
	pop	r13
	pop	r14
	pop	r15
ENDM

ASM_Install_VMCS PROC
	pushfq
	PUSHAQ
	mov rax,rcx
	mov r8d,edx             ;核心号
	mov rcx,rsp             ;参数1 GuestRsp
	mov rdx,VmLaunchToGuest  ;参数2 GuestResumeRip
	sub rsp,20h            ;提升栈顶，给一些局部变量分配足够的栈空间
	call rax                ;Install_VMCS
	add rsp,20h
	POPAQ
	popfq
	xor rax,rax
	ret
VmLaunchToGuest:
	POPAQ
	popfq
	xor rax,rax
	inc rax
	ret
ASM_Install_VMCS ENDP

CaptureContext PROC
	pushfq
	mov [rcx+078h], rax
	mov [rcx+080h], rcx
	mov [rcx+088h], rdx
	mov [rcx+0B8h], r8
	mov [rcx+0C0h], r9
	mov [rcx+0C8h], r10
	mov [rcx+0D0h], r11
	movaps xmmword ptr [rcx+01A0h], xmm0
	movaps xmmword ptr [rcx+01B0h], xmm1
	movaps xmmword ptr [rcx+01C0h], xmm2
	movaps xmmword ptr [rcx+01D0h], xmm3
	movaps xmmword ptr [rcx+01E0h], xmm4
	movaps xmmword ptr [rcx+01F0h], xmm5
	mov word ptr [rcx+038h], cs
	mov word ptr [rcx+03Ah], ds
	mov word ptr [rcx+03Ch], es
	mov word ptr [rcx+042h], ss
	mov word ptr [rcx+03Eh], fs
	mov word ptr [rcx+040h], gs
	mov [rcx+090h], rbx
	mov [rcx+0A0h], rbp
	mov [rcx+0A8h], rsi
	mov [rcx+0B0h], rdi
	mov [rcx+0D8h], r12
	mov [rcx+0E0h], r13
	mov [rcx+0E8h], r14
	mov [rcx+0F0h], r15
	fnstcw word ptr [rcx+0100h]
	mov dword ptr [rcx+0102h], 0
	movaps xmmword ptr [rcx+0200h], xmm6
	movaps xmmword ptr [rcx+0210h], xmm7
	movaps xmmword ptr [rcx+0220h], xmm8
	movaps xmmword ptr [rcx+0230h], xmm9
	movaps xmmword ptr [rcx+0240h], xmm10
	movaps xmmword ptr [rcx+0250h], xmm11
	movaps xmmword ptr [rcx+0260h], xmm12
	movaps xmmword ptr [rcx+0270h], xmm13
	movaps xmmword ptr [rcx+0280h], xmm14
	movaps xmmword ptr [rcx+0290h], xmm15
	stmxcsr dword ptr [rcx+0118h]
	stmxcsr dword ptr [rcx+034h]
	lea rax, [rsp+010h]
	mov [rcx+098h], rax
	mov rax, [rsp+08h]
	mov [rcx+0F8h], rax
	mov eax, [rsp]
	mov [rcx+044h], eax
	mov dword ptr [rcx+030h], 10000Fh
	add rsp, 8
	ret
CaptureContext ENDP

ReadTaskRegister PROC
	str ax
	ret
ReadTaskRegister ENDP

ReadLocalDescriptorTableRegister PROC
	sldt ax
	ret
ReadLocalDescriptorTableRegister ENDP

EnterFromGuest PROC
    sub rsp, 0168h
    PUSHAQ
    mov rcx, rsp 
	sub rsp, 68h
    movaps xmmword ptr [rsp +  0h], xmm0
    movaps xmmword ptr [rsp + 10h], xmm1
    movaps xmmword ptr [rsp + 20h], xmm2
    movaps xmmword ptr [rsp + 30h], xmm3
    movaps xmmword ptr [rsp + 40h], xmm4
    movaps xmmword ptr [rsp + 50h], xmm5
    pushfq
    sub rsp, 20h
    call HandleVmExit 
    add rsp, 20h
    popfq
	movaps xmm0, xmmword ptr [rsp +  0h]
    movaps xmm1, xmmword ptr [rsp + 10h]
    movaps xmm2, xmmword ptr [rsp + 20h]
    movaps xmm3, xmmword ptr [rsp + 30h]
    movaps xmm4, xmmword ptr [rsp + 40h]
    movaps xmm5, xmmword ptr [rsp + 50h]
    add rsp, 68h
    test al, al
    jz ExitVmx 
    POPAQ
    vmresume
    jmp VmxError
ExitVmx:
    POPAQ
    jz vmxError
    jc vmxError
    push rax
    popfq                   ; rflags <= GurstFlags
    mov rsp, rdx            ; rsp <= GuestRsp
    push rcx
    ret                     ; jmp AddressToReturn
VmxError:
    int 3
EnterFromGuest ENDP

AsmVmxCall PROC
    vmcall                  ; vmcall(hypercall_number, context)
    ret
AsmVmxCall ENDP

AsmReloadGdtr PROC
	push	rcx
	shl		rdx, 48
	push	rdx
	lgdt	fword ptr [rsp+6]
	pop		rax
	pop		rax
	ret
AsmReloadGdtr ENDP

AsmReloadIdtr PROC
	push	rcx
	shl		rdx, 48
	push	rdx
	lidt	fword ptr [rsp+6]
	pop		rax
	pop		rax
	ret
AsmReloadIdtr ENDP

AsmInvept PROC
    invept rcx, oword ptr [rdx]
    xor rax, rax
    ret
AsmInvept ENDP

AsmInvvpid PROC
    invvpid rcx, oword ptr [rdx]
    xor rax, rax
    ret
AsmInvvpid ENDP

; void __stdcall AsmWriteGDT(_In_ const GDTR *gdtr);
AsmWriteGDT PROC
    lgdt fword ptr [rcx]
    ret
AsmWriteGDT ENDP




END