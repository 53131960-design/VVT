#pragma once
#include "ia32.hpp"

enum VmCall
{
	CallExitVT = 16777,
	CallEPTHook,
	CallEPTUnHook,
};
struct Idtr {
	unsigned short limit;
	ULONG_PTR base;
};

struct Idtr32 {
	unsigned short limit;
	ULONG32 base;
};
using Gdtr = Idtr;
typedef struct _GPREGISTER_CONTEXT
{
	SIZE_T GuestRAX;
	SIZE_T GuestRCX;
	SIZE_T GuestRDX;
	SIZE_T GuestRBX;
	SIZE_T GuestRSP;
	SIZE_T GuestRBP;
	SIZE_T GuestRSI;
	SIZE_T GuestRDI;
	SIZE_T GuestR8;
	SIZE_T GuestR9;
	SIZE_T GuestR10;
	SIZE_T GuestR11;
	SIZE_T GuestR12;
	SIZE_T GuestR13;
	SIZE_T GuestR14;
	SIZE_T GuestR15;
} GPREGISTER_CONTEXT, * PGPREGISTER_CONTEXT;

typedef struct DECLSPEC_ALIGN(16) _REGISTER_CONTEXT
{
	ULONG64 P1Home;
	ULONG64 P2Home;
	ULONG64 P3Home;
	ULONG64 P4Home;
	ULONG64 P5Home;
	ULONG64 P6Home;
	ULONG ContextFlags;
	ULONG MxCsr;
	SEGMENT_SELECTOR SegCS;
	SEGMENT_SELECTOR SegDS;
	SEGMENT_SELECTOR SegES;
	SEGMENT_SELECTOR SegFS;
	SEGMENT_SELECTOR SegGS;
	SEGMENT_SELECTOR SegSS;
	ULONG EFlags;
	ULONG64 Dr0;
	ULONG64 Dr1;
	ULONG64 Dr2;
	ULONG64 Dr3;
	ULONG64 Dr6;
	ULONG64 Dr7;
	ULONG64 Rax;
	ULONG64 Rcx;
	ULONG64 Rdx;
	ULONG64 Rbx;
	ULONG64 Rsp;
	ULONG64 Rbp;
	ULONG64 Rsi;
	ULONG64 Rdi;
	ULONG64 R8;
	ULONG64 R9;
	ULONG64 R10;
	ULONG64 R11;
	ULONG64 R12;
	ULONG64 R13;
	ULONG64 R14;
	ULONG64 R15;
	ULONG64 Rip;
	union {
		XMM_SAVE_AREA32 FltSave;
		struct {
			M128A Header[2];
			M128A Legacy[8];
			M128A Xmm0;
			M128A Xmm1;
			M128A Xmm2;
			M128A Xmm3;
			M128A Xmm4;
			M128A Xmm5;
			M128A Xmm6;
			M128A Xmm7;
			M128A Xmm8;
			M128A Xmm9;
			M128A Xmm10;
			M128A Xmm11;
			M128A Xmm12;
			M128A Xmm13;
			M128A Xmm14;
			M128A Xmm15;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;
	M128A VectorRegister[26];
	ULONG64 VectorControl;
	ULONG64 DebugControl;
	ULONG64 LastBranchToRip;
	ULONG64 LastBranchFromRip;
	ULONG64 LastExceptionToRip;
	ULONG64 LastExceptionFromRip;
} REGISTER_CONTEXT, * PREGISTER_CONTEXT;

typedef struct _IA32_SPECIAL_REGISTERS
{
	CR0 ControlRegister0;
	CR3 ControlRegister3;
	CR4 ControlRegister4;
	SEGMENT_DESCRIPTOR_REGISTER_64 GlobalDescriptorTableRegister;
	SEGMENT_DESCRIPTOR_REGISTER_64 InterruptDescriptorTableRegister;
	DR7 DebugRegister7;
	EFLAGS RflagsRegister;
	SEGMENT_SELECTOR TaskRegister;
	SEGMENT_SELECTOR LocalDescriptorTableRegister;
	IA32_DEBUGCTL_REGISTER DebugControlMsr;
	IA32_SYSENTER_CS_REGISTER SysenterCsMsr;
	SIZE_T SysenterEspMsr;
	SIZE_T SysenterEipMsr;
	SIZE_T GlobalPerfControlMsr;
	IA32_PAT_REGISTER PatMsr;
	IA32_EFER_REGISTER EferMsr;
} IA32_SPECIAL_REGISTERS, * PIA32_SPECIAL_REGISTERS;

typedef struct _VMX_SEGMENT_DESCRIPTOR
{
	SIZE_T Selector;
	SIZE_T BaseAddress;
	UINT32 SegmentLimit;
	VMX_SEGMENT_ACCESS_RIGHTS AccessRights;
} VMX_SEGMENT_DESCRIPTOR, * PVMX_SEGMENT_DESCRIPTOR;

typedef struct _VMM_EPT_PAGE_HOOK
{
	DECLSPEC_ALIGN(PAGE_SIZE) UCHAR FakePage[PAGE_SIZE];
	LIST_ENTRY PageHookList;
	SIZE_T PhysicalBaseAddress;
	SIZE_T VirtualAddress;
	EPTE* TargetPage;
	EPTE ChangedEntry;
	EPTE OriginalEntry;
	PUCHAR Trampoline;
} VMM_EPT_PAGE_HOOK, * PVMM_EPT_PAGE_HOOK;

typedef SEGMENT_DESCRIPTOR_64* PSEGMENT_DESCRIPTOR_64;

typedef union _VMX_EXIT_REASON_FIELD_UNION
{
	struct
	{
		SIZE_T BasicExitReason : 16;
		SIZE_T MustBeZero1 : 11;
		SIZE_T WasInEnclaveMode : 1;
		SIZE_T PendingMTFExit : 1;
		SIZE_T ExitFromVMXRoot : 1;
		SIZE_T MustBeZero2 : 1;
		SIZE_T VmEntryFailure : 1;
	};
	SIZE_T Flags;
} VMX_EXIT_REASON, * PVMX_EXIT_REASON;

typedef struct _VMEXIT_CONTEXT
{
	PGPREGISTER_CONTEXT GuestContext;
	SIZE_T GuestRIP;
	union _GUEST_EFLAGS
	{
		SIZE_T RFLAGS;
		EFLAGS EFLAGS;
	} GuestFlags;
	KIRQL SavedIRQL;
	VMX_EXIT_REASON ExitReason;
	SIZE_T ExitQualification;
	SIZE_T InstructionLength;
	SIZE_T InstructionInformation;
	SIZE_T GuestPhysicalAddress;
	bool ShouldStopExecution;
	bool ShouldIncrementRIP;
} VMEXIT_CONTEXT, * PVMEXIT_CONTEXT;

union __xcr0
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 x87 : 1;
		unsigned __int64 sse : 1;
		unsigned __int64 avx : 1;
		unsigned __int64 bndreg : 1;
		unsigned __int64 bndcsr : 1;
		unsigned __int64 opmask : 1;
		unsigned __int64 zmm_hi256 : 1;
		unsigned __int64 hi16_zmm : 1;
		unsigned __int64 reserved1 : 1;
		unsigned __int64 pkru : 1;
		unsigned __int64 reserved2 : 1;
		unsigned __int64 cet_user_state : 1;
		unsigned __int64 cet_supervisor_state : 1;
		unsigned __int64 xaad : 1;
		unsigned __int64 reserved3 : 50;
	}fields;
};

typedef struct _VMEXIT_CONTEXT VMEXIT_CONTEXT, * PVMEXIT_CONTEXT;