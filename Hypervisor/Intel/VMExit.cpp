#include <ntifs.h>
#include <intrin.h>
#include "VMExit.hpp"
#include "EPT.hpp"
#include "Hook.hpp"
#include "../Global/Global.hpp"
#include "../Common/Common.hpp"

#define CPUID_VMX_ENABLED_BIT            5

extern "C" void __fastcall AsmReloadGdtr(void* GdtBase, unsigned long GdtLimit);
extern "C" void __fastcall AsmReloadIdtr(void* GdtBase, unsigned long GdtLimit);
extern "C" UCHAR __fastcall AsmInvept(_In_ ULONG_PTR InveptType, _In_ const INVEPT_DESCRIPTOR *InveptDescriptor);
extern "C" UCHAR __fastcall AsmInvvpid(_In_ ULONG_PTR invvpid_type,_In_ const INVVPID_DESCRIPTOR* invvpid_descriptor);
extern "C" void __stdcall AsmWriteGDT(_In_ const Gdtr * gdtr);
void __lgdt(_In_ void* gdtr) { AsmWriteGDT(static_cast<Gdtr*>(gdtr)); };
void UtilInveptGlobal() {
	INVEPT_DESCRIPTOR Desc = { 0 };
	AsmInvept(2, &Desc);
}

void UtilInvvpidAllContext() {
	INVVPID_DESCRIPTOR desc = { 0 };
	AsmInvvpid(2, &desc);
}

void ExitHandleUnknownExit(PVMEXIT_CONTEXT ExitContext)
{
	__debugbreak();
	ExitContext->ShouldIncrementRIP = true;
}

void ExitHandleExitVT(PVMEXIT_CONTEXT ExitContext)
{
	ULONG_PTR GuestRSP = 0, GuestRIP = 0, GuestCr3 = 0, ExitInstructionLength = 0;
	ULONG_PTR FsBase, GsBase, GdtrBase, GdtrLimit, IdtrBase, IdtrLimit;

	__vmx_vmread(VMCS_GUEST_CR3, &GuestCr3);
	__writecr3(GuestCr3);

	__vmx_vmread(VMCS_GUEST_RIP, &GuestRIP);
	__vmx_vmread(VMCS_GUEST_RSP, &GuestRSP);

	__vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &ExitInstructionLength);
	GuestRIP += ExitInstructionLength;

	__vmx_vmread(VMCS_GUEST_FS_BASE, &FsBase);
	__writemsr(IA32_FS_BASE, FsBase);

	__vmx_vmread(VMCS_GUEST_GS_BASE, &GsBase);
	__writemsr(IA32_GS_BASE, GsBase);

	__vmx_vmread(VMCS_GUEST_GDTR_BASE, &GdtrBase);
	__vmx_vmread(VMCS_GUEST_GDTR_LIMIT, &GdtrLimit);

	AsmReloadGdtr((void*)GdtrBase, (unsigned long)GdtrLimit);

	__vmx_vmread(VMCS_GUEST_IDTR_BASE, &IdtrBase);
	__vmx_vmread(VMCS_GUEST_IDTR_LIMIT, &IdtrLimit);

	AsmReloadIdtr((void*)IdtrBase, (unsigned long)IdtrLimit);

	ExitContext->GuestContext->GuestRAX = ExitContext->GuestFlags.RFLAGS;
	ExitContext->GuestContext->GuestRCX = GuestRIP;
	ExitContext->GuestContext->GuestRDX = GuestRSP;
	ExitContext->ShouldStopExecution = true;

	__vmx_off();

	CR4 Register;
	Register.Flags = __readcr4();
	Register.VmxEnable = 0;
	__writecr4(Register.Flags);
}

void ExitHandleCPUID(PVMEXIT_CONTEXT ExitContext)
{
	INT32 CPUInfo[4];
	__cpuidex(CPUInfo, (int)ExitContext->GuestContext->GuestRAX, (int)ExitContext->GuestContext->GuestRCX);
	if (ExitContext->GuestContext->GuestRAX == 1)
		CPUInfo[2] = (INT32)(CPUInfo[2] & ~(1ULL << CPUID_VMX_ENABLED_BIT));//CPUInfo[2] = CPUInfo[2] & 0x7FFFFFFF | 0x20;

	if (ExitContext->GuestContext->GuestRAX == 0x40000001)
	{
		CPUInfo[0] = 0;
		CPUInfo[1] = 0;
		CPUInfo[2] = 0;
		CPUInfo[3] = 0;
	}
	//Log("GuestRIP:%p", ExitContext->GuestRIP);
	//if (ExitContext->GuestRIP >= Global::g_EacCPUIDRip && ExitContext->GuestRIP <= Global::g_EacCPUIDRip + 0x100)
	if (ExitContext->GuestRIP <= 0x6FFFFFFFFFFF || ExitContext->GuestRIP >= Global::g_CPUIDRip && ExitContext->GuestRIP <= Global::g_CPUIDRip + 0x100)
	{
		ExitContext->GuestContext->GuestR11 = 0;
	}
	ExitContext->GuestContext->GuestRAX = CPUInfo[0];
	ExitContext->GuestContext->GuestRBX = CPUInfo[1];
	ExitContext->GuestContext->GuestRCX = CPUInfo[2];
	ExitContext->GuestContext->GuestRDX = CPUInfo[3];
}

void InjectInterruption(ULONG InterruptionType, ULONG Vector, bool DeliverErrorCode, ULONG ErrorCode)
{
	VMEXIT_INTERRUPT_INFORMATION Inject = { 0 };
	Inject.Flags = 0;
	Inject.Valid = true;
	Inject.InterruptionType = InterruptionType;
	Inject.Vector = Vector;
	Inject.ErrorCodeValid = DeliverErrorCode;
	__vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, Inject.Flags);
	if (DeliverErrorCode)
		__vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, ErrorCode);
}
void VmmpAdjustGuestInstructionPointer(PVMEXIT_CONTEXT ExitContext) 
{
	size_t exit_inst_length;
	__vmx_vmread(static_cast<size_t>(VMCS_VMEXIT_INSTRUCTION_LENGTH), &exit_inst_length);
	__vmx_vmwrite(static_cast<size_t>(VMCS_GUEST_RIP), ExitContext->GuestRIP + exit_inst_length);

	// Inject #DB if TF is set
	if (ExitContext->GuestFlags.EFLAGS.TrapFlag) {
		ExitContext->ShouldIncrementRIP = false;
		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::Debug, false, 0);//#GP异常
		__vmx_vmwrite(static_cast<size_t>(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH), exit_inst_length);
	}
}
void ExitHandleMSRAccess(PVMEXIT_CONTEXT ExitContext, bool ReadAccess)
{
	ULONG RCX = static_cast<ULONG>(ExitContext->GuestContext->GuestRCX & 0xFFFFFFFF);
	LARGE_INTEGER MSRValue = { 0 };
	if (RCX >= 0x40000000 && RCX <= 0x400000FF)
	{
		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::GeneralProtection, true, 0);//#GP异常
		return;
	}
	if (RCX <= 0x00001FFF || ((0xC0000000 <= RCX) && (RCX <= 0xC0001FFF)))
	{
		if (ReadAccess)
		{
			MSRValue.QuadPart = __readmsr(RCX);
			if (RCX == IA32_EFER)//MSR_EFER
			{
				IA32_EFER_REGISTER EFER;
				EFER.Flags = MSRValue.QuadPart;
				EFER.SyscallEnable = true;
				MSRValue.QuadPart = EFER.Flags;
			}
			ExitContext->GuestContext->GuestRAX = MSRValue.LowPart;
			ExitContext->GuestContext->GuestRDX = MSRValue.HighPart;
		}
		else
		{
			MSRValue.LowPart = (ULONG)ExitContext->GuestContext->GuestRAX;
			MSRValue.HighPart = (ULONG)ExitContext->GuestContext->GuestRDX;
			__writemsr(RCX, MSRValue.QuadPart);
		}
		VmmpAdjustGuestInstructionPointer(ExitContext);
	}
	else
	{
		//ExitContext->ShouldIncrementRIP = false;
		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::GeneralProtection, true, 0);//#GP异常
	}
}


//void ExitHandleMSRAccess(PVMEXIT_CONTEXT ExitContext, bool ReadAccess)
//{
//	LARGE_INTEGER MSRValue = { 0 };
//	if ((ExitContext->GuestContext->GuestRCX <= 0x00001FFF) || ((0xC0000000 <= ExitContext->GuestContext->GuestRCX) && (ExitContext->GuestContext->GuestRCX <= 0xC0001FFF)) || (ExitContext->GuestContext->GuestRCX >= 0x40000000 && (ExitContext->GuestContext->GuestRCX <= 0x400000F0)))
//	{
//		if (ReadAccess) {
//			MSRValue.QuadPart = __readmsr((ULONG)ExitContext->GuestContext->GuestRCX);
//			ExitContext->GuestContext->GuestRAX = MSRValue.LowPart;
//			ExitContext->GuestContext->GuestRDX = MSRValue.HighPart;
//		}
//		else
//		{
//			MSRValue.LowPart = (ULONG)ExitContext->GuestContext->GuestRAX;
//			MSRValue.HighPart = (ULONG)ExitContext->GuestContext->GuestRDX;
//			__writemsr((ULONG)ExitContext->GuestContext->GuestRCX, MSRValue.QuadPart);
//		}
//	}
//	else
//	{
//		ExitContext->ShouldIncrementRIP = false;
//		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::GeneralProtection, false, 0);//#GP异常
//	}
//}

void ExitHandleRdtscp(PVMEXIT_CONTEXT ExitContext)
{
	unsigned int TscAux = 0;
	ULARGE_INTEGER Tsc = { 0 };
	Tsc.QuadPart = __rdtscp(&TscAux);
	ExitContext->GuestContext->GuestRDX = Tsc.HighPart;
	ExitContext->GuestContext->GuestRAX = Tsc.LowPart;
	ExitContext->GuestContext->GuestRCX = TscAux;
}

void ExitHandleEPTViolation(PVMEXIT_CONTEXT ExitContext) {
	ULONG_PTR GuestPhysicalAddress = 0;
	__vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &GuestPhysicalAddress);

	ExitContext->ShouldIncrementRIP = false;

	if (EPTHandlePageHookExit(GuestPhysicalAddress))
		return;

	EPTE* EPTEntry = EPT::EPTGetPTEntry(EPT::g_EPTData.EPT_PML4, 4, GuestPhysicalAddress);
	/*if (EPTEntry && EPTEntry->Flags)
	{
		EPTEntry->ExecuteAccess = 0;
		EPTEntry->ReadAccess = true;
		EPTEntry->WriteAccess = true;
		UtilInveptGlobal();
	}
	else {
		EPT::EPTConstructTables(EPT::g_EPTData.EPT_PML4, 4, GuestPhysicalAddress, &EPT::g_EPTData);
		UtilInveptGlobal();
	}*/

	EPT::EPTConstructTables(EPT::g_EPTData.EPT_PML4, 4, GuestPhysicalAddress, &EPT::g_EPTData);
	UtilInveptGlobal();
}

void ExitHandleInvlpg(PVMEXIT_CONTEXT)
{
	INVVPID_DESCRIPTOR desc = { 0 };
	ULONG_PTR Invalidate;
	__vmx_vmread(VMCS_EXIT_QUALIFICATION, &Invalidate);
	desc.Vpid = (UINT16)(KeGetCurrentProcessorNumberEx(nullptr) + 1);
	desc.LinearAddress = Invalidate;
	AsmInvvpid(0, &desc);
}

void SetNmiExiting(PVMEXIT_CONTEXT,bool Enable)
{
	IA32_VMX_PROCBASED_CTLS_REGISTER VMProcctl = { 0 };
	VMProcctl.Flags = 0;
	__vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, (size_t*)&VMProcctl);
	VMProcctl.NmiWindowExiting = Enable;
	__vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, VMProcctl.Flags);
}

void ExitHandleXsetbv(PVMEXIT_CONTEXT ExitContext)
{
	__xcr0 NewXcr0 = { 0 };
	__xcr0 CurrentXcr0 = { 0 };
	unsigned int XcrNumber = ExitContext->GuestContext->GuestRCX & 0xFFFFFFFF;
	NewXcr0.all = ExitContext->GuestContext->GuestRDX << 32 | ExitContext->GuestContext->GuestRAX & 0xFFFFFFFF;
	CurrentXcr0.all = _xgetbv(0);
	if (XcrNumber > 0 || NewXcr0.fields.x87 == 0 || NewXcr0.fields.reserved1 != CurrentXcr0.fields.reserved1 || NewXcr0.fields.reserved2 != CurrentXcr0.fields.reserved2 || NewXcr0.fields.reserved3 != CurrentXcr0.fields.reserved3 || (NewXcr0.fields.avx == 1 && NewXcr0.fields.sse == 0)){
		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::GeneralProtection, false, 0);
		ExitContext->ShouldIncrementRIP = false;
		return;
	}
	_xsetbv(XcrNumber, NewXcr0.all);
}

void ExitHandleCRAccess(PVMEXIT_CONTEXT ExitContext)
{
	VMX_EXIT_QUALIFICATION_MOV_CR ExitQualification = { 0 };
	ExitQualification.Flags = 0;
	__vmx_vmread(VMCS_EXIT_QUALIFICATION, (size_t*)&ExitQualification);
	ULONG_PTR* RegisterUsed = nullptr;
	if (ExitQualification.GeneralPurposeRegister == 0)
		RegisterUsed = &ExitContext->GuestContext->GuestRAX;
	else if (ExitQualification.GeneralPurposeRegister == 1)
		RegisterUsed = &ExitContext->GuestContext->GuestRCX;
	else if (ExitQualification.GeneralPurposeRegister == 2)
		RegisterUsed = &ExitContext->GuestContext->GuestRDX;
	else if (ExitQualification.GeneralPurposeRegister == 3)
		RegisterUsed = &ExitContext->GuestContext->GuestRBX;
	else if (ExitQualification.GeneralPurposeRegister == 4)
		RegisterUsed = &ExitContext->GuestContext->GuestRSP;
	else if (ExitQualification.GeneralPurposeRegister == 5)
		RegisterUsed = &ExitContext->GuestContext->GuestRBP;
	else if (ExitQualification.GeneralPurposeRegister == 6)
		RegisterUsed = &ExitContext->GuestContext->GuestRSI;
	else if (ExitQualification.GeneralPurposeRegister == 7)
		RegisterUsed = &ExitContext->GuestContext->GuestRDI;
	else if (ExitQualification.GeneralPurposeRegister == 8)
		RegisterUsed = &ExitContext->GuestContext->GuestR8;
	else if (ExitQualification.GeneralPurposeRegister == 9)
		RegisterUsed = &ExitContext->GuestContext->GuestR9;
	else if (ExitQualification.GeneralPurposeRegister == 10)
		RegisterUsed = &ExitContext->GuestContext->GuestR10;
	else if (ExitQualification.GeneralPurposeRegister == 11)
		RegisterUsed = &ExitContext->GuestContext->GuestR11;
	else if (ExitQualification.GeneralPurposeRegister == 12)
		RegisterUsed = &ExitContext->GuestContext->GuestR12;
	else if (ExitQualification.GeneralPurposeRegister == 13)
		RegisterUsed = &ExitContext->GuestContext->GuestR13;
	else if (ExitQualification.GeneralPurposeRegister == 14)
		RegisterUsed = &ExitContext->GuestContext->GuestR14;
	else if (ExitQualification.GeneralPurposeRegister == 15)
		RegisterUsed = &ExitContext->GuestContext->GuestR15;

	if (ExitQualification.AccessType == 0) // MoveToCR
	{
		if (ExitQualification.ControlRegister == 0) // CR0 <- Reg
		{
			CR0 CR0Fixed0, CR0Fixed1, _CR0;
			CR0Fixed0.Flags = { __readmsr(IA32_VMX_CR0_FIXED0) };
			CR0Fixed1.Flags = { __readmsr(IA32_VMX_CR0_FIXED1) };
			_CR0.Flags = { *RegisterUsed };
			_CR0.Flags &= CR0Fixed1.Flags;
			_CR0.Flags |= CR0Fixed0.Flags;
			__vmx_vmwrite(VMCS_GUEST_CR0, _CR0.Flags);
			__vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, _CR0.Flags);
		}
		if (ExitQualification.ControlRegister == 3) // CR0 <- Reg
		{
			INVVPID_DESCRIPTOR desc = { 0 };
			desc.Vpid = (UINT16)(KeGetCurrentProcessorNumberEx(nullptr) + 1);
			AsmInvvpid(3, &desc);
			__vmx_vmwrite(VMCS_GUEST_CR3, *RegisterUsed & ~(1ULL << 63));
		}
		if (ExitQualification.ControlRegister == 4)
		{
			UtilInvvpidAllContext();
			CR4 CR4Fixed0, CR4Fixed1, _CR4;
			CR4Fixed0.Flags = { __readmsr(IA32_VMX_CR4_FIXED0) };
			CR4Fixed1.Flags = { __readmsr(IA32_VMX_CR4_FIXED1) };
			_CR4.Flags = { *RegisterUsed };
			_CR4.Flags &= CR4Fixed1.Flags;
			_CR4.Flags |= CR4Fixed0.Flags;
			__vmx_vmwrite(VMCS_GUEST_CR4, _CR4.Flags);
			__vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, _CR4.Flags);
		}
		KeBugCheck(0xC8);
	}
	else if (ExitQualification.AccessType == 1)
	{
		if (ExitQualification.ControlRegister == 3) // CR0 <- Reg
		{
			ULONG_PTR CR3 = 0;
			__vmx_vmread(VMCS_GUEST_CR3, &CR3);
			*RegisterUsed = CR3;
		}
		KeBugCheck(0xC8);
	}
	else {
		KeBugCheck(0xC8);
	}
}

void ExitHandleDRAccess(PVMEXIT_CONTEXT ExitContext)
{
	VMX_SEGMENT_ACCESS_RIGHTS AccessRights = { 0 };
	__vmx_vmread(VMCS_GUEST_SS_ACCESS_RIGHTS, (size_t*)&AccessRights);
	if (AccessRights.DescriptorPrivilegeLevel)
	{
		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::GeneralProtection, true, 0);
		ExitContext->ShouldIncrementRIP = false;
		return;
	}
	VMX_EXIT_QUALIFICATION_MOV_DR ExitQualification = { 0 };
	__vmx_vmread(VMCS_EXIT_QUALIFICATION, (size_t*)&ExitQualification);

	ULONG_PTR DebugRegister = ExitQualification.DebugRegister;
	if (DebugRegister == 4 || DebugRegister == 5)
	{
		CR4 GuestCR4 = { 0 };
		__vmx_vmread(VMCS_GUEST_CR4, (size_t*)&GuestCR4);
		if (GuestCR4.DebuggingExtensions)
		{
			InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::InvalidOpcode, false, 0);
			ExitContext->ShouldIncrementRIP = false;
			return;
		}
		else if (DebugRegister == 4)
			DebugRegister = 6;
		else
			DebugRegister = 7;
	}
	DR7 GuestDr7 = { 0 };
	__vmx_vmread(VMCS_GUEST_DR7, (size_t*)&GuestDr7);
	if (GuestDr7.GeneralDetect)
	{
		DR6 GuestDr6 = { __readdr(6) };
		GuestDr6.BreakpointCondition = 0;
		GuestDr6.DebugRegisterAccessDetected = true;
		__writedr(6, GuestDr6.Flags);

		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::Debug, false, 0);
		ExitContext->ShouldIncrementRIP = false;

		GuestDr7.GeneralDetect = false;
		__vmx_vmwrite(VMCS_GUEST_DR7, GuestDr7.Flags);
		return;
	}

	ULONG_PTR* RegisterUsed = nullptr;
	if (ExitQualification.GeneralPurposeRegister == 0)
		RegisterUsed = &ExitContext->GuestContext->GuestRAX;
	else if (ExitQualification.GeneralPurposeRegister == 1)
		RegisterUsed = &ExitContext->GuestContext->GuestRCX;
	else if (ExitQualification.GeneralPurposeRegister == 2)
		RegisterUsed = &ExitContext->GuestContext->GuestRDX;
	else if (ExitQualification.GeneralPurposeRegister == 3)
		RegisterUsed = &ExitContext->GuestContext->GuestRBX;
	else if (ExitQualification.GeneralPurposeRegister == 4)
		RegisterUsed = &ExitContext->GuestContext->GuestRSP;
	else if (ExitQualification.GeneralPurposeRegister == 5)
		RegisterUsed = &ExitContext->GuestContext->GuestRBP;
	else if (ExitQualification.GeneralPurposeRegister == 6)
		RegisterUsed = &ExitContext->GuestContext->GuestRSI;
	else if (ExitQualification.GeneralPurposeRegister == 7)
		RegisterUsed = &ExitContext->GuestContext->GuestRDI;
	else if (ExitQualification.GeneralPurposeRegister == 8)
		RegisterUsed = &ExitContext->GuestContext->GuestR8;
	else if (ExitQualification.GeneralPurposeRegister == 9)
		RegisterUsed = &ExitContext->GuestContext->GuestR9;
	else if (ExitQualification.GeneralPurposeRegister == 10)
		RegisterUsed = &ExitContext->GuestContext->GuestR10;
	else if (ExitQualification.GeneralPurposeRegister == 11)
		RegisterUsed = &ExitContext->GuestContext->GuestR11;
	else if (ExitQualification.GeneralPurposeRegister == 12)
		RegisterUsed = &ExitContext->GuestContext->GuestR12;
	else if (ExitQualification.GeneralPurposeRegister == 13)
		RegisterUsed = &ExitContext->GuestContext->GuestR13;
	else if (ExitQualification.GeneralPurposeRegister == 14)
		RegisterUsed = &ExitContext->GuestContext->GuestR14;
	else if (ExitQualification.GeneralPurposeRegister == 15)
		RegisterUsed = &ExitContext->GuestContext->GuestR15;

	if (!RegisterUsed)
		return;

	ULONG_PTR Direction = ExitQualification.DirectionOfAccess;

	if (Direction == 0) //move to dr
	{
		ULONG_PTR Value64 = *RegisterUsed;
		if ((DebugRegister == 6 || DebugRegister == 7) && (Value64 >> 32)) {
			InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::GeneralProtection, true, 0);
			ExitContext->ShouldIncrementRIP = false;
			return;
		}
		if (DebugRegister == 0)
			__writedr(0, *RegisterUsed);
		if (DebugRegister == 1)
			__writedr(1, *RegisterUsed);
		if (DebugRegister == 2)
			__writedr(2, *RegisterUsed);
		if (DebugRegister == 3)
			__writedr(3, *RegisterUsed);
		if (DebugRegister == 6)
		{
			DR6 WriteValue = { *RegisterUsed };
			WriteValue.Reserved1 |= ~WriteValue.Reserved1;
			WriteValue.Reserved2 |= ~WriteValue.Reserved2;
			__writedr(6, WriteValue.Flags);
		}
		if (DebugRegister == 7)
		{
			DR7 WriteValue = { *RegisterUsed };
			WriteValue.Reserved1 |= ~WriteValue.Reserved1;
			WriteValue.Reserved2 |= ~WriteValue.Reserved2;
			__writedr(7, WriteValue.Flags);
		}
	}
	if (Direction == 1)
	{
		if (DebugRegister == 0)
			*RegisterUsed = __readdr(0);
		if (DebugRegister == 1)
			*RegisterUsed = __readdr(1);
		if (DebugRegister == 2)
			*RegisterUsed = __readdr(2);
		if (DebugRegister == 3)
			*RegisterUsed = __readdr(3);
		if (DebugRegister == 6)
			*RegisterUsed = __readdr(6);
		if (DebugRegister == 7)
		{
			DR7 _Dr7 = { 0 };
			__vmx_vmread(VMCS_GUEST_DR7, (size_t*)&_Dr7);
			*RegisterUsed = _Dr7.Flags;
		}
	}
}

UCHAR VmmpGetGuestCpl() {
	VMX_SEGMENT_ACCESS_RIGHTS AccessRights = { 0 };
	__vmx_vmread(VMCS_GUEST_SS_ACCESS_RIGHTS, (size_t*)&AccessRights);
	return AccessRights.DescriptorPrivilegeLevel;
}
void VmmpHandleRdtsc(PVMEXIT_CONTEXT ExitContext) 
{
	ULARGE_INTEGER tsc;
	tsc.QuadPart = __rdtsc();
	ExitContext->GuestContext->GuestRAX = tsc.LowPart;
	ExitContext->GuestContext->GuestRDX = tsc.HighPart;
	VmmpAdjustGuestInstructionPointer(ExitContext);
}
void VmmpHandleVmCallTermination(PVMEXIT_CONTEXT guest_context) {
	// The processor sets ffff to limits of IDT and GDT when VM-exit occurred.
	// It is not correct value but fine to ignore since vmresume loads correct
	// values from VMCS. But here, we are going to skip vmresume and simply
	// return to where VMCALL is executed. It results in keeping those broken
	// values and ends up with bug check 109, so we should fix them manually.
	size_t gdt_limit, gdt_base, idt_limit, idt_base, exit_instruction_length;
	__vmx_vmread(static_cast<size_t>(VMCS_GUEST_GDTR_LIMIT), &gdt_limit);
	__vmx_vmread(static_cast<size_t>(VMCS_GUEST_GDTR_BASE), &gdt_base);
	__vmx_vmread(static_cast<size_t>(VMCS_GUEST_IDTR_LIMIT), &idt_limit);
	__vmx_vmread(static_cast<size_t>(VMCS_GUEST_IDTR_BASE), &idt_base);


	Gdtr gdtr = { static_cast<USHORT>(gdt_limit), gdt_base };
	Idtr idtr = { static_cast<USHORT>(idt_limit), idt_base };
	__lgdt(&gdtr);
	__lidt(&idtr);
	auto context = reinterpret_cast<void*>(guest_context->GuestContext->GuestRDX);
	// Store an address of the management structure to the context parameter
	/*const auto result_ptr = static_cast<ProcessorData**>(context);
	*result_ptr = guest_context->GuestContext->processor_data;*/
	//HYPERPLATFORM_LOG_DEBUG_SAFE("Context at %p %p", context,guest_context->stack->processor_data);

	// Set rip to the next instruction of VMCALL
	__vmx_vmread(static_cast<size_t>(VMCS_VMEXIT_INSTRUCTION_LENGTH), &exit_instruction_length);
	const auto return_address = guest_context->GuestRIP + exit_instruction_length;

	// Since the flag register is overwritten after VMXOFF, we should manually
	// indicates that VMCALL was successful by clearing those flags.
	// See: CONVENTIONS
	guest_context->GuestFlags.EFLAGS.CarryFlag = false;
	guest_context->GuestFlags.EFLAGS.ParityFlag = false;
	guest_context->GuestFlags.EFLAGS.AuxiliaryCarryFlag = false;
	guest_context->GuestFlags.EFLAGS.ZeroFlag = false;
	guest_context->GuestFlags.EFLAGS.SignFlag = false;
	guest_context->GuestFlags.EFLAGS.OverflowFlag = false;
	guest_context->GuestFlags.EFLAGS.CarryFlag = false;
	guest_context->GuestFlags.EFLAGS.ZeroFlag = false;

	// Set registers used after VMXOFF to recover the context. Volatile
	// registers must be used because those changes are reflected to the
	// guest's context after VMXOFF.
	guest_context->GuestContext->GuestRCX = return_address;
	guest_context->GuestContext->GuestRDX = guest_context->GuestContext->GuestRSP;
	guest_context->GuestContext->GuestRAX = guest_context->GuestFlags.RFLAGS;
	guest_context->ShouldStopExecution = false;
}
bool ExitDispatchFunction(PVMEXIT_CONTEXT ExitContext)
{
	SIZE_T GuestInstructionLength = 0;
	//Log("BasicExitReason:%p", ExitContext->ExitReason.BasicExitReason);
	switch (ExitContext->ExitReason.BasicExitReason)
	{
	case VMX_EXIT_REASON_EXCEPTION_OR_NMI: 
	{
		VMEXIT_INTERRUPT_INFORMATION Exception = { 0 };
		Exception.Flags = 0;
		__vmx_vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION, (size_t*)&Exception);
		if (Exception.Vector == 2 && Exception.InterruptionType == 2)
			SetNmiExiting(ExitContext, true);
		ExitContext->ShouldIncrementRIP = false;
		break;
	}
	case VMX_EXIT_REASON_NMI_WINDOW:
		SetNmiExiting(ExitContext, false);
		InjectInterruption(INTERRUPTION_TYPE::NonMaskableInterrupt, EXCEPTION_VECTOR::Nmi, false, 0);
		ExitContext->ShouldIncrementRIP = false;
		break;
	case VMX_EXIT_REASON_EXECUTE_VMCLEAR:
		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::InvalidOpcode, false, 0);
		ExitContext->ShouldIncrementRIP = false;
		break;
	case VMX_EXIT_REASON_EXECUTE_VMPTRLD:
		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::InvalidOpcode, false, 0);
		ExitContext->ShouldIncrementRIP = false;
		break;
	case VMX_EXIT_REASON_EXECUTE_VMPTRST:
		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::InvalidOpcode, false, 0);
		ExitContext->ShouldIncrementRIP = false;
		break;
	case VMX_EXIT_REASON_EXECUTE_VMREAD:
		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::InvalidOpcode, false, 0);
		ExitContext->ShouldIncrementRIP = false;
		break;
	case VMX_EXIT_REASON_EXECUTE_VMRESUME:
		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::InvalidOpcode, false, 0);
		ExitContext->ShouldIncrementRIP = false;
		break;
	case VMX_EXIT_REASON_EXECUTE_VMWRITE:
		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::InvalidOpcode, false, 0);
		ExitContext->ShouldIncrementRIP = false;
		break;
	case VMX_EXIT_REASON_EXECUTE_VMXON:
		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::InvalidOpcode, false, 0);
		ExitContext->ShouldIncrementRIP = false;
		break;
	case VMX_EXIT_REASON_EXECUTE_VMXOFF:
		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::InvalidOpcode, false, 0);
		ExitContext->ShouldIncrementRIP = false;
		break;
	case VMX_EXIT_REASON_EXECUTE_VMLAUNCH:
		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::InvalidOpcode, false, 0);
		ExitContext->ShouldIncrementRIP = false;
		break;
	case VMX_EXIT_REASON_EXECUTE_INVEPT:
		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::InvalidOpcode, false, 0);
		ExitContext->ShouldIncrementRIP = false;
		break;
	case VMX_EXIT_REASON_EXECUTE_INVVPID:
		InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::InvalidOpcode, false, 0);
		ExitContext->ShouldIncrementRIP = false;
		break;
	case VMX_EXIT_REASON_TRIPLE_FAULT:
		KeBugCheck(0x2);
		break;
	case VMX_EXIT_REASON_EXECUTE_RDTSC:
		VmmpHandleRdtsc(ExitContext);
		break;
	case VMX_EXIT_REASON_EXECUTE_RDTSCP:
		ExitHandleRdtscp(ExitContext);
		break;
	case VMX_EXIT_REASON_EXECUTE_CPUID:
		ExitHandleCPUID(ExitContext);
		break;
	case VMX_EXIT_REASON_EXECUTE_INVD:
		__wbinvd();
		VmmpAdjustGuestInstructionPointer(ExitContext);
		break;
	case VMX_EXIT_REASON_EXECUTE_XSETBV:
		ExitHandleXsetbv(ExitContext);
		break;
	case VMX_EXIT_REASON_EXECUTE_RDMSR:
		ExitHandleMSRAccess(ExitContext, true);
		break;
	case VMX_EXIT_REASON_EXECUTE_WRMSR:
		ExitHandleMSRAccess(ExitContext, false);
		break;
	case VMX_EXIT_REASON_EPT_MISCONFIGURATION:
		KeBugCheck(0x666666);
		break;
	case VMX_EXIT_REASON_EPT_VIOLATION:
		ExitHandleEPTViolation(ExitContext);
		break;
	case VMX_EXIT_REASON_EXECUTE_INVLPG:
		ExitHandleInvlpg(ExitContext);
		break;
	case VMX_EXIT_REASON_MONITOR_TRAP_FLAG:
		KeBugCheck(0x25);
		break;
	case VMX_EXIT_REASON_EXECUTE_VMCALL:
		if (VmmpGetGuestCpl() != 0) {
			InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::InvalidOpcode, false, 0);
			ExitContext->ShouldIncrementRIP = false;
			break;
		}
		ExitHandleExitVT(ExitContext);
		/*if (ExitContext->GuestContext->GuestRCX == 12)
		{
			VmmpHandleVmCallTermination(ExitContext);
		}*/
		if (ExitContext->GuestContext->GuestRCX == CallExitVT)
			ExitHandleExitVT(ExitContext);
		else {
			InjectInterruption(INTERRUPTION_TYPE::HardwareException, EXCEPTION_VECTOR::InvalidOpcode, false, 0);
			ExitContext->ShouldIncrementRIP = false;
		}
		break;
	case VMX_EXIT_REASON_MOV_CR:
		ExitHandleCRAccess(ExitContext);
		break;
	case VMX_EXIT_REASON_MOV_DR:
		ExitHandleDRAccess(ExitContext);
		break;
	default:
		ExitHandleUnknownExit(ExitContext);
		break;
	}
	if (ExitContext->ShouldStopExecution)
		return false;
	if (ExitContext->ShouldIncrementRIP)
	{
		__vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &GuestInstructionLength);
		__vmx_vmwrite(VMCS_GUEST_RIP, ExitContext->GuestRIP + GuestInstructionLength);
	}
	return true;
}

extern "C" bool HandleVmExitFailure(PGPREGISTER_CONTEXT GuestRegisters)
{
	UNREFERENCED_PARAMETER(GuestRegisters);
	KeBugCheck(0x7777777);
}

extern "C" bool HandleVmExit(PGPREGISTER_CONTEXT GuestRegisters)
{
	VMEXIT_CONTEXT ExitContext;
	bool Reulst = false;

	RtlZeroMemory(&ExitContext, sizeof(VMEXIT_CONTEXT));
	ExitContext.GuestContext = GuestRegisters;
	ExitContext.ShouldIncrementRIP = true;
	ExitContext.ShouldStopExecution = false;
	__vmx_vmread(VMCS_GUEST_RSP, &ExitContext.GuestContext->GuestRSP);
	__vmx_vmread(VMCS_GUEST_RIP, &ExitContext.GuestRIP);
	__vmx_vmread(VMCS_GUEST_RFLAGS, &ExitContext.GuestFlags.RFLAGS);
	__vmx_vmread(VMCS_EXIT_QUALIFICATION, &ExitContext.ExitQualification);
	__vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &ExitContext.InstructionLength);
	__vmx_vmread(VMCS_VMEXIT_INSTRUCTION_INFO, &ExitContext.InstructionInformation);
	__vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &ExitContext.GuestPhysicalAddress);
	__vmx_vmread(VMCS_EXIT_REASON, &ExitContext.ExitReason.Flags);

	if (ExitContext.ExitReason.VmEntryFailure == 1)
		return false;

	ExitContext.SavedIRQL = KeGetCurrentIrql();
	if (ExitContext.SavedIRQL < DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();

	Reulst = ExitDispatchFunction(&ExitContext);

	if (ExitContext.SavedIRQL < DISPATCH_LEVEL)
		KeLowerIrql(ExitContext.SavedIRQL);

	return Reulst;
}
