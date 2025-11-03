#include <ntifs.h>
#include <intrin.h>
#include "VMX.hpp"
#include "VMExit.hpp"
#include "EPT.hpp"
#include "Memory.hpp"
#include "../Global/Global.hpp"
#include "../Common/Common.hpp"

extern "C"
{
	void _sgdt(void*);
	bool __fastcall ASM_Install_VMCS(PVOID RCX, ULONG index);
	void __fastcall AsmVmxCall(ULONG_PTR num, ULONG_PTR param);
	void EnterFromGuest();
	void CaptureContext(PREGISTER_CONTEXT RegisterContext);
	SEGMENT_SELECTOR ReadTaskRegister();
	SEGMENT_SELECTOR ReadLocalDescriptorTableRegister();
}

void UtilInveptGlobal();
void UtilInvvpidAllContext();

SIZE_T UtilEncodeMustBeBits(SIZE_T DesiredValue, SIZE_T ControlMSR)
{
	LARGE_INTEGER ControlMSRLargeInteger;
	ControlMSRLargeInteger.QuadPart = ControlMSR;
	DesiredValue &= ControlMSRLargeInteger.HighPart;
	DesiredValue |= ControlMSRLargeInteger.LowPart;
	return DesiredValue;
}

bool CheckVTSupport()
{
	int ctx[4] = { 0 };
	__cpuidex(ctx, 0x1, 0);
	if ((ctx[2] & (0x1 << 0x5)) == 0)
		return false;
	return true;
}

bool CheckVTEnable()
{
	ULONG_PTR msr;
	msr = __readmsr(IA32_FEATURE_CONTROL);
	if ((msr & 0x1) == 0)
		return false;
	return true;
}

bool ExecuteVMXON(ULONG index)
{
	*(ULONG*)Global::g_IntelVmx[index].VMX_Region = (ULONG)__readmsr(IA32_VMX_BASIC);
	*(ULONG*)Global::g_IntelVmx[index].VMCS_Region = (ULONG)__readmsr(IA32_VMX_BASIC);

	CR4 Register;
	Register.Flags = __readcr4();
	Register.VmxEnable = 1;
	__writecr4(Register.Flags);
	Register.Flags = __readcr4();

	CR0 ControlRegister0;
	CR4 ControlRegister4;
	ControlRegister0.Flags = __readcr0();
	ControlRegister4.Flags = __readcr4();
	ControlRegister0.Flags |= __readmsr(IA32_VMX_CR0_FIXED0);
	ControlRegister0.Flags &= __readmsr(IA32_VMX_CR0_FIXED1);
	ControlRegister4.Flags |= __readmsr(IA32_VMX_CR4_FIXED0);
	ControlRegister4.Flags &= __readmsr(IA32_VMX_CR4_FIXED1);
	__writecr0(ControlRegister0.Flags);
	__writecr4(ControlRegister4.Flags);

	ULONG_PTR VMX_PhysicalAddress = MmGetPhysicalAddress((PVOID)Global::g_IntelVmx[index].VMX_Region).QuadPart;
	if (__vmx_on(&VMX_PhysicalAddress))
		return false;

	ULONG_PTR VMCS_PhysicalAddress = MmGetPhysicalAddress((PVOID)Global::g_IntelVmx[index].VMCS_Region).QuadPart;

	if (__vmx_vmclear(&VMCS_PhysicalAddress))
		return false;

	if (__vmx_vmptrld(&VMCS_PhysicalAddress))
		return false;
	return true;
}

void ExitVMXON(ULONG index)
{
	Common::FreeMemory((PVOID)Global::g_IntelVmx[index].VMX_Region, true);
	Common::FreeMemory((PVOID)Global::g_IntelVmx[index].VMCS_Region, true);
	Common::FreeMemory((PVOID)Global::g_IntelVmx[index].MSRBitMap, true);
	Common::FreeMemory((PVOID)Global::g_IntelVmx[index].VMMStack, true);
}

void VmxGetSegmentDescriptorFromSelector(PVMX_SEGMENT_DESCRIPTOR VmxSegmentDescriptor, SEGMENT_DESCRIPTOR_REGISTER_64 GdtRegister, SEGMENT_SELECTOR SegmentSelector, bool ClearRPL)
{
	PSEGMENT_DESCRIPTOR_64 OsSegmentDescriptor;
	RtlZeroMemory(VmxSegmentDescriptor, sizeof(VMX_SEGMENT_DESCRIPTOR));
	if (SegmentSelector.Flags == 0 || SegmentSelector.Table != 0)
	{
		VmxSegmentDescriptor->AccessRights.Unusable = 1;
		return;
	}
	OsSegmentDescriptor = (PSEGMENT_DESCRIPTOR_64)(((UINT64)GdtRegister.BaseAddress) + ((UINT64)SegmentSelector.Index << 3));
	VmxSegmentDescriptor->BaseAddress = (OsSegmentDescriptor->BaseAddressHigh << 24) | (OsSegmentDescriptor->BaseAddressMiddle << 16) | (OsSegmentDescriptor->BaseAddressLow);
	VmxSegmentDescriptor->BaseAddress &= 0xFFFFFFFF;
	if (OsSegmentDescriptor->DescriptorType == 0)
		VmxSegmentDescriptor->BaseAddress |= ((UINT64)OsSegmentDescriptor->BaseAddressUpper << 32);
	VmxSegmentDescriptor->SegmentLimit = __segmentlimit(SegmentSelector.Flags);
	if (ClearRPL)
		SegmentSelector.RequestPrivilegeLevel = 0;
	VmxSegmentDescriptor->Selector = SegmentSelector.Flags;
	VmxSegmentDescriptor->AccessRights.Type = OsSegmentDescriptor->Type;
	VmxSegmentDescriptor->AccessRights.DescriptorType = OsSegmentDescriptor->DescriptorType;
	VmxSegmentDescriptor->AccessRights.DescriptorPrivilegeLevel = OsSegmentDescriptor->DescriptorPrivilegeLevel;
	VmxSegmentDescriptor->AccessRights.Present = OsSegmentDescriptor->Present;
	VmxSegmentDescriptor->AccessRights.AvailableBit = OsSegmentDescriptor->System;
	VmxSegmentDescriptor->AccessRights.LongMode = OsSegmentDescriptor->LongMode;
	VmxSegmentDescriptor->AccessRights.DefaultBig = OsSegmentDescriptor->DefaultBig;
	VmxSegmentDescriptor->AccessRights.Granularity = OsSegmentDescriptor->Granularity;
	VmxSegmentDescriptor->AccessRights.Unusable = 0;
}

extern "C" void __fastcall Install_VMCS(SIZE_T GuestRSP, SIZE_T GuestRIP, ULONG index)
{
	REGISTER_CONTEXT InitialRegisters = { 0 };
	IA32_SPECIAL_REGISTERS InitialSpecialRegisters = { 0 };
	CaptureContext(&InitialRegisters);
	InitialSpecialRegisters.ControlRegister0.Flags = __readcr0();
	InitialSpecialRegisters.ControlRegister3.Flags = __readcr3();
	InitialSpecialRegisters.ControlRegister4.Flags = __readcr4();
	InitialSpecialRegisters.ControlRegister4.OsXsave = 1;
	_sgdt(&InitialSpecialRegisters.GlobalDescriptorTableRegister.Limit);
	__sidt(&InitialSpecialRegisters.InterruptDescriptorTableRegister.Limit);
	InitialSpecialRegisters.TaskRegister = ReadTaskRegister();
	InitialSpecialRegisters.LocalDescriptorTableRegister = ReadLocalDescriptorTableRegister();
	InitialSpecialRegisters.DebugRegister7.Flags = __readdr(7);
	InitialSpecialRegisters.RflagsRegister.Flags = (UINT32)__readeflags();
	InitialSpecialRegisters.DebugControlMsr.Flags = __readmsr(IA32_DEBUGCTL);
	InitialSpecialRegisters.SysenterCsMsr.Flags = __readmsr(IA32_SYSENTER_CS);
	InitialSpecialRegisters.SysenterEspMsr = __readmsr(IA32_SYSENTER_ESP);
	InitialSpecialRegisters.SysenterEipMsr = __readmsr(IA32_SYSENTER_EIP);
	InitialSpecialRegisters.GlobalPerfControlMsr = __readmsr(IA32_PERF_GLOBAL_CTRL);
	InitialSpecialRegisters.PatMsr.Flags = __readmsr(IA32_PAT);
	InitialSpecialRegisters.EferMsr.Flags = __readmsr(IA32_EFER);

	__vmx_vmwrite(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER, (size_t)KeGetCurrentProcessorNumberEx(nullptr) + 1);
	__vmx_vmwrite(VMCS_CTRL_MSR_BITMAP_ADDRESS, (SIZE_T)MmGetPhysicalAddress((PVOID)Global::g_IntelVmx[index].MSRBitMap).QuadPart);
	__vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, InitialSpecialRegisters.ControlRegister0.Flags);
	__vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, InitialSpecialRegisters.ControlRegister4.Flags);
	__vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, 0);
	__vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, 0);
	__vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);
	__vmx_vmwrite(VMCS_CTRL_CR3_TARGET_COUNT, 0);
	__vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
	__vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);
	__vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, 0);
	__vmx_vmwrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0);
	__vmx_vmwrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, 0);

	//// -----------------------------------------------------------------------

	__vmx_vmwrite(VMCS_GUEST_CR0, InitialSpecialRegisters.ControlRegister0.Flags);
	__vmx_vmwrite(VMCS_GUEST_CR3, InitialSpecialRegisters.ControlRegister3.Flags);
	__vmx_vmwrite(VMCS_GUEST_CR4, InitialSpecialRegisters.ControlRegister4.Flags);
	__vmx_vmwrite(VMCS_GUEST_DR7, InitialSpecialRegisters.DebugRegister7.Flags);
	__vmx_vmwrite(VMCS_GUEST_RFLAGS, InitialSpecialRegisters.RflagsRegister.Flags);
	__vmx_vmwrite(VMCS_GUEST_RIP, GuestRIP);
	__vmx_vmwrite(VMCS_GUEST_RSP, GuestRSP);

	SEGMENT_DESCRIPTOR_REGISTER_64 GdtRegister = { 0 };
	VMX_SEGMENT_DESCRIPTOR SegmentDescriptor = { 0 };
	GdtRegister = InitialSpecialRegisters.GlobalDescriptorTableRegister;

	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, InitialRegisters.SegES, false);
	__vmx_vmwrite(VMCS_GUEST_ES_SELECTOR, SegmentDescriptor.Selector);
	__vmx_vmwrite(VMCS_GUEST_ES_BASE, SegmentDescriptor.BaseAddress);
	__vmx_vmwrite(VMCS_GUEST_ES_LIMIT, SegmentDescriptor.SegmentLimit);
	__vmx_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS, SegmentDescriptor.AccessRights.Flags);

	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, InitialRegisters.SegCS, false);
	__vmx_vmwrite(VMCS_GUEST_CS_SELECTOR, SegmentDescriptor.Selector);
	__vmx_vmwrite(VMCS_GUEST_CS_BASE, SegmentDescriptor.BaseAddress);
	__vmx_vmwrite(VMCS_GUEST_CS_LIMIT, SegmentDescriptor.SegmentLimit);
	__vmx_vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS, SegmentDescriptor.AccessRights.Flags);

	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, InitialRegisters.SegSS, false);
	__vmx_vmwrite(VMCS_GUEST_SS_SELECTOR, SegmentDescriptor.Selector);
	__vmx_vmwrite(VMCS_GUEST_SS_BASE, SegmentDescriptor.BaseAddress);
	__vmx_vmwrite(VMCS_GUEST_SS_LIMIT, SegmentDescriptor.SegmentLimit);
	__vmx_vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS, SegmentDescriptor.AccessRights.Flags);

	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, InitialRegisters.SegDS, false);
	__vmx_vmwrite(VMCS_GUEST_DS_SELECTOR, SegmentDescriptor.Selector);
	__vmx_vmwrite(VMCS_GUEST_DS_BASE, SegmentDescriptor.BaseAddress);
	__vmx_vmwrite(VMCS_GUEST_DS_LIMIT, SegmentDescriptor.SegmentLimit);
	__vmx_vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS, SegmentDescriptor.AccessRights.Flags);

	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, InitialRegisters.SegGS, false);
	__vmx_vmwrite(VMCS_GUEST_GS_SELECTOR, SegmentDescriptor.Selector);
	__vmx_vmwrite(VMCS_GUEST_GS_BASE, SegmentDescriptor.BaseAddress);
	__vmx_vmwrite(VMCS_GUEST_GS_LIMIT, SegmentDescriptor.SegmentLimit);
	__vmx_vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS, SegmentDescriptor.AccessRights.Flags);

	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, InitialRegisters.SegFS, false);
	__vmx_vmwrite(VMCS_GUEST_FS_SELECTOR, SegmentDescriptor.Selector);
	__vmx_vmwrite(VMCS_GUEST_FS_BASE, SegmentDescriptor.BaseAddress);
	__vmx_vmwrite(VMCS_GUEST_FS_LIMIT, SegmentDescriptor.SegmentLimit);
	__vmx_vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS, SegmentDescriptor.AccessRights.Flags);

	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, InitialSpecialRegisters.LocalDescriptorTableRegister, false);
	__vmx_vmwrite(VMCS_GUEST_LDTR_SELECTOR, SegmentDescriptor.Selector);
	__vmx_vmwrite(VMCS_GUEST_LDTR_BASE, SegmentDescriptor.BaseAddress);
	__vmx_vmwrite(VMCS_GUEST_LDTR_LIMIT, SegmentDescriptor.SegmentLimit);
	__vmx_vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, SegmentDescriptor.AccessRights.Flags);

	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, InitialSpecialRegisters.TaskRegister, false);
	__vmx_vmwrite(VMCS_GUEST_TR_SELECTOR, SegmentDescriptor.Selector);
	__vmx_vmwrite(VMCS_GUEST_TR_BASE, SegmentDescriptor.BaseAddress);
	__vmx_vmwrite(VMCS_GUEST_TR_LIMIT, SegmentDescriptor.SegmentLimit);
	__vmx_vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, SegmentDescriptor.AccessRights.Flags);

	__vmx_vmwrite(VMCS_GUEST_GS_BASE, __readmsr(IA32_GS_BASE));
	__vmx_vmwrite(VMCS_GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
	__vmx_vmwrite(VMCS_GUEST_GDTR_BASE, InitialSpecialRegisters.GlobalDescriptorTableRegister.BaseAddress);
	__vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, InitialSpecialRegisters.GlobalDescriptorTableRegister.Limit);
	__vmx_vmwrite(VMCS_GUEST_IDTR_BASE, InitialSpecialRegisters.InterruptDescriptorTableRegister.BaseAddress);
	__vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, InitialSpecialRegisters.InterruptDescriptorTableRegister.Limit);
	__vmx_vmwrite(VMCS_GUEST_DEBUGCTL, InitialSpecialRegisters.DebugControlMsr.Flags);
	__vmx_vmwrite(VMCS_GUEST_SYSENTER_CS, InitialSpecialRegisters.SysenterCsMsr.Flags);
	__vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, InitialSpecialRegisters.SysenterEipMsr);
	__vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, InitialSpecialRegisters.SysenterEspMsr);
	__vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0);
	__vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, 0);
	__vmx_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, 0);
	__vmx_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0ULL);

	__vmx_vmwrite(VMCS_CTRL_EPT_POINTER, EPT::g_EPTData.EPTPointer.Flags);

	// -----------------------------------------------------------------------------

	__vmx_vmwrite(VMCS_HOST_CR0, InitialSpecialRegisters.ControlRegister0.Flags);
	__vmx_vmwrite(VMCS_HOST_CR3, Global::g_pSysRotineAddr.CsrssCR3);  // 这里CR3EPTCR3
	__vmx_vmwrite(VMCS_HOST_CR4, InitialSpecialRegisters.ControlRegister4.Flags);

	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, InitialRegisters.SegCS, true);
	__vmx_vmwrite(VMCS_HOST_CS_SELECTOR, SegmentDescriptor.Selector);

	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, InitialRegisters.SegSS, true);
	__vmx_vmwrite(VMCS_HOST_SS_SELECTOR, SegmentDescriptor.Selector);

	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, InitialRegisters.SegDS, true);
	__vmx_vmwrite(VMCS_HOST_DS_SELECTOR, SegmentDescriptor.Selector);

	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, InitialRegisters.SegES, true);
	__vmx_vmwrite(VMCS_HOST_ES_SELECTOR, SegmentDescriptor.Selector);

	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, InitialRegisters.SegFS, true);
	__vmx_vmwrite(VMCS_HOST_FS_SELECTOR, SegmentDescriptor.Selector);
	__vmx_vmwrite(VMCS_HOST_FS_BASE, SegmentDescriptor.BaseAddress);

	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, InitialRegisters.SegGS, true);
	__vmx_vmwrite(VMCS_HOST_GS_SELECTOR, SegmentDescriptor.Selector);
	__vmx_vmwrite(VMCS_HOST_GS_BASE, SegmentDescriptor.BaseAddress);

	VmxGetSegmentDescriptorFromSelector(&SegmentDescriptor, GdtRegister, InitialSpecialRegisters.TaskRegister, true);
	__vmx_vmwrite(VMCS_HOST_TR_SELECTOR, SegmentDescriptor.Selector);
	__vmx_vmwrite(VMCS_HOST_TR_BASE, SegmentDescriptor.BaseAddress);

	__vmx_vmwrite(VMCS_HOST_GS_BASE, __readmsr(IA32_GS_BASE));
	__vmx_vmwrite(VMCS_HOST_FS_BASE, __readmsr(IA32_FS_BASE));
	__vmx_vmwrite(VMCS_HOST_GDTR_BASE, InitialSpecialRegisters.GlobalDescriptorTableRegister.BaseAddress);
	__vmx_vmwrite(VMCS_HOST_IDTR_BASE, InitialSpecialRegisters.InterruptDescriptorTableRegister.BaseAddress);
	__vmx_vmwrite(VMCS_HOST_SYSENTER_CS, InitialSpecialRegisters.SysenterCsMsr.Flags);
	__vmx_vmwrite(VMCS_HOST_SYSENTER_ESP, InitialSpecialRegisters.SysenterEspMsr);
	__vmx_vmwrite(VMCS_HOST_SYSENTER_EIP, InitialSpecialRegisters.SysenterEipMsr);

	IA32_VMX_BASIC_REGISTER VMX_Basic_Register = { 0 };
	VMX_Basic_Register.Flags = __readmsr(IA32_VMX_BASIC);

	IA32_VMX_PINBASED_CTLS_REGISTER VMX_PINBASED_Register = { 0 };
	SIZE_T ConfigMSR;
	VMX_PINBASED_Register.Flags = 0;
	VMX_PINBASED_Register.NmiExiting = true;
	VMX_PINBASED_Register.VirtualNmi = true;
	if (VMX_Basic_Register.VmxControls == 1)
		ConfigMSR = __readmsr(IA32_VMX_TRUE_PINBASED_CTLS);
	else
		ConfigMSR = __readmsr(IA32_VMX_PINBASED_CTLS);
	VMX_PINBASED_Register.Flags = UtilEncodeMustBeBits(VMX_PINBASED_Register.Flags, ConfigMSR);
	__vmx_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, VMX_PINBASED_Register.Flags);


	IA32_VMX_PROCBASED_CTLS_REGISTER VMX_PROCBASED_Register = { 0 };
	VMX_PROCBASED_Register.Flags = 0;
	VMX_PROCBASED_Register.ActivateSecondaryControls = 1;
	VMX_PROCBASED_Register.UseMsrBitmaps = 1;
	if (VMX_Basic_Register.VmxControls == 1)
		ConfigMSR = __readmsr(IA32_VMX_TRUE_PROCBASED_CTLS);
	else
		ConfigMSR = __readmsr(IA32_VMX_PROCBASED_CTLS);
	VMX_PROCBASED_Register.Flags = UtilEncodeMustBeBits(VMX_PROCBASED_Register.Flags, ConfigMSR);
	__vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, VMX_PROCBASED_Register.Flags);

	IA32_VMX_EXIT_CTLS_REGISTER VMX_EXIT_Register = { 0 };
	VMX_EXIT_Register.Flags = 0;
	VMX_EXIT_Register.HostAddressSpaceSize = 1;
	VMX_EXIT_Register.SaveDebugControls = 1;

	if (VMX_Basic_Register.VmxControls == 1)
		ConfigMSR = __readmsr(IA32_VMX_TRUE_EXIT_CTLS);
	else
		ConfigMSR = __readmsr(IA32_VMX_EXIT_CTLS);
	VMX_EXIT_Register.Flags = UtilEncodeMustBeBits(VMX_EXIT_Register.Flags, ConfigMSR);
	__vmx_vmwrite(VMCS_CTRL_VMEXIT_CONTROLS, VMX_EXIT_Register.Flags);

	IA32_VMX_ENTRY_CTLS_REGISTER VMX_ENTRY_Register = { 0 };
	VMX_ENTRY_Register.Flags = 0;
	VMX_ENTRY_Register.Ia32EModeGuest = 1;
	VMX_ENTRY_Register.LoadDebugControls = 1;
	if (VMX_Basic_Register.VmxControls == 1)
		ConfigMSR = __readmsr(IA32_VMX_TRUE_ENTRY_CTLS);
	else
		ConfigMSR = __readmsr(IA32_VMX_ENTRY_CTLS);
	VMX_ENTRY_Register.Flags = UtilEncodeMustBeBits(VMX_ENTRY_Register.Flags, ConfigMSR);
	__vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, VMX_ENTRY_Register.Flags);

	IA32_VMX_PROCBASED_CTLS2_REGISTER VMX_PROCBASED2_Register = { 0 };
	VMX_PROCBASED2_Register.Flags = 0;
	VMX_PROCBASED2_Register.EnableEpt = 1; //EPT 是否开启
	VMX_PROCBASED2_Register.EnableRdtscp = 1;
	VMX_PROCBASED2_Register.EnableVpid = 1; //是否拦截 vpid
	VMX_PROCBASED2_Register.EnableInvpcid = 1;
	VMX_PROCBASED2_Register.EnableXsaves = 1;
	//VMX_PROCBASED2_Register.UseTscScaling = 1;

	ConfigMSR = __readmsr(IA32_VMX_PROCBASED_CTLS2);
	VMX_PROCBASED2_Register.Flags = UtilEncodeMustBeBits(VMX_PROCBASED2_Register.Flags, ConfigMSR);
	__vmx_vmwrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, VMX_PROCBASED2_Register.Flags);

	//ULONG64 target_ratio_fraction = (ULONG64)(0.4 * (1ULL << 48));  // 调整 0.4 根据测试（例如 0.3-0.5）。
	//__vmx_vmwrite(VMCS_CTRL_TSC_MULTIPLIER, target_ratio_fraction);


	__vmx_vmwrite(VMCS_HOST_RIP, (SIZE_T)EnterFromGuest);  //vmlaunch 进入HOST    EnterFromGuest
	__vmx_vmwrite(VMCS_HOST_RSP, (SIZE_T)Global::g_IntelVmx[index].VMMStack + VMM_STACK_SIZE - PAGE_SIZE); //VMM Stack

	__vmx_vmlaunch();
	UtilInveptGlobal();
	UtilInvvpidAllContext();

	//失败了
	ULONG_PTR ErrorCode = 0; //错误代码
	if (__vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &ErrorCode) != 0)
		return;
}

extern "C" void DPCVmxInstallCallBack(_In_ struct _KDPC* Dpc, _In_opt_ PVOID DeferredContext, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);

	ULONG index = KeGetCurrentProcessorIndex();

	Global::g_IntelVmx[index].VMX_Region = (ULONG_PTR)Common::AllocateMemory(PAGE_SIZE,true);
	Global::g_IntelVmx[index].VMCS_Region = (ULONG_PTR)Common::AllocateMemory(PAGE_SIZE,true);
	Global::g_IntelVmx[index].MSRBitMap = (ULONG_PTR)Common::AllocateMemory(PAGE_SIZE, true);
	Global::g_IntelVmx[index].VMMStack = (PUCHAR)Common::AllocateMemory(VMM_STACK_SIZE, true);


	if (!ExecuteVMXON(index))
		return;

	ASM_Install_VMCS(&Install_VMCS, index);

	if (SystemArgument2)
		KeSignalCallDpcSynchronize(SystemArgument2);
	if (SystemArgument1)
		KeSignalCallDpcDone(SystemArgument1);
}


bool IntelVMX::InstallVmx()
{
	if (!CheckVTSupport())
		return false;

	if (!CheckVTEnable())
		return false;

	ULONG ProcessCount = KeQueryActiveProcessorCount(0);

	Global::g_IntelVmx = (pIntelVmx)Common::AllocateMemory(sizeof(IntelVmx) * ProcessCount, false);

	EPT::g_PhysicalMemoryRanges = EPT::BuildPhysicalMemoryRanges();

	EPT::EPTInitializeMTRREntries(); //初始化MTRR

	EPT::g_EPTData = EPT::EPTInitialization();

	KeGenericCallDpc(DPCVmxInstallCallBack, NULL);

	InitMemory();

	return true;
}
