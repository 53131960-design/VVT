#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#pragma warning(disable:4200)
#pragma warning(disable:4201)

typedef signed char         INT8, * PINT8;
typedef signed short        INT16, * PINT16;
typedef signed int          INT32, * PINT32;
typedef signed __int64      INT64, * PINT64;
typedef unsigned char       UINT8, * PUINT8;
typedef unsigned short      UINT16, * PUINT16;
typedef unsigned int        UINT32, * PUINT32;
typedef unsigned __int64    UINT64, * PUINT64;

typedef INT8   int8_t;
typedef INT16  int16_t;
typedef INT32  int32_t;
typedef INT64  int64_t;
typedef UINT8  uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;

#define _BYTE  UCHAR
#define _WORD  USHORT
#define _DWORD ULONG
#define _QWORD ULONG64

#define MM_COPY_MEMORY_PHYSICAL             0x1
#define MM_COPY_MEMORY_VIRTUAL              0x2

#define MEM_IMAGE                   0x01000000  

#define PTE_SHIFT 3
#define PTI_SHIFT 12
#define PDI_SHIFT 21
#define PPI_SHIFT 30
#define PXI_SHIFT 39

#define VIRTUAL_ADDRESS_BITS 48
#define DUMP_BLOCK_SIZE 0x40000
#define PHYSICAL_ADDRESS_BITS 40
#define KDDEBUGGER_DATA_OFFSET 0x2080


#define VIRTUAL_ADDRESS_MASK ((((ULONG_PTR)1) << VIRTUAL_ADDRESS_BITS) - 1)

#define MiGetPdeAddress(va) \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PDI_SHIFT) << PTE_SHIFT) + PDE_BASE))

#define MiGetPteAddress(va) \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PTI_SHIFT) << PTE_SHIFT) + PTE_BASE))

#define VMM_STACK_SIZE                   10 * PAGE_SIZE

EXTERN_C NTKERNELAPI _IRQL_requires_(DISPATCH_LEVEL) _IRQL_requires_same_ VOID KeSignalCallDpcDone(_In_ PVOID SystemArgument1);

EXTERN_C NTKERNELAPI _IRQL_requires_(DISPATCH_LEVEL) _IRQL_requires_same_ LOGICAL KeSignalCallDpcSynchronize(_In_ PVOID SystemArgument2);

EXTERN_C NTKERNELAPI _IRQL_requires_max_(APC_LEVEL) _IRQL_requires_min_(PASSIVE_LEVEL) _IRQL_requires_same_ VOID KeGenericCallDpc(_In_ PKDEFERRED_ROUTINE Routine, _In_opt_ PVOID Context);

typedef struct _Report {
	UCHAR IPAddress[4];
	ULONG Port;
	ULONG RecvSize;
	ULONG ReportSize;
	PUCHAR RecvBuffer;
	PUCHAR ReportBuffer;
}Report, * pReport;

typedef struct _IntelVmx {
	ULONG_PTR VMX_Region;
	ULONG_PTR VMCS_Region;
	ULONG_PTR MSRBitMap;
	PUCHAR VMMStack;
}IntelVmx, * pIntelVmx;

typedef struct _DriverStruct {
	ULONG		Flags;
	HANDLE		Pid;
	ULONG64		BaseAddress;
	PVOID		Buffer;
	SIZE_T		Length;
	ULONG64     RetnData;
}DriverStruct, * pDriverStruct;

typedef struct _CallbackInfo
{
	UINT64 RetAddress;
	UINT64 Callback;
} CallbackInfo, * pCallbackInfo;

typedef struct _IopLoadDriver
{
	ULONG_PTR HookAddress;
	ULONG_PTR ReturnAddress;
}IopLoadDriver, * pIopLoadDriver;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _MYPEB
{
	union
	{
		struct dummy00
		{
			UCHAR InheritedAddressSpace;
			UCHAR ReadImageFileExecOptions;
			UCHAR BeingDebugged;
			UCHAR BitField;
		};
		PVOID dummy01;
	};

	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} MYPEB, * PMYPEB;

typedef struct _MEMORY_WORKING_SET_BLOCK
{
	ULONG_PTR Protection : 5;
	ULONG_PTR ShareCount : 3;
	ULONG_PTR Shared : 1;
	ULONG_PTR Node : 3;
#ifdef _WIN64
	ULONG_PTR VirtualPage : 52;
#else
	ULONG VirtualPage : 20;
#endif
} MEMORY_WORKING_SET_BLOCK, * PMEMORY_WORKING_SET_BLOCK;

typedef struct _MEMORY_WORKING_SET_INFORMATION
{
	ULONG_PTR NumberOfEntries;
	MEMORY_WORKING_SET_BLOCK WorkingSetInfo[1];
} MEMORY_WORKING_SET_INFORMATION, * PMEMORY_WORKING_SET_INFORMATION;


typedef struct _DBGKD_DEBUG_DATA_HEADER64 {
	//
	// Link to other blocks
	//

	LIST_ENTRY64 List;

	//
	// This is a unique tag to identify the owner of the block.
	// If your component only uses one pool tag, use it for this, too.
	//

	ULONG           OwnerTag;

	//
	// This must be initialized to the size of the data block,
	// including this structure.
	//

	ULONG           Size;
} DBGKD_DEBUG_DATA_HEADER64, * PDBGKD_DEBUG_DATA_HEADER64;

typedef struct _KDDEBUGGER_DATA64 {
	DBGKD_DEBUG_DATA_HEADER64 Header;

	ULONG64   KernBase;

	ULONG64   BreakpointWithStatus;       // address of breakpoint

	ULONG64   SavedContext;

	USHORT  ThCallbackStack;            // offset in thread data

	//
	// these values are offsets into that frame:
	//

	USHORT  NextCallback;               // saved pointer to next callback frame
	USHORT  FramePointer;               // saved frame pointer

	//
	// pad to a quad boundary
	//
	USHORT  PaeEnabled;

	//
	// Address of the kernel callout routine.
	//

	ULONG64   KiCallUserMode;             // kernel routine

	//
	// Address of the usermode entry point for callbacks.
	//

	ULONG64   KeUserCallbackDispatcher;   // address in ntdll

	//
	// Addresses of various kernel data structures and lists
	// that are of interest to the kernel debugger.
	//

	ULONG64   PsLoadedModuleList;
	ULONG64   PsActiveProcessHead;
	ULONG64   PspCidTable;

	ULONG64   ExpSystemResourcesList;
	ULONG64   ExpPagedPoolDescriptor;
	ULONG64   ExpNumberOfPagedPools;

	ULONG64   KeTimeIncrement;
	ULONG64   KeBugCheckCallbackListHead;
	ULONG64   KiBugcheckData;

	ULONG64   IopErrorLogListHead;

	ULONG64   ObpRootDirectoryObject;
	ULONG64   ObpTypeObjectType;

	ULONG64   MmSystemCacheStart;
	ULONG64   MmSystemCacheEnd;
	ULONG64   MmSystemCacheWs;

	ULONG64   MmPfnDatabase;
	ULONG64   MmSystemPtesStart;
	ULONG64   MmSystemPtesEnd;
	ULONG64   MmSubsectionBase;
	ULONG64   MmNumberOfPagingFiles;

	ULONG64   MmLowestPhysicalPage;
	ULONG64   MmHighestPhysicalPage;
	ULONG64   MmNumberOfPhysicalPages;

	ULONG64   MmMaximumNonPagedPoolInBytes;
	ULONG64   MmNonPagedSystemStart;
	ULONG64   MmNonPagedPoolStart;
	ULONG64   MmNonPagedPoolEnd;

	ULONG64   MmPagedPoolStart;
	ULONG64   MmPagedPoolEnd;
	ULONG64   MmPagedPoolInformation;
	ULONG64   MmPageSize;

	ULONG64   MmSizeOfPagedPoolInBytes;

	ULONG64   MmTotalCommitLimit;
	ULONG64   MmTotalCommittedPages;
	ULONG64   MmSharedCommit;
	ULONG64   MmDriverCommit;
	ULONG64   MmProcessCommit;
	ULONG64   MmPagedPoolCommit;
	ULONG64   MmExtendedCommit;

	ULONG64   MmZeroedPageListHead;
	ULONG64   MmFreePageListHead;
	ULONG64   MmStandbyPageListHead;
	ULONG64   MmModifiedPageListHead;
	ULONG64   MmModifiedNoWritePageListHead;
	ULONG64   MmAvailablePages;
	ULONG64   MmResidentAvailablePages;

	ULONG64   PoolTrackTable;
	ULONG64   NonPagedPoolDescriptor;

	ULONG64   MmHighestUserAddress;
	ULONG64   MmSystemRangeStart;
	ULONG64   MmUserProbeAddress;

	ULONG64   KdPrintCircularBuffer;
	ULONG64   KdPrintCircularBufferEnd;
	ULONG64   KdPrintWritePointer;
	ULONG64   KdPrintRolloverCount;

	ULONG64   MmLoadedUserImageList;

	// NT 5.1 Addition

	ULONG64   NtBuildLab;
	ULONG64   KiNormalSystemCall;

	// NT 5.0 hotfix addition

	ULONG64   KiProcessorBlock;
	ULONG64   MmUnloadedDrivers;
	ULONG64   MmLastUnloadedDriver;
	ULONG64   MmTriageActionTaken;
	ULONG64   MmSpecialPoolTag;
	ULONG64   KernelVerifier;
	ULONG64   MmVerifierData;
	ULONG64   MmAllocatedNonPagedPool;
	ULONG64   MmPeakCommitment;
	ULONG64   MmTotalCommitLimitMaximum;
	ULONG64   CmNtCSDVersion;

	// NT 5.1 Addition

	ULONG64   MmPhysicalMemoryBlock;
	ULONG64   MmSessionBase;
	ULONG64   MmSessionSize;
	ULONG64   MmSystemParentTablePage;

	// Server 2003 addition

	ULONG64   MmVirtualTranslationBase;

	USHORT    OffsetKThreadNextProcessor;
	USHORT    OffsetKThreadTeb;
	USHORT    OffsetKThreadKernelStack;
	USHORT    OffsetKThreadInitialStack;

	USHORT    OffsetKThreadApcProcess;
	USHORT    OffsetKThreadState;
	USHORT    OffsetKThreadBStore;
	USHORT    OffsetKThreadBStoreLimit;

	USHORT    SizeEProcess;
	USHORT    OffsetEprocessPeb;
	USHORT    OffsetEprocessParentCID;
	USHORT    OffsetEprocessDirectoryTableBase;

	USHORT    SizePrcb;
	USHORT    OffsetPrcbDpcRoutine;
	USHORT    OffsetPrcbCurrentThread;
	USHORT    OffsetPrcbMhz;

	USHORT    OffsetPrcbCpuType;
	USHORT    OffsetPrcbVendorString;
	USHORT    OffsetPrcbProcStateContext;
	USHORT    OffsetPrcbNumber;

	USHORT    SizeEThread;

	ULONG64   KdPrintCircularBufferPtr;
	ULONG64   KdPrintBufferSize;

	ULONG64   KeLoaderBlock;

	USHORT    SizePcr;
	USHORT    OffsetPcrSelfPcr;
	USHORT    OffsetPcrCurrentPrcb;
	USHORT    OffsetPcrContainedPrcb;

	USHORT    OffsetPcrInitialBStore;
	USHORT    OffsetPcrBStoreLimit;
	USHORT    OffsetPcrInitialStack;
	USHORT    OffsetPcrStackLimit;

	USHORT    OffsetPrcbPcrPage;
	USHORT    OffsetPrcbProcStateSpecialReg;
	USHORT    GdtR0Code;
	USHORT    GdtR0Data;

	USHORT    GdtR0Pcr;
	USHORT    GdtR3Code;
	USHORT    GdtR3Data;
	USHORT    GdtR3Teb;

	USHORT    GdtLdt;
	USHORT    GdtTss;
	USHORT    Gdt64R3CmCode;
	USHORT    Gdt64R3CmTeb;

	ULONG64   IopNumTriageDumpDataBlocks;
	ULONG64   IopTriageDumpDataBlocks;

	// Longhorn addition

	ULONG64   VfCrashDataBlock;
	ULONG64   MmBadPagesDetected;
	ULONG64   MmZeroedPageSingleBitErrorsDetected;

	// Windows 7 addition

	ULONG64   EtwpDebuggerData;
	USHORT    OffsetPrcbContext;

	// Windows 8 addition

	USHORT    OffsetPrcbMaxBreakpoints;
	USHORT    OffsetPrcbMaxWatchpoints;

	ULONG     OffsetKThreadStackLimit;
	ULONG     OffsetKThreadStackBase;
	ULONG     OffsetKThreadQueueListEntry;
	ULONG     OffsetEThreadIrpList;

	USHORT    OffsetPrcbIdleThread;
	USHORT    OffsetPrcbNormalDpcState;
	USHORT    OffsetPrcbDpcStack;
	USHORT    OffsetPrcbIsrStack;

	USHORT    SizeKDPC_STACK_FRAME;

	// Windows 8.1 Addition

	USHORT    OffsetKPriQueueThreadListHead;
	USHORT    OffsetKThreadWaitReason;

	// Windows 10 RS1 Addition

	USHORT    Padding;
	ULONG64   PteBase;

	// Windows 10 RS5 Addition

	ULONG64 RetpolineStubFunctionTable;
	ULONG RetpolineStubFunctionTableSize;
	ULONG RetpolineStubOffset;
	ULONG RetpolineStubSize;
} KDDEBUGGER_DATA64, * PKDDEBUGGER_DATA64;

typedef struct tag_thread_info
{
	PETHREAD owning_thread;
}_tag_thread_info, * ptag_thread_info;

typedef struct tag_wnd
{
	HANDLE window;
	void* win32_thread;
	ptag_thread_info thread_info;
	char unk1[0x8];
	void* self;
	void* user_info;
	HANDLE region;
	void* region_info;
	void* parent;
	void* next;
	void* unk2;
	void* child;
	void* previous;
	void* unk3;
	void* win32;
	void* global_info_link;
	char unk4[0x48];
	ULONG user_procedures_link;
	char unk5[0x1c];
	ULONG procedure_flag;
	char unk6[0x3C];
	void* procedure_table;
}_tag_wnd, * ptag_wnd;

typedef struct _DUMP_HEADER {
	ULONG Signature;
	ULONG ValidDump;
	ULONG MajorVersion;
	ULONG MinorVersion;
	ULONG_PTR DirectoryTableBase;
	ULONG_PTR PfnDataBase;
	PLIST_ENTRY PsLoadedModuleList;
	PLIST_ENTRY PsActiveProcessHead;
	ULONG MachineImageType;
	ULONG NumberProcessors;
	ULONG BugCheckCode;
	ULONG_PTR BugCheckParameter1;
	ULONG_PTR BugCheckParameter2;
	ULONG_PTR BugCheckParameter3;
	ULONG_PTR BugCheckParameter4;
	CHAR VersionUser[32];

#ifndef _WIN64
	ULONG PaeEnabled;
#endif // !_WIN64

	struct _KDDEBUGGER_DATA64* KdDebuggerDataBlock;
} DUMP_HEADER, * PDUMP_HEADER;

typedef struct _PMISCFLAGSWin11
{
	ULONG AutoBoostActive : 1;                                        //0x74
	ULONG ReadyTransition : 1;                                        //0x74
	ULONG WaitNext : 1;                                               //0x74
	ULONG SystemAffinityActive : 1;                                   //0x74
	ULONG Alertable : 1;                                              //0x74
	ULONG UserStackWalkActive : 1;                                    //0x74
	ULONG ApcInterruptRequest : 1;                                    //0x74
	ULONG QuantumEndMigrate : 1;                                      //0x74
	ULONG Spare1 : 1;                                                 //0x74
	ULONG TimerActive : 1;                                            //0x74
	ULONG SystemThread : 1;                                           //0x74
	ULONG ProcessDetachActive : 1;                                    //0x74
	ULONG CalloutActive : 1;                                          //0x74
	ULONG ScbReadyQueue : 1;                                          //0x74
	ULONG ApcQueueable : 1;                                           //0x74
	ULONG ReservedStackInUse : 1;                                     //0x74
	ULONG Spare2 : 1;                                                 //0x74
	ULONG TimerSuspended : 1;                                         //0x74
	ULONG SuspendedWaitMode : 1;                                      //0x74
	ULONG SuspendSchedulerApcWait : 1;                                //0x74
	ULONG CetUserShadowStack : 1;                                     //0x74
	ULONG BypassProcessFreeze : 1;                                    //0x74
	ULONG CetKernelShadowStack : 1;                                   //0x74
	ULONG StateSaveAreaDecoupled : 1;                                 //0x74
	ULONG IsolationWidth : 1;                                         //0x74
	ULONG Reserved : 7;                                               //0x74
}PMISCFLAGSWin11, * pPMISCFLAGSWin11;

typedef struct _PMISCFLAGSWin10
{
	ULONG AutoBoostActive : 1;
	ULONG ReadyTransition : 1;
	ULONG WaitNext : 1;
	ULONG SystemAffinityActive : 1;
	ULONG Alertable : 1;
	ULONG UserStackWalkActive : 1;
	ULONG ApcInterruptRequest : 1;
	ULONG QuantumEndMigrate : 1;
	ULONG UmsDirectedSwitchEnable : 1;
	ULONG TimerActive : 1;
	ULONG SystemThread : 1;
	ULONG ProcessDetachActive : 1;
	ULONG CalloutActive : 1;
	ULONG ScbReadyQueue : 1;
	ULONG ApcQueueable : 1;
	ULONG ReservedStackInUse : 1;
	ULONG UmsPerformingSyscall : 1;
	ULONG TimerSuspended : 1;
	ULONG SuspendedWaitMode : 1;
	ULONG SuspendSchedulerApcWait : 1;
	ULONG CetUserShadowStack : 1;
	ULONG BypassProcessFreeze : 1;
	ULONG Reserved : 10;
}PMISCFLAGSWin10, * pPMISCFLAGSWin10;

typedef struct _PMISCFLAGSWin8
{
	ULONG KernelStackResident : 1;                                    //0x74
	ULONG ReadyTransition : 1;                                        //0x74
	ULONG ProcessReadyQueue : 1;                                      //0x74
	ULONG WaitNext : 1;                                               //0x74
	ULONG SystemAffinityActive : 1;                                   //0x74
	ULONG Alertable : 1;                                              //0x74
	ULONG CodePatchInProgress : 1;                                    //0x74
	ULONG UserStackWalkActive : 1;                                    //0x74
	ULONG ApcInterruptRequest : 1;                                    //0x74
	ULONG QuantumEndMigrate : 1;                                      //0x74
	ULONG UmsDirectedSwitchEnable : 1;                                //0x74
	ULONG TimerActive : 1;                                            //0x74
	ULONG SystemThread : 1;                                           //0x74
	ULONG ProcessDetachActive : 1;                                    //0x74
	ULONG CalloutActive : 1;                                          //0x74
	ULONG ScbReadyQueue : 1;                                          //0x74
	ULONG ApcQueueable : 1;                                           //0x74
	ULONG ReservedStackInUse : 1;                                     //0x74
	ULONG UmsPerformingSyscall : 1;                                   //0x74
	ULONG Reserved : 13;                                              //0x74
}PMISCFLAGSWin8, * pPMISCFLAGSWin8;

typedef struct _PMISCFLAGSWin81
{
	ULONG KernelStackResident : 1;                                    //0x74
	ULONG ReadyTransition : 1;                                        //0x74
	ULONG ProcessReadyQueue : 1;                                      //0x74
	ULONG WaitNext : 1;                                               //0x74
	ULONG SystemAffinityActive : 1;                                   //0x74
	ULONG Alertable : 1;                                              //0x74
	ULONG UserStackWalkActive : 1;                                    //0x74
	ULONG ApcInterruptRequest : 1;                                    //0x74
	ULONG QuantumEndMigrate : 1;                                      //0x74
	ULONG UmsDirectedSwitchEnable : 1;                                //0x74
	ULONG TimerActive : 1;                                            //0x74
	ULONG SystemThread : 1;                                           //0x74
	ULONG ProcessDetachActive : 1;                                    //0x74
	ULONG CalloutActive : 1;                                          //0x74
	ULONG ScbReadyQueue : 1;                                          //0x74
	ULONG ApcQueueable : 1;                                           //0x74
	ULONG ReservedStackInUse : 1;                                     //0x74
	ULONG UmsPerformingSyscall : 1;                                   //0x74
	ULONG ApcPendingReload : 1;                                       //0x74
	ULONG Reserved : 13;                                              //0x74
}PMISCFLAGSWin81, * pPMISCFLAGSWin81;

typedef struct _PMISCFLAGSWin7
{
	volatile ULONG AutoAlignment : 1;                                 //0x100
	volatile ULONG DisableBoost : 1;                                  //0x100
	volatile ULONG EtwStackTraceApc1Inserted : 1;                     //0x100
	volatile ULONG EtwStackTraceApc2Inserted : 1;                     //0x100
	volatile ULONG CalloutActive : 1;                                 //0x100
	volatile ULONG ApcQueueable : 1;                                  //0x100
	volatile ULONG EnableStackSwap : 1;                               //0x100
	volatile ULONG GuiThread : 1;                                     //0x100
	volatile ULONG UmsPerformingSyscall : 1;                          //0x100
	volatile ULONG ReservedFlags : 23;                                //0x100
}PMISCFLAGSWin7, * pPMISCFLAGSWin7;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0x0,
	SystemProcessorInformation = 0x1,
	SystemPerformanceInformation = 0x2,
	SystemTimeOfDayInformation = 0x3,
	SystemPathInformation = 0x4,
	SystemProcessInformation = 0x5,
	SystemCallCountInformation = 0x6,
	SystemDeviceInformation = 0x7,
	SystemProcessorPerformanceInformation = 0x8,
	SystemFlagsInformation = 0x9,
	SystemCallTimeInformation = 0xa,
	SystemModuleInformation = 0xb,
	SystemLocksInformation = 0xc,
	SystemStackTraceInformation = 0xd,
	SystemPagedPoolInformation = 0xe,
	SystemNonPagedPoolInformation = 0xf,
	SystemHandleInformation = 0x10,
	SystemObjectInformation = 0x11,
	SystemPageFileInformation = 0x12,
	SystemVdmInstemulInformation = 0x13,
	SystemVdmBopInformation = 0x14,
	SystemFileCacheInformation = 0x15,
	SystemPoolTagInformation = 0x16,
	SystemInterruptInformation = 0x17,
	SystemDpcBehaviorInformation = 0x18,
	SystemFullMemoryInformation = 0x19,
	SystemLoadGdiDriverInformation = 0x1a,
	SystemUnloadGdiDriverInformation = 0x1b,
	SystemTimeAdjustmentInformation = 0x1c,
	SystemSummaryMemoryInformation = 0x1d,
	SystemMirrorMemoryInformation = 0x1e,
	SystemPerformanceTraceInformation = 0x1f,
	SystemObsolete0 = 0x20,
	SystemExceptionInformation = 0x21,
	SystemCrashDumpStateInformation = 0x22,
	SystemKernelDebuggerInformation = 0x23,
	SystemContextSwitchInformation = 0x24,
	SystemRegistryQuotaInformation = 0x25,
	SystemExtendServiceTableInformation = 0x26,
	SystemPrioritySeperation = 0x27,
	SystemVerifierAddDriverInformation = 0x28,
	SystemVerifierRemoveDriverInformation = 0x29,
	SystemProcessorIdleInformation = 0x2a,
	SystemLegacyDriverInformation = 0x2b,
	SystemCurrentTimeZoneInformation = 0x2c,
	SystemLookasideInformation = 0x2d,
	SystemTimeSlipNotification = 0x2e,
	SystemSessionCreate = 0x2f,
	SystemSessionDetach = 0x30,
	SystemSessionInformation = 0x31,
	SystemRangeStartInformation = 0x32,
	SystemVerifierInformation = 0x33,
	SystemVerifierThunkExtend = 0x34,
	SystemSessionProcessInformation = 0x35,
	SystemLoadGdiDriverInSystemSpace = 0x36,
	SystemNumaProcessorMap = 0x37,
	SystemPrefetcherInformation = 0x38,
	SystemExtendedProcessInformation = 0x39,
	SystemRecommendedSharedDataAlignment = 0x3a,
	SystemComPlusPackage = 0x3b,
	SystemNumaAvailableMemory = 0x3c,
	SystemProcessorPowerInformation = 0x3d,
	SystemEmulationBasicInformation = 0x3e,
	SystemEmulationProcessorInformation = 0x3f,
	SystemExtendedHandleInformation = 0x40,
	SystemLostDelayedWriteInformation = 0x41,
	SystemBigPoolInformation = 0x42,
	SystemSessionPoolTagInformation = 0x43,
	SystemSessionMappedViewInformation = 0x44,
	SystemHotpatchInformation = 0x45,
	SystemObjectSecurityMode = 0x46,
	SystemWatchdogTimerHandler = 0x47,
	SystemWatchdogTimerInformation = 0x48,
	SystemLogicalProcessorInformation = 0x49,
	SystemWow64SharedInformationObsolete = 0x4a,
	SystemRegisterFirmwareTableInformationHandler = 0x4b,
	SystemFirmwareTableInformation = 0x4c,
	SystemModuleInformationEx = 0x4d,
	SystemVerifierTriageInformation = 0x4e,
	SystemSuperfetchInformation = 0x4f,
	SystemMemoryListInformation = 0x50,
	SystemFileCacheInformationEx = 0x51,
	SystemThreadPriorityClientIdInformation = 0x52,
	SystemProcessorIdleCycleTimeInformation = 0x53,
	SystemVerifierCancellationInformation = 0x54,
	SystemProcessorPowerInformationEx = 0x55,
	SystemRefTraceInformation = 0x56,
	SystemSpecialPoolInformation = 0x57,
	SystemProcessIdInformation = 0x58,
	SystemErrorPortInformation = 0x59,
	SystemBootEnvironmentInformation = 0x5a,
	SystemHypervisorInformation = 0x5b,
	SystemVerifierInformationEx = 0x5c,
	SystemTimeZoneInformation = 0x5d,
	SystemImageFileExecutionOptionsInformation = 0x5e,
	SystemCoverageInformation = 0x5f,
	SystemPrefetchPatchInformation = 0x60,
	SystemVerifierFaultsInformation = 0x61,
	SystemSystemPartitionInformation = 0x62,
	SystemSystemDiskInformation = 0x63,
	SystemProcessorPerformanceDistribution = 0x64,
	SystemNumaProximityNodeInformation = 0x65,
	SystemDynamicTimeZoneInformation = 0x66,
	SystemCodeIntegrityInformation = 0x67,
	SystemProcessorMicrocodeUpdateInformation = 0x68,
	SystemProcessorBrandString = 0x69,
	SystemVirtualAddressInformation = 0x6a,
	SystemLogicalProcessorAndGroupInformation = 0x6b,
	SystemProcessorCycleTimeInformation = 0x6c,
	SystemStoreInformation = 0x6d,
	SystemRegistryAppendString = 0x6e,
	SystemAitSamplingValue = 0x6f,
	SystemVhdBootInformation = 0x70,
	SystemCpuQuotaInformation = 0x71,
	SystemNativeBasicInformation = 0x72,
	SystemErrorPortTimeouts = 0x73,
	SystemLowPriorityIoInformation = 0x74,
	SystemBootEntropyInformation = 0x75,
	SystemVerifierCountersInformation = 0x76,
	SystemPagedPoolInformationEx = 0x77,
	SystemSystemPtesInformationEx = 0x78,
	SystemNodeDistanceInformation = 0x79,
	SystemAcpiAuditInformation = 0x7a,
	SystemBasicPerformanceInformation = 0x7b,
	SystemQueryPerformanceCounterInformation = 0x7c,
	SystemSessionBigPoolInformation = 0x7d,
	SystemBootGraphicsInformation = 0x7e,
	SystemScrubPhysicalMemoryInformation = 0x7f,
	SystemBadPageInformation = 0x80,
	SystemProcessorProfileControlArea = 0x81,
	SystemCombinePhysicalMemoryInformation = 0x82,
	SystemEntropyInterruptTimingInformation = 0x83,
	SystemConsoleInformation = 0x84,
	SystemPlatformBinaryInformation = 0x85,
	SystemThrottleNotificationInformation = 0x86,
	SystemHypervisorProcessorCountInformation = 0x87,
	SystemDeviceDataInformation = 0x88,
	SystemDeviceDataEnumerationInformation = 0x89,
	SystemMemoryTopologyInformation = 0x8a,
	SystemMemoryChannelInformation = 0x8b,
	SystemBootLogoInformation = 0x8c,
	SystemProcessorPerformanceInformationEx = 0x8d,
	SystemSpare0 = 0x8e,
	SystemSecureBootPolicyInformation = 0x8f,
	SystemPageFileInformationEx = 0x90,
	SystemSecureBootInformation = 0x91,
	SystemEntropyInterruptTimingRawInformation = 0x92,
	SystemPortableWorkspaceEfiLauncherInformation = 0x93,
	SystemFullProcessInformation = 0x94,
	SystemKernelDebuggerInformationEx = 0x95,
	SystemBootMetadataInformation = 0x96,
	SystemSoftRebootInformation = 0x97,
	SystemElamCertificateInformation = 0x98,
	SystemOfflineDumpConfigInformation = 0x99,
	SystemProcessorFeaturesInformation = 0x9a,
	SystemRegistryReconciliationInformation = 0x9b,
	MaxSystemInfoClass = 0x9c,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE
{
	ULONG_PTR Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_THREADS
{
	LARGE_INTEGER  KernelTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  CreateTime;
	ULONG    WaitTime;
	PVOID    StartAddress;
	CLIENT_ID   ClientID;
	KPRIORITY   Priority;
	KPRIORITY   BasePriority;
	ULONG    ContextSwitchCount;
	ULONG    ThreadState;
	KWAIT_REASON  WaitReason;
	ULONG    Reserved; //Add
}SYSTEM_THREADS, * PSYSTEM_THREADS;

typedef struct _MEMORY_SECTION_NAME {
	UNICODE_STRING Name;
	WCHAR     Buffer[260];
}MEMORY_SECTION_NAME, * PMEMORY_SECTION_NAME;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	KPRIORITY               BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
	ULONG                   HandleCount;
	ULONG                   Reserved2[2];
	ULONG                   PrivatePageCount;
	VM_COUNTERS             VirtualMemoryCounters;
	IO_COUNTERS             IoCounters;
	SYSTEM_THREADS           Threads[0];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG_PTR ulModuleCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
{
	PULONG_PTR ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG_PTR NumberOfServices;
	PUCHAR ParamTableBase;
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, * PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;         // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];//ntobase
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _MODULE_INFO
{
	PUCHAR Base;
	SIZE_T Size;
} MODULE_INFO, * PMODULE_INFO;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, * PPEB;

typedef struct _MMPTE_HARDWARE64
{
	ULONGLONG Valid : 1;
	ULONGLONG Dirty1 : 1;
	ULONGLONG Owner : 1;
	ULONGLONG WriteThrough : 1;
	ULONGLONG CacheDisable : 1;
	ULONGLONG Accessed : 1;
	ULONGLONG Dirty : 1;
	ULONGLONG LargePage : 1;
	ULONGLONG Global : 1;
	ULONGLONG CopyOnWrite : 1;
	ULONGLONG Unused : 1;
	ULONGLONG Write : 1;
	ULONGLONG PageFrameNumber : 36;
	ULONGLONG reserved1 : 4;
	ULONGLONG SoftwareWsIndex : 11;
	ULONGLONG NoExecute : 1;
} MMPTE_HARDWARE64, * PMMPTE_HARDWARE64;

typedef union _HARDWARE_PTE
{
	struct
	{
		ULONG64 Vaild : 1;
		ULONG64 Write : 1;
		ULONG64 Owner : 1;
		ULONG64 WriteThrough : 1;
		ULONG64 CacheDisable : 1;
		ULONG64 Accessed : 1;
		ULONG64 Dirty : 1;
		ULONG64 LargePage : 1;
		ULONG64 Global : 1;
		ULONG64 CopyOnWrite : 1;
		ULONG64 Prototype : 1;
		ULONG64 reserved0 : 1;
		ULONG64 PageFrameNumber : 36;
		ULONG64 reserved1 : 4;
		ULONG64 SoftwareWsIndex : 11;
		ULONG64 NoExecute : 1;
	};
}HARDWARE_PTE, * PHARDWARE_PTE;

typedef struct _MMPTE
{
	union
	{
		ULONG_PTR Long;
		MMPTE_HARDWARE64 Hard;
	} u;
} MMPTE;
typedef MMPTE* PMMPTE;

typedef ptag_wnd(NTAPI* fn_ValidateHwnd)(ULONG64 Wnd);

typedef NTSTATUS(NTAPI* fn_MmCopyVirtualMemory)(IN  PUCHAR FromProcess, IN  PVOID FromAddress, IN  PUCHAR ToProcess, OUT PVOID ToAddress, IN  SIZE_T BufferSize, IN  KPROCESSOR_MODE PreviousMode, OUT PSIZE_T NumberOfBytesCopied);

typedef PVOID(__fastcall* fn_MmAllocateIndependentPages)(size_t a1, size_t a2);

typedef void(__fastcall* fn_MmFreeIndependentPages)(PVOID Base, size_t a2);

typedef struct _SYSTEM_ROUTINE_ADDRESS {
	ULONG_PTR CsrssCR3;
	ULONG CR3Offset;
	ULONG buildNo;
	ULONG PrevMode;
	ULONG PmiscFlag;
	ULONG ActiveProcessLinks;
	ULONG UniqueProcessId;
	ULONG_PTR DYN_PDE_BASE;
	ULONG_PTR DYN_PTE_BASE;
	ULONG_PTR DYN_PXE_BASE;
	ULONG_PTR DYN_PPE_BASE;
	ptag_wnd My_ptag_wnd;
	fn_ValidateHwnd pfn_ValidateHwnd;
	fn_MmAllocateIndependentPages pfn_MmAllocateIndependentPages;
	fn_MmFreeIndependentPages pfn_MmFreeIndependentPages;
	fn_MmCopyVirtualMemory pfn_MmCopyVirtualMemory;
	IopLoadDriver PnpDiagnosticTraceObject;
	ULONG_PTR PspGetContext;
	ULONG_PTR MmQueryVirtualMemory;
	ULONG_PTR MmCopyMemory;
	ULONG_PTR PspExitProcess;
	ULONG_PTR RtlWalkFrameChain;
	ULONG_PTR InstrumentationCallback;
}SYSTEM_ROUTINE_ADDRESS, * PSYSTEM_ROUTINE_ADDRESS;

extern "C" NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);
extern "C" NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);
extern "C" NTSYSAPI NTSTATUS NTAPI KeCapturePersistentThreadState(__in PCONTEXT Context, __in_opt PKTHREAD Thread, __in ULONG BugCheckCode, __in ULONG_PTR BugCheckParameter1, __in ULONG_PTR BugCheckParameter2, __in ULONG_PTR BugCheckParameter3, __in ULONG_PTR BugCheckParameter4, __in PDUMP_HEADER DumpHeader);
extern "C" NTSYSAPI NTSTATUS NTAPI ZwSetSystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN PVOID SystemInformation, IN ULONG SystemInformationLength);
extern "C" NTSTATUS NTAPI ObReferenceObjectByName(PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID OPTIONAL, PVOID*);
extern "C" NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
extern "C" PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);