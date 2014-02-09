#pragma once

#pragma comment(lib, "ntdll.lib")

//宏
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define InitializeObjectAttributes( p, n, a, r, s ) { (p)->Length = sizeof( OBJECT_ATTRIBUTES ); \
	(p)->RootDirectory = r; (p)->Attributes = a; (p)->ObjectName = n; \
	(p)->SecurityDescriptor = s; (p)->SecurityQualityOfService = NULL; }

//类型定义
typedef int NT_IO_APC_ROUTINE;
typedef NT_IO_APC_ROUTINE *PNT_IO_APC_ROUTINE;
typedef long NTSTATUS;
typedef long KPRIORITY;

//结构声明
typedef struct _NT_API_SET_NAMESPACE_ENTRY_V2
{
	DWORD NameOffset;
	DWORD NameLength;
	DWORD DataOffset;                     //指明API_SET_VALUE_ARRAY_V2相对于API_SET_NAMESPACE_ARRAY_V2的偏移
} NT_API_SET_NAMESPACE_ENTRY_V2, *PNT_API_SET_NAMESPACE_ENTRY_V2;

typedef struct _NT_API_SET_NAMESPACE_ARRAY_V2
{
	DWORD Version;
	DWORD Count;       //指明有多少个API_SET_MAP_ENTRY
	NT_API_SET_NAMESPACE_ENTRY_V2 Entry[1];
} NT_API_SET_NAMESPACE_ARRAY_V2, *PNT_API_SET_NAMESPACE_ARRAY_V2;

typedef struct _NT_API_SET_VALUE_ENTRY_V2
{
	DWORD NameOffset;
	DWORD NameLength;
	DWORD ValueOffset;
	DWORD ValueLength;
} NT_API_SET_VALUE_ENTRY_V2, *PNT_API_SET_VALUE_ENTRY_V2;

typedef struct _NT_API_SET_VALUE_ARRAY_V2
{
	DWORD Count;                                  //API_SET_VALUE_ENTRY_V2的数量
	NT_API_SET_VALUE_ENTRY_V2 Entry[1];
} NT_API_SET_VALUE_ARRAY_V2, *PNT_API_SET_VALUE_ARRAY_V2;

typedef struct _NT_API_SET_NAMESPACE_ENTRY_V4
{
	DWORD Flags;
	DWORD NameOffset;
	DWORD NameLength;
	DWORD AliasOffset;
	DWORD AliasLength;
	DWORD DataOffset;                                 //API_SET_VALUE_ARRAY_V4相对于API_SET_NAMESPACE_ARRAY_V4的偏移
} NT_API_SET_NAMESPACE_ENTRY_V4, *PNT_API_SET_NAMESPACE_ENTRY_V4;

typedef struct _NT_API_SET_NAMESPACE_ARRAY_V4
{
	DWORD Version;
	DWORD Size;
	DWORD Flags;
	DWORD Count;                                         //指明有多少个API_SET_NAMESPACE_ENTRY_V4
	NT_API_SET_NAMESPACE_ENTRY_V4 Entry[1];
} NT_API_SET_NAMESPACE_ARRAY_V4, *PNT_API_SET_NAMESPACE_ARRAY_V4;

typedef struct _NT_API_SET_VALUE_ENTRY_V4
{
	DWORD Flags;
	DWORD NameOffset;
	DWORD NameLength;
	DWORD ValueOffset;
	DWORD ValueLength;
} NT_API_SET_VALUE_ENTRY_V4, *PNT_API_SET_VALUE_ENTRY_V4;

typedef struct _API_SET_VALUE_ARRAY_V4
{
	DWORD Flags;
	DWORD Count;
	NT_API_SET_VALUE_ENTRY_V4 Entry[1];
} NT_API_SET_VALUE_ARRAY_V4, *PNT_API_SET_VALUE_ARRAY_V4;

typedef struct _NT_LIST_ENTRY {
	struct _NT_LIST_ENTRY *Flink;
	struct _NT_LIST_ENTRY *Blink;
} NT_LIST_ENTRY, *PNT_LIST_ENTRY;

typedef struct _NT_STRING
{
	UINT16 Length;
	UINT16 MaximumLength;
	char *Buffer;
}NT_ANSI_STRING, *PNT_ANSI_STRING;

typedef struct _NT_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} NT_UNICODE_STRING, *PNT_UNICODE_STRING;

typedef union _NT_LARGE_INTEGER
{
	struct
	{
		ULONG LowPart;
		LONG HighPart;
	};
	struct
	{
		ULONG LowPart;
		LONG HighPart;
	}u;
	LONGLONG QuadPart;
}NT_LARGE_INTEGER, *PNT_LARGE_INTEGER;

typedef struct _NT_ULARGE_INTEGER
{
	struct
	{
		ULONG LowPart;
		ULONG HighPart;
	};
	struct
	{
		ULONG LowPart;
		ULONG HighPart;
	}u;
	LONGLONG QuadPart;
}NT_ULARGE_INTEGER, *PNT_ULARGE_INTEGER;

typedef struct _NT_CURDIR
{
	NT_UNICODE_STRING DosPath;
	void *Handle;
}NT_CURDIR, *PNT_CURDIR;

typedef struct _NT_CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} NT_CLIENT_ID, *PNT_CLIENT_ID;

typedef struct _NT_ACTIVATION_CONTEXT
{

}NT_ACTIVATION_CONTEXT, *PNT_ACTIVATION_CONTEXT;

typedef struct _NT_ACTIVATION_CONTEXT_DATA
{

}NT_ACTIVATION_CONTEXT_DATA, *PNT_ACTIVATION_CONTEXT_DATA;

typedef struct _NT_ASSEMBLY_STORAGE_MAP
{

}NT_ASSEMBLY_STORAGE_MAP, *PNT_ASSEMBLY_STORAGE_MAP;

typedef struct _NT_FLS_CALLBACK_INFO
{

}NT_FLS_CALLBACK_INFO, *PNT_FLS_CALLBACK_INFO;

typedef struct _NT_RTL_DRIVE_LETTER_CURDIR
{
	UINT16 Flags;
	UINT16  Length;
	ULONG TimeStamp;
	NT_ANSI_STRING DosPath;
}NT_RTL_DRIVE_LETTER_CURDIR, *PNT_RTL_DRIVE_LETTER_CURDIR;

typedef struct _NT_RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;  
	ULONG Length;
	ULONG Flags; 
	ULONG DebugFlags; 
	void *ConsoleHandle;
	ULONG ConsoleFlags;
	void *StandardInput;
	void *StandardOutput;
	void *StandardError;
	NT_CURDIR CurrentDirectory;
	NT_UNICODE_STRING DllPath;
	NT_UNICODE_STRING ImagePathName;
	NT_UNICODE_STRING CommandLine;
	void *Environment; 
	ULONG  StartingX;
	ULONG  StartingY;
	ULONG CountX; 
	ULONG CountY; 
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute; 
	ULONG WindowFlags;
	ULONG ShowWindowFlags; 
	NT_UNICODE_STRING WindowTitle;
	NT_UNICODE_STRING DesktopInfo;
	NT_UNICODE_STRING ShellInfo;
	NT_UNICODE_STRING RuntimeData;
	NT_RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
	ULONG EnvironmentSize; 
	ULONG EnvironmentVersion;
}NT_RTL_USER_PROCESS_PARAMETERS, *PNT_RTL_USER_PROCESS_PARAMETERS;

typedef struct _NT_RTL_CRITICAL_SECTION_DEBUG
{
	WORD Type;
	WORD CreatorBackTraceIndex;
	struct _NT_RTL_CRITICAL_SECTION *CriticalSection;
	NT_LIST_ENTRY ProcessLocksList;
	ULONG EntryCount;
	ULONG ContentionCount;
	ULONG Flags;
	WORD CreatorBackTraceIndexHigh;
	WORD SpareUSHORT;
}NT_RTL_CRITICAL_SECTION_DEBUG, *PNT_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _NT_RTL_CRITICAL_SECTION
{
	struct _NT_RTL_CRITICAL_SECTION_DEBUG *DebugInfo;
	LONG LockCount;
	LONG RecursionCount;
	PVOID OwningThread;
	PVOID LockSemaphore;
	ULONG SpinCount;
}NT_RTL_CRITICAL_SECTION, *PNT_RTL_CRITICAL_SECTION;

typedef struct _NT_LDR_DATA_TABLE_ENTRY
{
	NT_LIST_ENTRY InLoadOrderLinks;
	NT_LIST_ENTRY InMemoryOrderLinks;
	NT_LIST_ENTRY InInitializationOrderLinks;
	void *DllBase;
	void *EntryPoint;
	ULONG SizeOfImage;
	NT_UNICODE_STRING FullDllName;
	NT_UNICODE_STRING BaseDllName;
	ULONG Flags; 
	UINT16 LoadCount;
	UINT16 TlsIndex;
	union
	{
		NT_LIST_ENTRY HashLinks;
		struct
		{
			void *SectionPointer;
			ULONG CheckSum;
		};
	};
	union 
	{
		ULONG TimeDateStamp;
		void *LoadedImports; 
	};
	PNT_ACTIVATION_CONTEXT EntryPointActivationContext;
	void *PatchInformation;
	NT_LIST_ENTRY ForwarderLinks;
	NT_LIST_ENTRY ServiceTagLinks;
	NT_LIST_ENTRY StaticLinks;
	void *ContextInformation;
	ULONG OriginalBase;
	NT_LARGE_INTEGER LoadTime;
}NT_LDR_DATA_TABLE_ENTRY, *PNT_LDR_DATA_TABLE_ENTRY;

typedef struct _NT_PEB_LDR_DATA
{
	DWORD Length;
	UCHAR Initialized;
	PVOID SsHandle;
	NT_LIST_ENTRY InLoadOrderModuleList;
	NT_LIST_ENTRY InMemoryOrderModuleList;
	NT_LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	UCHAR ShutdownInProgress;
	PVOID ShutdownThreadId;
}NT_PEB_LDR_DATA, *PNT_PEB_LDR_DATA;

typedef struct _NT_RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
	struct _NT_RTL_ACTIVATION_CONTEXT_STACK_FRAME *Previous;
	PNT_ACTIVATION_CONTEXT ActivationContext;
	ULONG Flags;
}NT_RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PNT_RTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _NT_ACTIVATION_CONTEXT_STACK
{
	PNT_RTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
	NT_LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
}NT_ACTIVATION_CONTEXT_STACK, *PNT_ACTIVATION_CONTEXT_STACK;

typedef struct _NT_TEB_ACTIVE_FRAME_CONTEXT
{
	ULONG Flags;
	char *FrameName;
}NT_TEB_ACTIVE_FRAME_CONTEXT, *PNT_TEB_ACTIVE_FRAME_CONTEXT;

typedef struct _NT_TEB_ACTIVE_FRAME
{
	ULONG Flags;
	struct _NT_TEB_ACTIVE_FRAME *Previous;
	PNT_TEB_ACTIVE_FRAME_CONTEXT Context;
}NT_TEB_ACTIVE_FRAME, *PNT_TEB_ACTIVE_FRAME;

typedef struct _NT_GDI_TEB_BATCH
{
	ULONG Offset;
	ULONG HDC;
	ULONG Buffer[310];
}NT_GDI_TEB_BATCH, *PNT_GDI_TEB_BATCH;

typedef struct _NT_PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID ImageBaseAddress;
	PNT_PEB_LDR_DATA Ldr;
	PNT_RTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PNT_RTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	ULONG CrossProcessFlags;
	PVOID KernelCallbackTable;
	PVOID UserSharedInfoPtr;
	ULONG SystemReserved[1];
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID SparePvoid0;
	PVOID ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	NT_LARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID *ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	PNT_RTL_CRITICAL_SECTION LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG ActiveProcessAffinityMask;
	ULONG GdiHandleBuffer[34];
	PVOID PostProcessInitRoutine;
	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];
	ULONG SessionId;
	NT_ULARGE_INTEGER AppCompatFlags;
	NT_ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;
	NT_UNICODE_STRING CSDVersion;
	PNT_ACTIVATION_CONTEXT_DATA ActivationContextData;
	PNT_ASSEMBLY_STORAGE_MAP ProcessAssemblyStorageMap;
	PNT_ACTIVATION_CONTEXT_DATA SystemDefaultActivationContextData;
	PNT_ASSEMBLY_STORAGE_MAP SystemAssemblyStorageMap;
	ULONG MinimumStackCommit;
	PNT_FLS_CALLBACK_INFO FlsCallback;
	PNT_LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits[4];
	ULONG FlsHighIndex;
	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
	PVOID pUnused;
	PVOID pImageHeaderHash;
	ULONG TracingFlags;
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
}NT_PEB, *PNT_PEB;

typedef struct _NT_TEB
{
	PNT_TIB NtTib;
	PVOID EnvironmentPointer;
	NT_CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PNT_PEB ProcessEnvironmentBlock;
	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG User32Reserved[26];;
	ULONG UserReserved[5];
	PVOID WOW32Reserved;
	ULONG CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	PVOID SystemReserved1[54];
	LONG ExceptionCode;
	PNT_ACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
	UCHAR SpareBytes[36];
	ULONG TxFsContext;
	NT_GDI_TEB_BATCH GdiTebBatch;
	NT_CLIENT_ID RealClientId;
	PVOID GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocalInfo;
	ULONG Win32ClientInfo[62];
	PVOID glDispatchTable[233];
	ULONG glReserved1[29];
	PVOID glReserved2;
	PVOID glSectionInfo;
	PVOID glSection;
	PVOID glTable;
	PVOID glCurrentRC;
	PVOID glContext;
	ULONG LastStatusValue;
	NT_UNICODE_STRING StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];
	PVOID DeallocationStack;
	PVOID TlsSlots[64];
	NT_LIST_ENTRY TlsLinks;
	PVOID Vdm;
	PVOID ReservedForNtRpc;
	PVOID DbgSsReserved[2];
	ULONG HardErrorMode;
	PVOID  Instrumentation[9];
	GUID ActivityId;
	PVOID SubProcessTag;
	PVOID PerflibData;
	PVOID EtwTraceData;
	PVOID WinSockData;
	ULONG GdiBatchCount;
	union
	{
		PROCESSOR_NUMBER CurrentIdealProcessor;
		ULONG IdealProcessorValue;
		struct
		{
			UCHAR ReservedPad0;
			UCHAR ReservedPad1;
			UCHAR ReservedPad2;
			UCHAR IdealProcessor;
		};
	};
	ULONG GuaranteedStackBytes;
	PVOID ReservedForPerf;
	PVOID ReservedForOle;
	ULONG WaitingOnLoaderLock;
	PVOID SavedPriorityState;
	ULONG ReservedForCodeCoverage;
	PVOID ThreadPoolData;
	PVOID TlsExpansionSlots;
	ULONG MuiGeneration;
	ULONG IsImpersonating;
	PVOID NlsCache;
	PVOID pShimData;
	WORD HeapVirtualAffinity;
	WORD LowFragHeapDataSlot;
	PVOID CurrentTransactionHandle;
	PNT_TEB_ACTIVE_FRAME ActiveFrame;
	PVOID FlsData;
	PVOID PreferredLanguages;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;
	union
	{
		WORD CrossTebFlags;
		WORD SpareCrossTebBits;
	};
	WORD SameTebFlags;
	PVOID TxnScopeEnterCallback;
	PVOID TxnScopeExitCallback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	ULONG SpareUlong0;
	PVOID ResourceRetValue;
	PVOID ReservedForWdf;
}NT_TEB, *PNT_TEB;

typedef enum _NT_MEMORY_INFORMATION_CLASS
{
MemoryBasicInformation,
MemoryWorkingSetList,
MemorySectionName
}NT_MEMORY_INFORMATION_CLASS;

typedef enum _NT_SYSTEM_INFORMATION_CLASS {
  SystemBasicInformation,    //0
  SystemProcessorInformation,             // obsolete...delete  1
  SystemPerformanceInformation,    //2
  SystemTimeOfDayInformation,     //3
  SystemPathInformation,     //4
  SystemProcessInformation,    //5
  SystemCallCountInformation,    //6
  SystemDeviceInformation,    //7
  SystemProcessorPerformanceInformation,    //8
  SystemFlagsInformation,    //9
  SystemCallTimeInformation,    //10
  SystemModuleInformation,   //11 
  SystemLocksInformation,    //12
  SystemStackTraceInformation,    //13
  SystemPagedPoolInformation,    //14
  SystemNonPagedPoolInformation,    //15
  SystemHandleInformation,   //16
  SystemObjectInformation,    //17 
  SystemPageFileInformation,    //18
  SystemVdmInstemulInformation,   //19
  SystemVdmBopInformation,    //20
  SystemFileCacheInformation,    //21
  SystemPoolTagInformation,      //22
  SystemInterruptInformation,     //23
  SystemDpcBehaviorInformation,     //24
  SystemFullMemoryInformation,     //25
  SystemLoadGdiDriverInformation,      //26
  SystemUnloadGdiDriverInformation,     //27
  SystemTimeAdjustmentInformation,     //28
  SystemSummaryMemoryInformation,    //29
  SystemMirrorMemoryInformation,     //30
  SystemPerformanceTraceInformation,    //31
  SystemObsolete0,            //32
  SystemExceptionInformation,        //33
  SystemCrashDumpStateInformation,       //34
  SystemKernelDebuggerInformation,      //35
  SystemContextSwitchInformation,         //36
  SystemRegistryQuotaInformation,     //37
  SystemExtendServiceTableInformation,         //38
  SystemPrioritySeperation,               //39
  SystemVerifierAddDriverInformation,      //40
  SystemVerifierRemoveDriverInformation,          //41
  SystemProcessorIdleInformation,          //42
  SystemLegacyDriverInformation,            //43
  SystemCurrentTimeZoneInformation,          //44
  SystemLookasideInformation,                 //45
  SystemTimeSlipNotification,                   //46
  SystemSessionCreate,                           //47
  SystemSessionDetach,                    //48
  SystemSessionInformation,              //49
  SystemRangeStartInformation,       //50
  SystemVerifierInformation,             //51
  SystemVerifierThunkExtend,           //52
  SystemSessionProcessInformation,             //53
  SystemLoadGdiDriverInSystemSpace,          //54
  SystemNumaProcessorMap,                    //55
  SystemPrefetcherInformation,                //56
  SystemExtendedProcessInformation,   //57
  SystemRecommendedSharedDataAlignment,    //58
  SystemComPlusPackage,                 //59
  SystemNumaAvailableMemory,     //60
  SystemProcessorPowerInformation,         //61
  SystemEmulationBasicInformation,             //62
  SystemEmulationProcessorInformation,     //63
  SystemExtendedHandleInformation,          //64
  SystemLostDelayedWriteInformation,        //65
  SystemBigPoolInformation,                    //66
  SystemSessionPoolTagInformation,       //67
  SystemSessionMappedViewInformation,          //68
  SystemHotpatchInformation,           //69
  SystemObjectSecurityMode,             //70
  SystemWatchdogTimerHandler,      //71
  SystemWatchdogTimerInformation,     //72
  SystemLogicalProcessorInformation,    //73
  SystemWow64SharedInformation,      //74
  SystemRegisterFirmwareTableInformationHandler,         //75
  SystemFirmwareTableInformation,         //76
  SystemModuleInformationEx,             //77
  SystemVerifierTriageInformation,          //78
  SystemSuperfetchInformation,              //79
  SystemMemoryListInformation,           //80
  SystemFileCacheInformationEx,            //81
  MaxSystemInfoClass          // MaxSystemInfoClass should always be the last enum     82
} NT_SYSTEM_INFORMATION_CLASS, *PNT_SYSTEM_INFORMATION_CLASS;

typedef enum _NT_THREAD_STATE
{   
    StateInitialized,   
    StateReady,   
    StateRunning,   
    StateStandby,   
    StateTerminated,   
    StateWait,   
    StateTransition,   
    StateUnknown 
} NT_THREAD_STATE;

typedef enum _NT_KWAIT_REASON
{   
    Executive,   
    FreePage,   
    PageIn,   
    PoolAllocation,   
    DelayExecution,   
    Suspended,   
    UserRequest,   
    WrExecutive,   
    WrFreePage,   
    WrPageIn,   
    WrPoolAllocation,   
    WrDelayExecution,   
    WrSuspended,   
    WrUserRequest,   
    WrEventPair,   
    WrQueue,   
    WrLpcReceive,   
    WrLpcReply,   
    WrVirtualMemory,   
    WrPageOut,   
    WrRendezvous,   
    Spare2,   
    Spare3,   
    Spare4,   
    Spare5,   
    Spare6,   
    WrKernel 
} NT_KWAIT_REASON;

typedef struct _NT_VM_COUNTERS
{
	ULONG PeakVirtualSize;      
    ULONG VirtualSize;                  
    ULONG PageFaultCount;                  
    ULONG PeakWorkingSetSize;              
    ULONG WorkingSetSize;                  
    ULONG QuotaPeakPagedPoolUsage;         
    ULONG QuotaPagedPoolUsage;          
    ULONG QuotaPeakNonPagedPoolUsage;   
    ULONG QuotaNonPagedPoolUsage;       
    ULONG PagefileUsage;               
    ULONG PeakPagefileUsage;  
}NT_VM_COUNTERS, *PNT_VM_COUNTERS;

typedef struct _NT_SYSTEM_THREADS
{   
	NT_LARGE_INTEGER KernelTime;
	NT_LARGE_INTEGER UserTime;
	NT_LARGE_INTEGER CreateTime;
    ULONG WaitTime;   
    PVOID StartAddress;   
	NT_CLIENT_ID ClientId;
    KPRIORITY Priority;   
    KPRIORITY BasePriority;   
    ULONG ContextSwitchCount;   
	NT_THREAD_STATE State;
	NT_KWAIT_REASON WaitReason;
} NT_SYSTEM_THREADS, *PNT_SYSTEM_THREADS;

typedef struct _NT_SYSTEM_PROCESSES
{   
    ULONG NextEntryOffset;   
    ULONG ThreadCount;   
    ULONG Reserved1[6];   
	NT_LARGE_INTEGER CreateTime;
	NT_LARGE_INTEGER UserTime;
	NT_LARGE_INTEGER KernelTime;
	NT_UNICODE_STRING ProcessName;
    KPRIORITY BasePriority;   
    ULONG ProcessId;   
    ULONG InheritedFromProcessId;   
    ULONG HandleCount;   
    ULONG Reserved2[2];   
	NT_VM_COUNTERS  VmCounters;
    IO_COUNTERS IoCounters;   
	NT_SYSTEM_THREADS Threads[1];
} NT_SYSTEM_PROCESSES, *PNT_SYSTEM_PROCESSES;

typedef enum _NT_OBJECT_INFORMATION_CLASS
{
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllInformation,
    ObjectDataInformation
} NT_OBJECT_INFORMATION_CLASS, *PNT_OBJECT_INFORMATION_CLASS;

typedef struct _NT_OBJECT_ATTRIBUTES 
{
  ULONG Length;
  HANDLE RootDirectory;
  PNT_UNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
}  NT_OBJECT_ATTRIBUTES, *PNT_OBJECT_ATTRIBUTES;

typedef struct _NT_IO_STATUS_BLOCK 
{
  union
  {
    NTSTATUS Status;
    PVOID    Pointer;
  };
  ULONG_PTR Information;
} NT_IO_STATUS_BLOCK, *PNT_IO_STATUS_BLOCK;

typedef struct _NT_CONTEXT {
	ULONG ContextFlags;
	ULONG   Dr0;
	ULONG   Dr1;
	ULONG   Dr2;
	ULONG   Dr3;
	ULONG   Dr6;
	ULONG   Dr7;
	FLOATING_SAVE_AREA FloatSave;
	ULONG   SegGs;
	ULONG   SegFs;
	ULONG   SegEs;
	ULONG   SegDs;
	ULONG   Edi;
	ULONG   Esi;
	ULONG   Ebx;
	ULONG   Edx;
	ULONG   Ecx;
	ULONG   Eax;
	ULONG   Ebp;
	ULONG   Eip;
	ULONG   SegCs;             
	ULONG   EFlags;            
	ULONG   Esp;
	ULONG   SegSs;
	UCHAR   ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
} NT_CONTEXT, *PNT_CONTEXT;

typedef enum _NT_PROCESS_CLASS
{
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	MaxProcessInfoClass
}NT_PROCESS_CLASS, *PNT_PROCESS_CLASS;

typedef struct _NT_PROCESS_BASIC_INFORMATION
{
	DWORD ExitStatus;
	DWORD PebBaseAddress;
	DWORD AffinityMask;
	DWORD BasePriority;
	ULONG UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
}NT_PROCESS_BASIC_INFORMATION, *PNT_PROCESS_BASIC_INFORMATION;

typedef struct _NT_SYSTEM_HANDLE_INFORMATION
{
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
}NT_SYSTEM_HANDLE_INFORMATION, *PNT_SYSTEM_HANDLE_INFORMATION;

typedef enum _NT_SYSTEM_HANDLE_TYPE
{
	OB_TYPE_UNKNOWN,	//0
	OB_TYPE_TYPE,		//1
	OB_TYPE_DIRECTORY,	//2
	OB_TYPE_SYMBOLIC_LINK,//3
	OB_TYPE_TOKEN,		//4
	OB_TYPE_PROCESS,	//5
	OB_TYPE_THREAD,		//6
	OB_TYPE_UNKNOWN_7,	//7
	OB_TYPE_EVENT,		//8
	OB_TYPE_EVENT_PAIR,	//9
	OB_TYPE_MUTANT,		//10
	OB_TYPE_UNKNOWN_11,	//11
	OB_TYPE_SEMAPHORE,	//12
	OB_TYPE_TIMER,		//13
	OB_TYPE_PROFILE,	//14
	OB_TYPE_WINDOW_STATION,//15
	OB_TYPE_DESKTOP,	//16
	OB_TYPE_SECTION,	//17
	OB_TYPE_KEY,		//18
	OB_TYPE_PORT,		//19
	OB_TYPE_WAITABLE_PORT,//20
	OB_TYPE_UNKNOWN_21,	
	OB_TYPE_UNKNOWN_22,
	OB_TYPE_UNKNOWN_23,
	OB_TYPE_UNKNOWN_24,
	OB_TYPE_IO_COMPLETION,//25
	OB_TYPE_FILE		//26
}NT_SYSTEM_HANDLE_TYPE;

typedef enum _NT_KEY_INFORMATION_CLASS {
	KeyBasicInformation = 0,
	KeyNodeInformation = 1,
	KeyFullInformation = 2,
	KeyNameInformation = 3,
	KeyCachedInformation = 4,
	KeyFlagsInformation = 5,
	KeyVirtualizationInformation = 6,
	KeyHandleTagsInformation = 7,
	MaxKeyInfoClass = 8
} NT_KEY_INFORMATION_CLASS;

typedef enum _NT_KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation = 0,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	MaxKeyValueInfoClass
} NT_KEY_VALUE_INFORMATION_CLASS;

//结构声明结束

//函数声明

extern "C" 
{
	NTSTATUS NTAPI RtlAdjustPrivilege(
	ULONG Privilege,
	BOOLEAN Enable,
	BOOLEAN CurrentThread,
	PBOOLEAN Enabled);

	PIMAGE_NT_HEADERS RtlImageNtHeader(IN PVOID ModuleAddress);

	DWORD NTAPI RtlImageDirectoryEntryToData(
	IN DWORD BaseAddress,
	IN BOOL MappedAsImage,
	IN DWORD dwDataDirectoryIndex, 
	IN DWORD *Size);

	NTSTATUS NTAPI LdrLoadDll(
		IN PWCHAR PathToFile,
		IN ULONG Flags,
		IN PNT_UNICODE_STRING ModuleFileName,
		IN PHANDLE ModuleHandle);

	NTSTATUS NTAPI NtOpenProcess(
		OUT PHANDLE ProcessHandle,
		IN ACCESS_MASK DesiredAccess,
		IN PNT_OBJECT_ATTRIBUTES ObjectAttributes,
		IN PNT_CLIENT_ID ClientId);

	NTSTATUS NTAPI NtGetNextProcess(
		HANDLE ProcessHandle,
		ACCESS_MASK DesiredAccess,
		ULONG HandleAttributes,
		ULONG Flags,
		PHANDLE NewProcessHandle);

	NTSTATUS NTAPI NtGetNextThread(
		HANDLE ProcessHandle,
		HANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		ULONG HandleAttributes,
		ULONG Flags,
		PHANDLE NewThreadHandle);

	NTSTATUS NTAPI NtQueryInformationProcess(
		IN HANDLE ProcessHandle,
		IN NT_PROCESS_CLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength);

	NTSTATUS NTAPI NtTerminateProcess(
		IN HANDLE ProcessHandle,
		IN NTSTATUS ExitStatus);

	NTSTATUS NTAPI NtSuspendProcess(IN HANDLE hProcess);

	HANDLE NTAPI ZwCurrentProcess();

	NTSTATUS NTAPI NtGetContextThread(IN HANDLE hThread, OUT PNT_CONTEXT pContext);

	NTSTATUS NTAPI NtSetContextThread(IN HANDLE hThread, IN PNT_CONTEXT pContext);

	NTSTATUS NTAPI NtResumeThread(IN HANDLE hThread, OUT PULONG SuspendCount);

	NTSTATUS NTAPI NtQuerySystemInformation(
		IN      NT_SYSTEM_INFORMATION_CLASS SystemInformationClass,
        IN      PVOID SystemInformation,
        IN      ULONG SystemInformationLength,
        OUT   PULONG ReturnLength);

	NTSTATUS NTAPI NtQueryObject(
	IN HANDLE Handle,
	IN NT_OBJECT_INFORMATION_CLASS ObjectInformationClass,
	OUT PVOID ObjectInformation,
	IN ULONG ObjectInformationLength,
	OUT PULONG ReturnLength);

	NTSTATUS NTAPI NtCreateFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN PNT_OBJECT_ATTRIBUTES ObjectAttributes,
	OUT PNT_IO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer,
	IN ULONG EaLength);

	NTSTATUS NTAPI NtOpenFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN PNT_OBJECT_ATTRIBUTES ObjectAttributes,
	OUT PNT_IO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions);

	NTSTATUS NTAPI NtReadFile(
	IN HANDLE FileHandle,
	IN HANDLE Event,
	IN PNT_IO_APC_ROUTINE ApcRoutine,
	IN PVOID ApcContext,
	OUT PNT_IO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset,
	IN PULONG Key);

	NTSTATUS NTAPI NtWriteFile(
    IN HANDLE FileHandle,
	IN HANDLE Event,
	IN PNT_IO_APC_ROUTINE ApcRoutine,
	IN PVOID ApcContext,
	OUT PNT_IO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset,
	IN PULONG Key);

	NTSTATUS NTAPI NtDeleteFile(IN PNT_OBJECT_ATTRIBUTES ObjectAttributes);

	NTSTATUS NTAPI NtClose(IN HANDLE Handle);

	NTSTATUS NTAPI NtQueryVirtualMemory(
		IN HANDLE ProcessHandle,
		IN PVOID BaseAddress,
		IN NT_MEMORY_INFORMATION_CLASS MemoryInformationClass,
		OUT PVOID MemoryInformation,
		IN ULONG MemoryInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	NTSTATUS NTAPI NtAllocateVirtualMemory(
		IN HANDLE hProcess,
		IN PVOID *BaseAddress,
		IN ULONG_PTR ZeroBits,
		IN PSIZE_T RegionSize,
		IN ULONG AllocationType,
		IN ULONG Protect);

	NTSTATUS NTAPI NtWriteVirtualMemory(
		IN HANDLE hProcess,
		IN PVOID BaseAddress,
		IN PVOID Buffer,
		IN ULONG NumberOfBytesToWrite,
		OUT PULONG NumberOfBytesWritten);

	NTSTATUS NTAPI NtReadVirtualMemory(
		IN HANDLE hProcess,
		IN PVOID BaseAddress,
		OUT PVOID Buffer,
		IN ULONG NumberOfBytesToRead,
		OUT PULONG NumberOfBytesReaded);

	NTSTATUS NTAPI NtProtectVirtualMemory(
		IN HANDLE hProcess,
		IN PVOID *BaseAddress,
		IN PULONG NumberOfBytesToProtect,
		IN ULONG NewAccessProtection,
		OUT PULONG OldAccessProtection);

	NTSTATUS NTAPI NtFreeVirtualMemory(
		IN HANDLE hProcess,
		IN PVOID *BaseAddress,
		IN PSIZE_T RegionSize,
		IN ULONG FreeType);

	NTSTATUS NTAPI ZwDuplicateObject(
		IN HANDLE  SourceProcessHandle,
		IN HANDLE  SourceHandle,
		IN HANDLE  TargetProcessHandle,
		OUT PHANDLE  TargetHandle,
		IN ACCESS_MASK  DesiredAccess,
		IN ULONG  Attributes,
		IN ULONG  Options);

	NTSTATUS NTAPI NtCreateKey(
		OUT PHANDLE KeyHandle,
		IN  ACCESS_MASK DesiredAccess,
		IN  PNT_OBJECT_ATTRIBUTES ObjectAttributes,
		IN  ULONG TitleIndex,
		OPTIONAL  PNT_UNICODE_STRING Class,
		IN  ULONG CreateOptions,
		OPTIONAL PULONG Disposition
		);

	NTSTATUS NTAPI NtOpenKey(
		OUT PHANDLE KeyHandle,
		IN ACCESS_MASK DesiredAccess,
		IN PNT_OBJECT_ATTRIBUTES ObjectAttributes
		);

	NTSTATUS NTAPI NtEnumerateKey(
		IN HANDLE KeyHandle,
		IN ULONG Index,
		IN NT_KEY_INFORMATION_CLASS KeyInformationClass,
		IN PVOID KeyInformation,
		IN ULONG Length,
		IN PULONG ResultLength
		);

	NTSTATUS NTAPI NtDeleteKey(IN HANDLE KeyHandle);

	NTSTATUS NTAPI NtQueryValueKey(
		IN HANDLE KeyHandle,
		IN PNT_UNICODE_STRING ValueName,
		IN NT_KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
		OUT PVOID KeyValueInformation,
		IN ULONG Length,
		OUT PULONG ResultLength
		);

	NTSTATUS NTAPI NtSetValueKey(
		IN HANDLE KeyHandle,
		IN PNT_UNICODE_STRING ValueName,
		IN ULONG TitleIndex OPTIONAL,
		IN ULONG Type,
		IN PVOID Data,
		IN ULONG DataSize
		);

	NTSTATUS NTAPI NtDeleteValueKey(IN HANDLE KeyHandle, IN PNT_UNICODE_STRING ValueName);
}