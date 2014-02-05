#pragma once

//宏
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define InitializeObjectAttributes( p, n, a, r, s ) { (p)->Length = sizeof( OBJECT_ATTRIBUTES ); \
	(p)->RootDirectory = r; (p)->Attributes = a; (p)->ObjectName = n; \
	(p)->SecurityDescriptor = s; (p)->SecurityQualityOfService = NULL; }

//类型定义
typedef int IO_APC_ROUTINE;
typedef IO_APC_ROUTINE *PIO_APC_ROUTINE;
typedef long NTSTATUS;
typedef long KPRIORITY;
typedef unsigned short UINT16;

//结构声明
/*typedef struct _LIST_ENTRY {
	struct _LIST_ENTRY *Flink;
	struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;*/

typedef struct _STRING
{
	UINT16 Length;
	UINT16 MaximumLength;
	char *Buffer;
}STRING, *PSTRING;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

/*typedef union _LARGE_INTEGER
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
	__int64 QuadPart;
}LARGE_INTEGER, *PLARGE_INTEGER;*/

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	void *Handle;
}CURDIR, *PCURDIR;

typedef struct _ACTIVATION_CONTEXT
{

}ACTIVATION_CONTEXT, *PACTIVATION_CONTEXT;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	UINT16 Flags;
	UINT16  Length;
	ULONG TimeStamp;
	STRING DosPath;
}RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
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
	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath; 
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
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
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32]; 
	ULONG EnvironmentSize; 
	ULONG EnvironmentVersion;
}RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	void *DllBase;
	void *EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName; 
	ULONG Flags; 
	UINT16 LoadCount;
	UINT16 TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
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
	PACTIVATION_CONTEXT EntryPointActivationContext; 
	void *PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;   
	void *ContextInformation;
	ULONG OriginalBase;
	LARGE_INTEGER LoadTime;
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _NT_PEB_LDR_DATA
{
	DWORD Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
}NT_PEB_LDR_DATA, *PNT_PEB_LDR_DATA;

typedef enum _MEMORY_INFORMATION_CLASS 
{
MemoryBasicInformation,
MemoryWorkingSetList,
MemorySectionName
}MEMORY_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS {
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
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _CLIENT_ID   
{   
    HANDLE UniqueProcess;   
    HANDLE UniqueThread; 
} CLIENT_ID, *PCLIENT_ID;

typedef enum _THREAD_STATE   
{   
    StateInitialized,   
    StateReady,   
    StateRunning,   
    StateStandby,   
    StateTerminated,   
    StateWait,   
    StateTransition,   
    StateUnknown 
} THREAD_STATE;

typedef enum _KWAIT_REASON   
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
} KWAIT_REASON;

typedef struct _VM_COUNTERS
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
}VM_COUNTERS, *PVM_COUNTERS;

typedef struct _SYSTEM_THREADS   
{   
    LARGE_INTEGER KernelTime;   
    LARGE_INTEGER UserTime;   
    LARGE_INTEGER CreateTime;   
    ULONG WaitTime;   
    PVOID StartAddress;   
    CLIENT_ID ClientId;   
    KPRIORITY Priority;   
    KPRIORITY BasePriority;   
    ULONG ContextSwitchCount;   
    THREAD_STATE State;   
    KWAIT_REASON WaitReason;
} SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES   
{   
    ULONG NextEntryOffset;   
    ULONG ThreadCount;   
    ULONG Reserved1[6];   
    LARGE_INTEGER CreateTime;   
    LARGE_INTEGER UserTime;   
    LARGE_INTEGER KernelTime;   
    UNICODE_STRING ProcessName;   
    KPRIORITY BasePriority;   
    ULONG ProcessId;   
    ULONG InheritedFromProcessId;   
    ULONG HandleCount;   
    ULONG Reserved2[2];   
    VM_COUNTERS  VmCounters;   
    IO_COUNTERS IoCounters;   
    SYSTEM_THREADS Threads[1];   
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;  

typedef enum _OBJECT_INFORMATION_CLASS
{
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllInformation,
    ObjectDataInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID    Pointer;
  };
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

/*typedef struct _CONTEXT {
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
} CONTEXT, *PCONTEXT;*/

typedef enum _PROCESS_CLASS
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
}PROCESS_CLASS, *PPROCESS_CLASS;

typedef struct _PROCESS_BASIC_INFORMATION
{
	DWORD ExitStatus;
	DWORD PebBaseAddress;
	DWORD AffinityMask;
	DWORD BasePriority;
	ULONG UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
}PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
}SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

/*typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;*/

typedef enum _SYSTEM_HANDLE_TYPE
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
}SYSTEM_HANDLE_TYPE;

//结构声明结束

//函数声明

extern "C" {
	NTSTATUS WINAPI RtlAdjustPrivilege(
	ULONG Privilege,
	BOOLEAN Enable,
	BOOLEAN CurrentThread,
	PBOOLEAN Enabled);

	PIMAGE_NT_HEADERS RtlImageNtHeader(IN PVOID ModuleAddress);

    DWORD WINAPI RtlImageDirectoryEntryToData(
	IN DWORD BaseAddress,
	IN BOOL MappedAsImage,
	IN DWORD dwDataDirectoryIndex, 
	IN DWORD *Size);

	NTSTATUS WINAPI LdrLoadDll(
		IN PWCHAR PathToFile,
		IN ULONG Flags,
		IN PUNICODE_STRING ModuleFileName,
		IN PHANDLE ModuleHandle);

	NTSTATUS WINAPI NtOpenProcess(
		OUT PHANDLE ProcessHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN PCLIENT_ID ClientId);
	NTSTATUS WINAPI NtQueryInformationProcess(
		IN HANDLE ProcessHandle,
		IN PROCESS_CLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength);

	NTSTATUS WINAPI NtTerminateProcess(
		IN HANDLE ProcessHandle,
		IN NTSTATUS ExitStatus);

	NTSTATUS WINAPI NtSuspendProcess(IN HANDLE hProcess);

	HANDLE WINAPI ZwCurrentProcess();

	NTSTATUS WINAPI NtGetContextThread(IN HANDLE hThread, OUT PCONTEXT pContext);

	NTSTATUS WINAPI NtSetContextThread(IN HANDLE hThread, IN PCONTEXT pContext);

	NTSTATUS WINAPI NtResumeThread(IN HANDLE hThread, OUT PULONG SuspendCount);

    NTSTATUS WINAPI NtQuerySystemInformation(
    IN      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN      PVOID SystemInformation,
    IN      ULONG SystemInformationLength,
    OUT   PULONG ReturnLength);

NTSTATUS WINAPI NtQueryObject(
	IN HANDLE Handle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	OUT PVOID ObjectInformation,
	IN ULONG ObjectInformationLength,
	OUT PULONG ReturnLength);

	NTSTATUS WINAPI NtCreateFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer,
	IN ULONG EaLength);

	NTSTATUS WINAPI NtOpenFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions);

	NTSTATUS WINAPI NtReadFile(
	IN HANDLE FileHandle,
	IN HANDLE Event,
	IN PIO_APC_ROUTINE ApcRoutine,
	IN PVOID ApcContext,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset,
	IN PULONG Key);

    NTSTATUS WINAPI NtWriteFile(
    IN HANDLE FileHandle,
	IN HANDLE Event,
	IN PIO_APC_ROUTINE ApcRoutine,
	IN PVOID ApcContext,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset,
	IN PULONG Key);

	NTSTATUS WINAPI NtDeleteFile(IN POBJECT_ATTRIBUTES ObjectAttributes);

	NTSTATUS WINAPI NtClose(IN HANDLE Handle);

	NTSTATUS WINAPI NtQueryVirtualMemory(
		IN HANDLE ProcessHandle,
		IN PVOID BaseAddress,
		IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
		OUT PVOID MemoryInformation,
		IN ULONG MemoryInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	NTSTATUS WINAPI NtAllocateVirtualMemory(
		IN HANDLE hProcess,
		IN PVOID *BaseAddress,
		IN ULONG_PTR ZeroBits,
		IN PSIZE_T RegionSize,
		IN ULONG AllocationType,
		IN ULONG Protect);

	NTSTATUS WINAPI NtWriteVirtualMemory(
		IN HANDLE hProcess,
		IN PVOID BaseAddress,
		IN PVOID Buffer,
		IN ULONG NumberOfBytesToWrite,
		OUT PULONG NumberOfBytesWritten);

	NTSTATUS WINAPI NtReadVirtualMemory(
		IN HANDLE hProcess,
		IN PVOID BaseAddress,
		OUT PVOID Buffer,
		IN ULONG NumberOfBytesToRead,
		OUT PULONG NumberOfBytesReaded);

	NTSTATUS WINAPI NtProtectVirtualMemory(
		IN HANDLE hProcess,
		IN PVOID *BaseAddress,
		IN PULONG NumberOfBytesToProtect,
		IN ULONG NewAccessProtection,
		OUT PULONG OldAccessProtection);

	NTSTATUS WINAPI NtFreeVirtualMemory(
		IN HANDLE hProcess,
		IN PVOID *BaseAddress,
		IN PSIZE_T RegionSize,
		IN ULONG FreeType);

	NTSTATUS WINAPI ZwDuplicateObject(
		IN HANDLE  SourceProcessHandle,
		IN HANDLE  SourceHandle,
		IN HANDLE  TargetProcessHandle,
		OUT PHANDLE  TargetHandle,
		IN ACCESS_MASK  DesiredAccess,
		IN ULONG  Attributes,
		IN ULONG  Options);
}