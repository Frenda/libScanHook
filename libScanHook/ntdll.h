#pragma once

#pragma comment(lib, "ntdll.lib")

extern "C"
{
	//宏
    #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
    #define InitializeObjectAttributes( p, n, a, r, s ) { (p)->Length = sizeof( OBJECT_ATTRIBUTES ); \
	  (p)->RootDirectory = r; (p)->Attributes = a; (p)->ObjectName = n; \
	  (p)->SecurityDescriptor = s; (p)->SecurityQualityOfService = NULL; }
    #define LDRP_RELOCATION_FINAL 0x2

	//类型
	typedef int NT_IO_APC_ROUTINE;
	typedef NT_IO_APC_ROUTINE *PNT_IO_APC_ROUTINE;
	typedef long NTSTATUS;
	typedef long KPRIORITY;

	//枚举类型
	typedef enum _NT_LDR_DDAG_STATE
	{
		LdrModulesMerged = -5,
		LdrModulesInitError = -4,
		LdrModulesSnapError = -3,
		LdrModulesUnloaded = -2,
		LdrModulesUnloading = -1,
		LdrModulesPlaceHolder = 0,
		LdrModulesMapping = 1,
		LdrModulesMapped = 2,
		LdrModulesWaitingForDependencies = 3,
		LdrModulesSnapping = 4,
		LdrModulesSnapped = 5,
		LdrModulesCondensed = 6,
		LdrModulesReadyToInit = 7,
		LdrModulesInitializing = 8,
		LdrModulesReadyToRun = 9
	} NT_LDR_DDAG_STATE;

	typedef enum _NT_MEMORY_INFORMATION_CLASS
	{
		MemoryBasicInformation,
		MemoryWorkingSetList,
		MemorySectionName
	} NT_MEMORY_INFORMATION_CLASS;

	typedef enum _NT_SYSTEM_INFORMATION_CLASS
	{
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

	typedef enum _NT_PROCESS_INFORMATION_CLASS
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
	} NT_PROCESS_INFORMATION_CLASS;

	typedef enum _NT_THREAD_INFORMATION_CLASS
	{
		ThreadBasicInformation,
		ThreadTimes,
		ThreadPriority,
		ThreadBasePriority,
		ThreadAffinityMask,
		ThreadImpersonationToken,
		ThreadDescriptorTableEntry,
		ThreadEnableAlignmentFaultFixup,
		ThreadEventPair,
		ThreadQuerySetWin32StartAddress,
		ThreadZeroTlsCell,
		ThreadPerformanceCount,
		ThreadAmILastThread,
		ThreadIdealProcessor,
		ThreadPriorityBoost,
		ThreadSetTlsArrayAddress,
		ThreadIsIoPending,
		ThreadHideFromDebugger
	} NT_THREAD_INFORMATION_CLASS;

	typedef enum _NT_FILE_INFORMATION_CLASS
	{
		FileDirectoryInformation = 1,
		FileFullDirectoryInformation = 2,
		FileBothDirectoryInformation = 3,
		FileBasicInformation = 4,
		FileStandardInformation = 5,
		FileInternalInformation = 6,
		FileEaInformation = 7,
		FileAccessInformation = 8,
		FileNameInformation = 9,
		FileRenameInformation = 10,
		FileLinkInformation = 11,
		FileNamesInformation = 12,
		FileDispositionInformation = 13,
		FilePositionInformation = 14,
		FileFullEaInformation = 15,
		FileModeInformation = 16,
		FileAlignmentInformation = 17,
		FileAllInformation = 18,
		FileAllocationInformation = 19,
		FileEndOfFileInformation = 20,
		FileAlternateNameInformation = 21,
		FileStreamInformation = 22,
		FilePipeInformation = 23,
		FilePipeLocalInformation = 24,
		FilePipeRemoteInformation = 25,
		FileMailslotQueryInformation = 26,
		FileMailslotSetInformation = 27,
		FileCompressionInformation = 28,
		FileObjectIdInformation = 29,
		FileCompletionInformation = 30,
		FileMoveClusterInformation = 31,
		FileQuotaInformation = 32,
		FileReparsePointInformation = 33,
		FileNetworkOpenInformation = 34,
		FileAttributeTagInformation = 35,
		FileTrackingInformation = 36,
		FileIdBothDirectoryInformation = 37,
		FileIdFullDirectoryInformation = 38,
		FileValidDataLengthInformation = 39,
		FileShortNameInformation = 40,
		FileIoCompletionNotificationInformation = 41,
		FileIoStatusBlockRangeInformation = 42,
		FileIoPriorityHintInformation = 43,
		FileSfioReserveInformation = 44,
		FileSfioVolumeInformation = 45,
		FileHardLinkInformation = 46,
		FileProcessIdsUsingFileInformation = 47,
		FileNormalizedNameInformation = 48,
		FileNetworkPhysicalNameInformation = 49,
		FileIdGlobalTxDirectoryInformation = 50,
		FileIsRemoteDeviceInformation = 51,
		FileUnusedInformation = 52,
		FileNumaNodeInformation = 53,
		FileStandardLinkInformation = 54,
		FileRemoteProtocolInformation = 55,
		FileRenameInformationBypassAccessCheck = 56,
		FileLinkInformationBypassAccessCheck = 57,
		FileVolumeNameInformation = 58,
		FileIdInformation = 59,
		FileIdExtdDirectoryInformation = 60,
		FileReplaceCompletionInformation = 61,
		FileHardLinkFullIdInformation = 62,
		FileMaximumInformation = 63,
	}NT_FILE_INFORMATION_CLASS;

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
	} NT_SYSTEM_HANDLE_TYPE;

	typedef enum _NT_KEY_INFORMATION_CLASS
	{
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

	typedef enum _NT_KEY_VALUE_INFORMATION_CLASS
	{
		KeyValueBasicInformation = 0,
		KeyValueFullInformation,
		KeyValuePartialInformation,
		KeyValueFullInformationAlign64,
		KeyValuePartialInformationAlign64,
		MaxKeyValueInfoClass
	} NT_KEY_VALUE_INFORMATION_CLASS;

	typedef enum _NT_OBJECT_INFORMATION_CLASS
	{
		ObjectBasicInformation,
		ObjectNameInformation,
		ObjectTypeInformation,
		ObjectAllInformation,
		ObjectDataInformation
	} NT_OBJECT_INFORMATION_CLASS;

	typedef enum _NT_LDR_DLL_LOAD_REASON
	{
		LoadReasonStaticDependency = 0,
		LoadReasonStaticForwarderDependency = 1,
		LoadReasonDynamicForwarderDependency = 2,
		LoadReasonDelayloadDependency = 3,
		LoadReasonDynamicLoad = 4,
		LoadReasonAsImageLoad = 5,
		LoadReasonAsDataLoad = 6,
		LoadReasonUnknown = -1
	} NT_LDR_DLL_LOAD_REASON;

	typedef enum _NT_SECTION_INFORMATION_CLASS
	{
		SectionBasicInformation,
		SectionImageInformation
	} NT_SECTION_INFORMATION_CLASS;

	typedef enum _NT_SECTION_INHERIT
	{
		ViewShare = 1,
		ViewUnmap
	} NT_SECTION_INHERIT;

	typedef enum _NT_LPC_TYPE
	{
		LPC_NEW_MESSAGE,
		LPC_REQUEST,
		LPC_REPLY,
		LPC_DATAGRAM,
		LPC_LOST_REPLY,
		LPC_PORT_CLOSED,
		LPC_CLIENT_DIED,
		LPC_EXCEPTION,
		LPC_DEBUG_EVENT,
		LPC_ERROR_EVENT,
		LPC_CONNECTION_REQUEST
	} NT_LPC_TYPE;

	//结构
	typedef struct _NT_ACTIVATION_CONTEXT
	{
	} NT_ACTIVATION_CONTEXT, *PNT_ACTIVATION_CONTEXT;

	typedef struct _NT_ACTIVATION_CONTEXT_DATA
	{
	} NT_ACTIVATION_CONTEXT_DATA, *PNT_ACTIVATION_CONTEXT_DATA;

	typedef struct _NT_ASSEMBLY_STORAGE_MAP
	{
	} NT_ASSEMBLY_STORAGE_MAP, *PNT_ASSEMBLY_STORAGE_MAP;

	typedef struct _NT_FLS_CALLBACK_INFO
	{
	} NT_FLS_CALLBACK_INFO, *PNT_FLS_CALLBACK_INFO;

	typedef struct _NT_LDRP_DLL_SNAP_CONTEXT
	{
	} NT_LDRP_DLL_SNAP_CONTEXT, *PNT_LDRP_DLL_SNAP_CONTEXT;

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
	} NT_ANSI_STRING, *PNT_ANSI_STRING;

	typedef struct _NT_UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} NT_UNICODE_STRING, *PNT_UNICODE_STRING;

	typedef const NT_UNICODE_STRING *PCNT_UNICODE_STRING;

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
	} NT_LARGE_INTEGER, *PNT_LARGE_INTEGER;

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
	} NT_ULARGE_INTEGER, *PNT_ULARGE_INTEGER;

	typedef struct _NT_CURDIR
	{
		NT_UNICODE_STRING DosPath;
		void *Handle;
	} NT_CURDIR, *PNT_CURDIR;

	typedef struct _NT_CLIENT_ID
	{
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	} NT_CLIENT_ID, *PNT_CLIENT_ID;

	typedef struct _NT_RTL_DRIVE_LETTER_CURDIR
	{
		UINT16 Flags;
		UINT16  Length;
		ULONG TimeStamp;
		NT_ANSI_STRING DosPath;
	} NT_RTL_DRIVE_LETTER_CURDIR, *PNT_RTL_DRIVE_LETTER_CURDIR;

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
	} NT_RTL_USER_PROCESS_PARAMETERS, *PNT_RTL_USER_PROCESS_PARAMETERS;

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
	} NT_RTL_CRITICAL_SECTION_DEBUG, *PNT_RTL_CRITICAL_SECTION_DEBUG;

	typedef struct _NT_RTL_CRITICAL_SECTION
	{
		struct _NT_RTL_CRITICAL_SECTION_DEBUG *DebugInfo;
		LONG LockCount;
		LONG RecursionCount;
		PVOID OwningThread;
		PVOID LockSemaphore;
		ULONG SpinCount;
	} NT_RTL_CRITICAL_SECTION, *PNT_RTL_CRITICAL_SECTION;

	typedef struct _NT_LDR_SERVICE_TAG_RECORD
	{
		struct _NT_LDR_SERVICE_TAG_RECORD *Next;
		ULONG ServiceTag;
	} NT_LDR_SERVICE_TAG_RECORD, *PNT_LDR_SERVICE_TAG_RECORD;

	typedef struct _NT_SINGLE_LIST_ENTRY
	{
		struct _NT_SINGLE_LIST_ENTRY *Next;
	} NT_SINGLE_LIST_ENTRY, *PNT_SINGLE_LIST_ENTRY;

	typedef struct _NT_LDRP_CSLIST
	{
		PNT_SINGLE_LIST_ENTRY Tail;
	} NT_LDRP_CSLIST, *PNT_LDRP_CSLIST;

	typedef struct _NT_LDR_DDAG_NODE
	{
		NT_LIST_ENTRY Modules;
		PNT_LDR_SERVICE_TAG_RECORD ServiceTagList;
		ULONG LoadCount;
		ULONG ReferenceCount;
		ULONG DependencyCount;
		union
		{
			NT_LDRP_CSLIST Dependencies;
			NT_SINGLE_LIST_ENTRY RemovalLink;
		};
		NT_LDRP_CSLIST IncomingDependencies;
		NT_LDR_DDAG_STATE State;
		NT_SINGLE_LIST_ENTRY CondenseLink;
		ULONG PreorderNumber;
		ULONG LowestLink;
	} NT_LDR_DDAG_NODE, *PNT_LDR_DDAG_NODE;

	typedef struct _NT_RTL_BALANCED_NODE
	{
		union
		{
			struct _NT_RTL_BALANCED_NODE *Children[2];
			struct
			{
				struct _NT_RTL_BALANCED_NODE *Left;
				struct _NT_RTL_BALANCED_NODE *Right;
			};
			ULONG ParentValue;
		};
	} NT_RTL_BALANCED_NODE, *PNT_RTL_BALANCED_NODE;

	typedef struct _NT_LDR_DATA_TABLE_ENTRY
	{
		NT_LIST_ENTRY InLoadOrderLinks;
		NT_LIST_ENTRY InMemoryOrderLinks;
		union
		{
			NT_LIST_ENTRY InInitializationOrderLinks;
			NT_LIST_ENTRY InProgressLinks;
		};
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		NT_UNICODE_STRING FullDllName;
		NT_UNICODE_STRING BaseDllName;
		union
		{
			UCHAR FlagGroup[4];
			ULONG Flags;
		};
		WORD ObsoleteLoadCount;
		WORD TlsIndex;
		NT_LIST_ENTRY HashLinks;
		ULONG TimeDateStamp;
		PNT_ACTIVATION_CONTEXT EntryPointActivationContext;
		PVOID Spare;
		PNT_LDR_DDAG_NODE DdagNode;
		PNT_LIST_ENTRY NodeModuleLink;
		PNT_LDRP_DLL_SNAP_CONTEXT SnapContext;
		PVOID ParentDllBase;
		PVOID SwitchBackContext;
		PNT_RTL_BALANCED_NODE BaseAddressIndexNode;
		PNT_RTL_BALANCED_NODE MappingInfoIndexNode;
		ULONG OriginalBase;
		NT_LARGE_INTEGER LoadTime;
		ULONG BaseNameHashValue;
		NT_LDR_DLL_LOAD_REASON LoadReason;
		ULONG ImplicitPathOptions;
	} NT_LDR_DATA_TABLE_ENTRY, *PNT_LDR_DATA_TABLE_ENTRY;

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
	} NT_PEB_LDR_DATA, *PNT_PEB_LDR_DATA;

	typedef struct _NT_RTL_ACTIVATION_CONTEXT_STACK_FRAME
	{
		struct _NT_RTL_ACTIVATION_CONTEXT_STACK_FRAME *Previous;
		PNT_ACTIVATION_CONTEXT ActivationContext;
		ULONG Flags;
	} NT_RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PNT_RTL_ACTIVATION_CONTEXT_STACK_FRAME;

	typedef struct _NT_ACTIVATION_CONTEXT_STACK
	{
		PNT_RTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
		NT_LIST_ENTRY FrameListCache;
		ULONG Flags;
		ULONG NextCookieSequenceNumber;
		ULONG StackId;
	} NT_ACTIVATION_CONTEXT_STACK, *PNT_ACTIVATION_CONTEXT_STACK;

	typedef struct _NT_TEB_ACTIVE_FRAME_CONTEXT
	{
		ULONG Flags;
		char *FrameName;
	} NT_TEB_ACTIVE_FRAME_CONTEXT, *PNT_TEB_ACTIVE_FRAME_CONTEXT;

	typedef struct _NT_TEB_ACTIVE_FRAME
	{
		ULONG Flags;
		struct _NT_TEB_ACTIVE_FRAME *Previous;
		PNT_TEB_ACTIVE_FRAME_CONTEXT Context;
	} NT_TEB_ACTIVE_FRAME, *PNT_TEB_ACTIVE_FRAME;

	typedef struct _NT_GDI_TEB_BATCH
	{
		ULONG Offset;
		ULONG HDC;
		ULONG Buffer[310];
	} NT_GDI_TEB_BATCH, *PNT_GDI_TEB_BATCH;

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
	} NT_PEB, *PNT_PEB;

	typedef struct _NT_INITIAL_TEB
	{
		struct 
		{
			PVOID OldStackBase;
			PVOID OldStackLimit;
		} OldInitialTeb;
		PVOID StackBase;
		PVOID StackLimit;
		PVOID StackAllocationBase;
	} NT_INITIAL_TEB, *PNT_INITIAL_TEB;

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
	} NT_TEB, *PNT_TEB;

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
	} NT_VM_COUNTERS, *PNT_VM_COUNTERS;

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

	typedef struct _NT_PROCESS_BASIC_INFORMATION
	{
		DWORD ExitStatus;
		DWORD PebBaseAddress;
		DWORD AffinityMask;
		DWORD BasePriority;
		ULONG UniqueProcessId;
		ULONG InheritedFromUniqueProcessId;
	} NT_PROCESS_BASIC_INFORMATION, *PNT_PROCESS_BASIC_INFORMATION;

	typedef struct _NT_SYSTEM_HANDLE_INFORMATION
	{
		ULONG ProcessId;
		UCHAR ObjectTypeNumber;
		UCHAR Flags;
		USHORT Handle;
		PVOID Object;
		ACCESS_MASK GrantedAccess;
	} NT_SYSTEM_HANDLE_INFORMATION, *PNT_SYSTEM_HANDLE_INFORMATION;

	typedef struct _NT_PORT_MESSAGE
	{
		union
		{
			struct
			{
				USHORT DataLength;
				USHORT TotalLength;
			} s1;
			ULONG Length;
		} u1;
		union
		{
			struct
			{
				USHORT Type;
				USHORT DataInfoOffset;
			} s2;
			ULONG ZeroInit;
		} u2;
		union
		{
			NT_CLIENT_ID ClientId;
			double DoNotUseThisField;
		};
		ULONG MessageId;
		union
		{
			ULONG_PTR ClientViewSize;
			ULONG CallbackId;
		};
	} NT_PORT_MESSAGE, *PNT_PORT_MESSAGE;

	typedef struct _NT_PORT_VIEW
	{
		ULONG Length;
		HANDLE SectionHandle;
		ULONG SectionOffset;
		ULONG ViewSize;
		PVOID ViewBase;
		PVOID ViewRemoteBase;
	} NT_PORT_VIEW, *PNT_PORT_VIEW;

	typedef struct _NT_REMOTE_PORT_VIEW
	{
		ULONG Length;
		ULONG ViewSize;
		PVOID ViewBase;
	} NT_REMOTE_PORT_VIEW, *PNT_REMOTE_PORT_VIEW;

	typedef struct _NT_RTL_PROCESS_MODULE_INFORMATION
	{
		ULONG Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		CHAR FullPathName[256];
	} NT_RTL_PROCESS_MODULE_INFORMATION, *PNT_RTL_PROCESS_MODULE_INFORMATION;

	typedef struct _NT_RTL_PROCESS_MODULE_INFORMATION_EX
	{
		ULONG NextOffset;
		NT_RTL_PROCESS_MODULE_INFORMATION BaseInfo;
		ULONG ImageCheckSum;
		ULONG TimeDateStamp;
		PVOID DefaultBase;
	} NT_RTL_PROCESS_MODULE_INFORMATION_EX, *PNT_RTL_PROCESS_MODULE_INFORMATION_EX;

	typedef struct _NT_RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		NT_RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} NT_RTL_PROCESS_MODULES, *PNT_RTL_PROCESS_MODULES;

	typedef struct _NT_RTL_PROCESS_BACKTRACE_INFORMATION
	{
		PVOID SymbolicBackTrace;
		ULONG TraceCount;
		USHORT Index;
		USHORT Depth;
		PVOID BackTrace[16];
	} NT_RTL_PROCESS_BACKTRACE_INFORMATION, *PNT_RTL_PROCESS_BACKTRACE_INFORMATION;

	typedef struct _NT_RTL_PROCESS_BACKTRACES
	{
		ULONG CommittedMemory;
		ULONG ReservedMemory;
		ULONG NumberOfBackTraceLookups;
		ULONG NumberOfBackTraces;
		NT_RTL_PROCESS_BACKTRACE_INFORMATION BackTraces[1];
	} NT_RTL_PROCESS_BACKTRACES, *PNT_RTL_PROCESS_BACKTRACES;

	typedef struct _NT_RTL_HEAP_ENTRY
	{
		SIZE_T Size;
		USHORT Flags;
		USHORT AllocatorBackTraceIndex;
		union
		{
			struct
			{
				SIZE_T Settable;
				ULONG Tag;
			} s1;
			struct
			{
				SIZE_T CommittedSize;
				PVOID FirstBlock;
			} s2;
		} u;
	} NT_RTL_HEAP_ENTRY, *PNT_RTL_HEAP_ENTRY;

	typedef struct _NT_RTL_HEAP_TAG
	{
		ULONG NumberOfAllocations;
		ULONG NumberOfFrees;
		SIZE_T BytesAllocated;
		USHORT TagIndex;
		USHORT CreatorBackTraceIndex;
		WCHAR TagName[24];
	} NT_RTL_HEAP_TAG, *PNT_RTL_HEAP_TAG;

	typedef struct _NT_RTL_HEAP_INFORMATION
	{
		PVOID BaseAddress;
		ULONG Flags;
		USHORT EntryOverhead;
		USHORT CreatorBackTraceIndex;
		SIZE_T BytesAllocated;
		SIZE_T BytesCommitted;
		ULONG NumberOfTags;
		ULONG NumberOfEntries;
		ULONG NumberOfPseudoTags;
		ULONG PseudoTagGranularity;
		ULONG Reserved[4];
		PNT_RTL_HEAP_TAG Tags;
		PNT_RTL_HEAP_ENTRY Entries;
	} NT_RTL_HEAP_INFORMATION, *PNT_RTL_HEAP_INFORMATION;

	typedef struct _NT_RTL_PROCESS_HEAPS
	{
		ULONG NumberOfHeaps;
		NT_RTL_HEAP_INFORMATION Heaps[1];
	} NT_RTL_PROCESS_HEAPS, *PNT_RTL_PROCESS_HEAPS;

	typedef struct _NT_RTL_PROCESS_LOCK_INFORMATION
	{
		PVOID Address;
		USHORT Type;
		USHORT CreatorBackTraceIndex;
		ULONG OwnerThreadId;
		ULONG ActiveCount;
		ULONG ContentionCount;
		ULONG EntryCount;
		ULONG RecursionCount;
		ULONG NumberOfSharedWaiters;
		ULONG NumberOfExclusiveWaiters;
	} NT_RTL_PROCESS_LOCK_INFORMATION, *PNT_RTL_PROCESS_LOCK_INFORMATION;

	typedef struct _NT_RTL_PROCESS_LOCKS
	{
		ULONG NumberOfLocks;
		NT_RTL_PROCESS_LOCK_INFORMATION Locks[1];
	} NT_RTL_PROCESS_LOCKS, *PNT_RTL_PROCESS_LOCKS;

	typedef struct _NT_RTL_PROCESS_VERIFIER_OPTIONS
	{
		ULONG SizeStruct;
		ULONG Option;
		UCHAR OptionData[1];
	} NT_RTL_PROCESS_VERIFIER_OPTIONS, *PNT_RTL_PROCESS_VERIFIER_OPTIONS;

	typedef struct _NT_RTL_DEBUG_INFORMATION
	{
		HANDLE SectionHandleClient;
		PVOID ViewBaseClient;
		PVOID ViewBaseTarget;
		ULONG ViewBaseDelta;
		HANDLE EventPairClient;
		PVOID EventPairTarget;
		HANDLE TargetProcessId;
		HANDLE TargetThreadHandle;
		ULONG Flags;
		ULONG OffsetFree;
		ULONG CommitSize;
		ULONG ViewSize;
		union
		{
			PNT_RTL_PROCESS_MODULES Modules;
			PNT_RTL_PROCESS_MODULE_INFORMATION_EX ModulesEx;
		};
		PNT_RTL_PROCESS_BACKTRACES BackTraces;
		PNT_RTL_PROCESS_HEAPS Heaps;
		PNT_RTL_PROCESS_LOCKS Locks;
		HANDLE SpecificHeap;
		HANDLE TargetProcessHandle;
		NT_RTL_PROCESS_VERIFIER_OPTIONS VerifierOptions;
		HANDLE ProcessHeap;
		HANDLE CriticalSectionHandle;
		HANDLE CriticalSectionOwnerThread;
		PVOID Reserved[4];
	} NT_RTL_DEBUG_INFORMATION, *PNT_RTL_DEBUG_INFORMATION;

	typedef struct _NT_SECTION_BASIC_INFORMATION
	{
		ULONG  Unknown;
		ULONG SectionAttributes;
		NT_LARGE_INTEGER SectionSize;
	} NT_SECTION_BASIC_INFORMATION, *PNT_SECTION_BASIC_INFORMATION;

	typedef struct _NT_SECTION_IMAGE_INFORMATION 
	{
		PVOID EntryPoint;
		ULONG StackZeroBits;
		ULONG StackReserved;
		ULONG StackCommit;
		ULONG ImageSubsystem;
		WORD SubSystemVersionLow;
		WORD SubSystemVersionHigh;
		ULONG Unknown1;
		ULONG ImageCharacteristics;
		ULONG ImageMachineType;
		ULONG Unknown2[3];
	} NT_SECTION_IMAGE_INFORMATION, *PNT_SECTION_IMAGE_INFORMATION;

	typedef struct _NT_JOB_SET_ARRAY
	{
		HANDLE JobHandle;
		ULONG MemberLevel;
		ULONG Flags;
	} NT_JOB_SET_ARRAY, *PNT_JOB_SET_ARRAY;

	//函数声明
	//Unicode/Ansi string functions
	VOID NTAPI RtlInitUnicodeString(OUT PNT_UNICODE_STRING DestinationString, IN PCWSTR SourceString);

	LONG NTAPI RtlCompareUnicodeString(IN  PCNT_UNICODE_STRING String1, IN  PCNT_UNICODE_STRING String2, IN BOOLEAN CaseInSensitive);

	NTSTATUS NTAPI RtlStringFromGUID(IN REFGUID Guid, OUT PNT_UNICODE_STRING GuidString);

	NTSTATUS NTAPI RtlAppendUnicodeStringToString(IN PNT_UNICODE_STRING Destination, IN PNT_UNICODE_STRING Source);

	NTSTATUS RtlAppendUnicodeToString(IN PNT_UNICODE_STRING Destination, IN PCWSTR Source);

	VOID RtlCopyUnicodeString(IN PNT_UNICODE_STRING DestinationString, IN PCNT_UNICODE_STRING SourceString);

	BOOLEAN RtlEqualUnicodeString(IN PCNT_UNICODE_STRING String1, IN PCNT_UNICODE_STRING String2, IN BOOLEAN CaseInSensitive);

	VOID NTAPI RtlFreeUnicodeString(IN PNT_UNICODE_STRING UnicodeString);

	VOID NTAPI RtlInitAnsiString(OUT PNT_ANSI_STRING DestinationString, IN PCHAR SourceString);

	VOID NTAPI RtlFreeAnsiString(IN PNT_ANSI_STRING AnsiString);

	//Rtl Funtions
	NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

	PIMAGE_NT_HEADERS RtlImageNtHeader(IN PVOID ModuleAddress);

	DWORD NTAPI RtlImageDirectoryEntryToData(
		IN DWORD BaseAddress,
		IN BOOL MappedAsImage,
		IN DWORD dwDataDirectoryIndex,
		IN DWORD *Size);

	NTSTATUS NTAPI RtlQueryProcessDebugInformation(
		IN ULONG ProcessId,
		IN ULONG DebugInfoMask,
		IN OUT PNT_RTL_DEBUG_INFORMATION Buffer);

	PNT_RTL_DEBUG_INFORMATION NTAPI RtlCreateQueryDebugBuffer(IN ULONG Size, IN BOOLEAN EventPair);

	NTSTATUS NTAPI RtlDestroyQueryDebugBuffer(IN PNT_RTL_DEBUG_INFORMATION Buffer);
	
	NTSTATUS NTAPI RtlpQueryRemoteProcessModules(
		IN HANDLE ProcessHandle,
		IN PNT_RTL_PROCESS_MODULES Modules,
		IN ULONG Size,
		OUT PULONG ReturnedSize);

	//Ldr Functions
	NTSTATUS NTAPI LdrLoadDll(
		IN PWCHAR PathToFile,
		IN ULONG Flags,
		IN PNT_UNICODE_STRING ModuleFileName,
		IN PHANDLE ModuleHandle);

	//Process Funtions
	NTSTATUS NTAPI NtCreateProcess(
		OUT PHANDLE ProcessHandle,
		IN ACCESS_MASK DesiredAccess,
		IN PNT_OBJECT_ATTRIBUTES ObjectAttributes ,
		IN HANDLE ParentProcess,
		IN BOOLEAN InheritObjectTable,
		IN HANDLE SectionHandle,
		IN HANDLE DebugPort,
		IN HANDLE ExceptionPort);

	NTSTATUS NTAPI NtOpenProcess(
		OUT PHANDLE ProcessHandle,
		IN ACCESS_MASK DesiredAccess,
		IN PNT_OBJECT_ATTRIBUTES ObjectAttributes,
		IN PNT_CLIENT_ID ClientId);

	NTSTATUS NTAPI NtTerminateProcess(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus);

	NTSTATUS NTAPI NtSuspendProcess(IN HANDLE hProcess);

	NTSTATUS NTAPI NtGetNextProcess(
		HANDLE ProcessHandle,
		ACCESS_MASK DesiredAccess,
		ULONG HandleAttributes,
		ULONG Flags,
		PHANDLE NewProcessHandle);

	NTSTATUS NTAPI NtQueryInformationProcess(
		IN HANDLE ProcessHandle,
		IN NT_PROCESS_INFORMATION_CLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength);

	NTSTATUS NTAPI NtSetInformationProcess(
		IN HANDLE ProcessHandle,
		IN NT_PROCESS_INFORMATION_CLASS ProcessInformationClass,
		IN PVOID ProcessInformation,
		IN ULONG ProcessInformationLength);

	//Thread Funtions
	NTSTATUS NTAPI NtCreateThread(
		OUT PHANDLE ThreadHandle,
		IN ACCESS_MASK DesiredAccess,
		IN PNT_OBJECT_ATTRIBUTES ObjectAttributes,
		IN HANDLE ProcessHandle,
		OUT PNT_CLIENT_ID ClientId,
		IN PCONTEXT ThreadContext,
		IN PNT_INITIAL_TEB InitialTeb,
		IN BOOLEAN CreateSuspended);

	NTSTATUS NTAPI NtOpenThread(
		OUT PHANDLE ThreadHandle,
		IN ACCESS_MASK AccessMask,
		IN PNT_OBJECT_ATTRIBUTES ObjectAttributes,
		IN PNT_CLIENT_ID ClientId);

	NTSTATUS NTAPI NtTerminateThread(IN HANDLE ThreadHandle, IN NTSTATUS ExitStatus);

	NTSTATUS NTAPI NtGetNextThread(
		HANDLE ProcessHandle,
		HANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		ULONG HandleAttributes,
		ULONG Flags,
		PHANDLE NewThreadHandle);

	NTSTATUS NTAPI NtGetContextThread(IN HANDLE hThread, OUT PNT_CONTEXT pContext);

	NTSTATUS NTAPI NtSetContextThread(IN HANDLE hThread, IN PNT_CONTEXT pContext);

	NTSTATUS NTAPI NtResumeThread(IN HANDLE hThread, OUT PULONG SuspendCount);

	NTSTATUS NTAPI NtQueryInformationThread(
		IN HANDLE ThreadHandle,
		IN NT_THREAD_INFORMATION_CLASS ThreadInformationClass,
		OUT PVOID ThreadInformation,
		IN ULONG ThreadInformationLength,
		OUT PULONG ReturnLength);

	NTSTATUS ZwSetInformationThread(
		IN  HANDLE ThreadHandle,
		IN  NT_THREAD_INFORMATION_CLASS ThreadInformationClass,
		IN  PVOID ThreadInformation,
		IN  ULONG ThreadInformationLength);

	//File Funtions
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

	NTSTATUS WINAPI NtDeviceIoControlFile(
		IN HANDLE FileHandle,
		IN HANDLE Event,
		IN PNT_IO_APC_ROUTINE ApcRoutine,
		IN PVOID ApcContext,
		OUT PNT_IO_STATUS_BLOCK IoStatusBlock,
		IN ULONG IoControlCode,
		IN PVOID InputBuffer,
		IN ULONG InputBufferLength,
		OUT PVOID OutputBuffer,
		IN ULONG OutputBufferLength);

	NTSTATUS NtFsControlFile(
		IN HANDLE FileHandle,
		IN HANDLE Event,
		IN PNT_IO_APC_ROUTINE ApcRoutine,
		IN PVOID ApcContext,
		OUT PNT_IO_STATUS_BLOCK IoStatusBlock,
		IN ULONG FsControlCode,
		IN PVOID InputBuffer,
		IN ULONG InputBufferLength,
		OUT PVOID OutputBuffer,
		IN ULONG OutputBufferLength);

	NTSTATUS NTAPI NtDeleteFile(IN PNT_OBJECT_ATTRIBUTES ObjectAttributes);

	NTSTATUS NTAPI NtQueryInformationFile(
		IN HANDLE FileHandle,
		OUT PNT_IO_STATUS_BLOCK IoStatusBlock,
		OUT PVOID FileInformation,
		IN ULONG Length,
		IN NT_FILE_INFORMATION_CLASS FileInformationClass);

	NTSTATUS NTAPI NtSetInformationFile(
		IN HANDLE FileHandle,
		OUT PNT_IO_STATUS_BLOCK IoStatusBlock,
		IN PVOID FileInformation,
		IN ULONG Length,
		IN NT_FILE_INFORMATION_CLASS FileInformationClass);

	//VirtualMemory Funtions
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

	NTSTATUS NTAPI NtQueryVirtualMemory(
		IN HANDLE ProcessHandle,
		IN PVOID BaseAddress,
		IN NT_MEMORY_INFORMATION_CLASS MemoryInformationClass,
		OUT PVOID MemoryInformation,
		IN ULONG MemoryInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	//Section Funtions
	NTSTATUS NTAPI NtCreateSection(
		OUT PHANDLE SectionHandle,
		IN ULONG DesiredAccess,
		IN PNT_OBJECT_ATTRIBUTES ObjectAttributes,
		IN PNT_LARGE_INTEGER MaximumSize,
		IN ULONG PageAttributess,
		IN ULONG SectionAttributes,
		IN HANDLE FileHandle);

	NTSTATUS NTAPI NtOpenSection(OUT PHANDLE SectionHandle,IN ACCESS_MASK DesiredAccess, IN PNT_OBJECT_ATTRIBUTES ObjectAttributes);

	NTSTATUS NTAPI NtQuerySection(
		IN HANDLE SectionHandle,
		IN NT_SECTION_INFORMATION_CLASS InformationClass,
		OUT PVOID InformationBuffer,
		IN ULONG InformationBufferSize,
		OUT PULONG ResultLength);

	NTSTATUS NTAPI NtMapViewOfSection(
		IN HANDLE SectionHandle,
		IN HANDLE ProcessHandle,
		IN PVOID *BaseAddress,
		IN ULONG_PTR ZeroBits,
		IN SIZE_T CommitSize,
		IN PNT_LARGE_INTEGER SectionOffset,
		IN PSIZE_T ViewSize,
		IN NT_SECTION_INHERIT InheritDisposition,
		IN ULONG AllocationType,
		IN ULONG Win32Protect);

	NTSTATUS NTAPI NtUnmapViewOfSection(IN HANDLE ProcessHandle, IN PVOID BaseAddress);

	//Driver Function
	NTSTATUS NTAPI NtLoadDriver(IN PNT_UNICODE_STRING DriverServiceName);

	NTSTATUS NTAPI NtUnloadDriver(IN  PNT_UNICODE_STRING DriverServiceName);

	//LPC Funtions
	NTSTATUS NTAPI NtCreatePort(
		OUT PHANDLE PortHandle,
		IN PNT_OBJECT_ATTRIBUTES ObjectAttributes,
		IN ULONG MaxConnectInfoLength,
		IN ULONG MaxDataLength,
		OUT PULONG Reserved);

	NTSTATUS NTAPI NtConnectPort(
		OUT PHANDLE PortHandle,
		IN PNT_UNICODE_STRING PortName,
		IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
		IN  PNT_PORT_VIEW ClientView,
		OUT PNT_REMOTE_PORT_VIEW ServerView,
		OUT PULONG MaxMessageLength,
		IN PVOID ConnectionInformation,
		IN PULONG ConnectionInformationLength);

	NTSTATUS NTAPI NtListenPort(IN  HANDLE PortHandle, OUT PNT_PORT_MESSAGE RequestMessage);

	NTSTATUS NTAPI NtAcceptConnectPort(
		OUT PHANDLE PortHandle,
		IN  PVOID PortContext,
		IN  PNT_PORT_MESSAGE ConnectionRequest,
		IN  BOOLEAN AcceptConnection,
		IN  PNT_PORT_VIEW ServerView,
		OUT PNT_REMOTE_PORT_VIEW ClientView);

	NTSTATUS NTAPI NtCompleteConnectPort(IN  HANDLE PortHandle);

	NTSTATUS NTAPI NtRequestPort(IN  HANDLE PortHandle, IN  PNT_PORT_MESSAGE RequestMessage);

	NTSTATUS NTAPI NtRequestWaitReplyPort(
		IN  HANDLE PortHandle,
		IN  PNT_PORT_MESSAGE RequestMessage,
		OUT PNT_PORT_MESSAGE ReplyMessage);

	NTSTATUS NTAPI NtReplyPort(IN  HANDLE PortHandle, IN  PNT_PORT_MESSAGE ReplyMessage);

	NTSTATUS NTAPI NtReplyWaitReplyPort(IN  HANDLE PortHandle, IN PNT_PORT_MESSAGE ReplyMessage);

	NTSTATUS NTAPI NtReplyWaitReceivePort(
		IN  HANDLE PortHandle,
		OUT PHANDLE PortContext,
		IN  PNT_PORT_MESSAGE ReplyMessage,
		OUT PNT_PORT_MESSAGE ReceiveMessage);

	//Job Funtions
	NTSTATUS NTAPI NtCreateJobObject(OUT PHANDLE JobHandle, IN ACCESS_MASK DesiredAccess, IN PNT_OBJECT_ATTRIBUTES ObjectAttributes);

	NTSTATUS NTAPI NtAssignProcessToJobObject(IN HANDLE JobHandle, IN HANDLE ProcessHandle);

	NTSTATUS NTAPI NtCreateJobSet(IN ULONG NumJob, IN PNT_JOB_SET_ARRAY UserJobSet, IN ULONG 	Flags);

	NTSTATUS NTAPI NtTerminateJobObject(IN HANDLE JobHandle, IN NTSTATUS 	ExitStatus);

	//Registry Funtions
	NTSTATUS NTAPI NtCreateKey(
		OUT PHANDLE KeyHandle,
		IN  ACCESS_MASK DesiredAccess,
		IN  PNT_OBJECT_ATTRIBUTES ObjectAttributes,
		IN  ULONG TitleIndex,
		OPTIONAL  PNT_UNICODE_STRING Class,
		IN  ULONG CreateOptions,
		OPTIONAL PULONG Disposition);

	NTSTATUS NTAPI NtOpenKey(
		OUT PHANDLE KeyHandle,
		IN ACCESS_MASK DesiredAccess,
		IN PNT_OBJECT_ATTRIBUTES ObjectAttributes);

	NTSTATUS NTAPI NtEnumerateKey(
		IN HANDLE KeyHandle,
		IN ULONG Index,
		IN NT_KEY_INFORMATION_CLASS KeyInformationClass,
		IN PVOID KeyInformation,
		IN ULONG Length,
		IN PULONG ResultLength);

	NTSTATUS NTAPI NtDeleteKey(IN HANDLE KeyHandle);

	NTSTATUS NTAPI NtQueryValueKey(
		IN HANDLE KeyHandle,
		IN PNT_UNICODE_STRING ValueName,
		IN NT_KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
		OUT PVOID KeyValueInformation,
		IN ULONG Length,
		OUT PULONG ResultLength);

	NTSTATUS NTAPI NtSetValueKey(
		IN HANDLE KeyHandle,
		IN PNT_UNICODE_STRING ValueName,
		IN ULONG TitleIndex OPTIONAL,
		IN ULONG Type,
		IN PVOID Data,
		IN ULONG DataSize);

	NTSTATUS NTAPI NtDeleteValueKey(IN HANDLE KeyHandle, IN PNT_UNICODE_STRING ValueName);

	//Object Funtions
	NTSTATUS NTAPI NtQueryObject(
		IN HANDLE Handle,
		IN NT_OBJECT_INFORMATION_CLASS ObjectInformationClass,
		OUT PVOID ObjectInformation,
		IN ULONG ObjectInformationLength,
		OUT PULONG ReturnLength);

	NTSTATUS NTAPI NtSetInformationObject(
		IN HANDLE ObjectHandle,
		IN NT_OBJECT_INFORMATION_CLASS ObjectInformationClass,
		IN PVOID ObjectInformation,
		IN ULONG Length);

	NTSTATUS NTAPI NtDuplicateObject(
		IN HANDLE  SourceProcessHandle,
		IN HANDLE  SourceHandle,
		IN HANDLE  TargetProcessHandle,
		OUT PHANDLE  TargetHandle,
		IN ACCESS_MASK  DesiredAccess,
		IN ULONG  Attributes,
		IN ULONG  Options);

	NTSTATUS NTAPI NtClose(IN HANDLE Handle);

	//System Information Funtions
	NTSTATUS NTAPI NtQuerySystemInformation(
		IN NT_SYSTEM_INFORMATION_CLASS SystemInformationClass,
		IN PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength);

	NTSTATUS NTAPI NtSetSystemInformation(
		IN NT_SYSTEM_INFORMATION_CLASS SystemInformationClass,
		IN PVOID SystemInformation,
		IN ULONG SystemInformationLength);
}