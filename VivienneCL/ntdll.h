#pragma once

#include <Windows.h>


typedef _Return_type_success_(return >= 0) LONG NTSTATUS;


#pragma region Preprocessor

//=============================================================================
// NTSTATUS Codes
//=============================================================================
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_NO_MORE_ENTRIES           ((NTSTATUS)0x8000001AL)
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
#define STATUS_INVALID_PAGE_PROTECTION   ((NTSTATUS)0xC0000045L)
#define STATUS_INTERNAL_ERROR            ((NTSTATUS)0xC00000E5L)
#define STATUS_PROCEDURE_NOT_FOUND       ((NTSTATUS)0xC000007AL)

//=============================================================================
// Sections
//=============================================================================
#define SEC_NO_CHANGE 0x00400000

//=============================================================================
// Code Integrity
//=============================================================================
#define CODEINTEGRITY_OPTION_ENABLED                    0x00000001
#define CODEINTEGRITY_OPTION_TESTSIGN                   0x00000002
#define CODEINTEGRITY_OPTION_UMCI_ENABLED               0x00000004
#define CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED     0x00000008
#define CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED 0x00000010
#define CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED          0x00000080
#define CODEINTEGRITY_OPTION_FLIGHTING_ENABLED          0x00000200

//=============================================================================
// Paging
//=============================================================================
#ifndef PAGE_SIZE
#define PAGE_SIZE               0x1000
#endif
#define PAGE_ALIGN(Va)          ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))
#define ROUND_TO_PAGES(Size) \
    (((ULONG_PTR)(Size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

//=============================================================================
// Alignment
//=============================================================================
#define ALIGN_DOWN_BY(length, alignment) \
    ((ULONG_PTR)(length) & ~(alignment - 1))

#define ALIGN_UP_BY(length, alignment) \
    (ALIGN_DOWN_BY(((ULONG_PTR)(length) + alignment - 1), alignment))

#define ALIGN_DOWN_POINTER_BY(address, alignment) \
    ((PVOID)((ULONG_PTR)(address) & ~((ULONG_PTR)alignment - 1)))

#define ALIGN_UP_POINTER_BY(address, alignment) \
    (ALIGN_DOWN_POINTER_BY(((ULONG_PTR)(address) + alignment - 1), alignment))

#define ALIGN_DOWN(length, type) \
    ALIGN_DOWN_BY(length, sizeof(type))

#define ALIGN_UP(length, type) \
    ALIGN_UP_BY(length, sizeof(type))

#define ALIGN_DOWN_POINTER(address, type) \
    ALIGN_DOWN_POINTER_BY(address, sizeof(type))

#define ALIGN_UP_POINTER(address, type) \
    ALIGN_UP_POINTER_BY(address, sizeof(type))

//  Checks if 1st argument is aligned on given power of 2 boundary specified
//  by 2nd argument
#define IS_ALIGNED(_pointer, _alignment) \
    ((((ULONG_PTR) (_pointer)) & ((_alignment) - 1)) == 0)

//=============================================================================
// Objects
//=============================================================================
#define OBJ_CASE_INSENSITIVE    0x00000040L

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

#pragma endregion Preprocessor


#pragma region Enumerations

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

#pragma endregion Enumerations


#pragma region Types

typedef _Null_terminated_ CHAR *PSZ;
typedef _Null_terminated_ CONST char *PCSZ;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;
typedef const ANSI_STRING *PCANSI_STRING;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef
VOID
(NTAPI *PIO_APC_ROUTINE) (
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved
    );

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
{
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG NumberOfModules;
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

typedef LONG KPRIORITY;

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
    WrSpare0,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    WrAlertByThreadId,
    WrDeferredPreempt,
    WrPhysicalFault,
    MaximumWaitReason
} KWAIT_REASON;

typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER Reserved1[3];
    ULONG Reserved2;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG Reserved3;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

#pragma endregion Types


#pragma region Prototypes

EXTERN_C
NTSTATUS
NTAPI
NtQuerySystemInformation(
    _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Inout_   PVOID                    SystemInformation,
    _In_      ULONG                    SystemInformationLength,
    _Out_opt_ PULONG                   ReturnLength
);

EXTERN_C
VOID
NTAPI
RtlRaiseException(
    _In_ PEXCEPTION_RECORD ExceptionRecord
);

EXTERN_C
NTSTATUS
NTAPI
NtDeviceIoControlFile(
    _In_  HANDLE           FileHandle,
    _In_  HANDLE           Event,
    _In_  PIO_APC_ROUTINE  ApcRoutine,
    _In_  PVOID            ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_  ULONG            IoControlCode,
    _In_  PVOID            InputBuffer,
    _In_  ULONG            InputBufferLength,
    _Out_ PVOID            OutputBuffer,
    _In_  ULONG            OutputBufferLength
);

EXTERN_C
NTSTATUS
NTAPI
NtQueryPortInformationProcess();

EXTERN_C
NTSTATUS
NTAPI
NtDelayExecution(
    _In_ BOOLEAN Alertable,
    _In_ PLARGE_INTEGER DelayInterval
);

EXTERN_C
NTSTATUS
NTAPI
NtOpenSection(
    _Out_ PHANDLE            SectionHandle,
    _In_  ACCESS_MASK        DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes
);

EXTERN_C
NTSTATUS
NTAPI
NtCreateSection(
    _Out_    PHANDLE            SectionHandle,
    _In_     ACCESS_MASK        DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER     MaximumSize,
    _In_     ULONG              SectionPageProtection,
    _In_     ULONG              AllocationAttributes,
    _In_opt_ HANDLE             FileHandle
);

EXTERN_C
NTSTATUS
NTAPI
NtMapViewOfSection(
    _In_        HANDLE          SectionHandle,
    _In_        HANDLE          ProcessHandle,
    _Inout_     PVOID           *BaseAddress,
    _In_        ULONG_PTR       ZeroBits,
    _In_        SIZE_T          CommitSize,
    _Inout_opt_ PLARGE_INTEGER  SectionOffset,
    _Inout_     PSIZE_T         ViewSize,
    _In_        SECTION_INHERIT InheritDisposition,
    _In_        ULONG           AllocationType,
    _In_        ULONG           Win32Protect
);

EXTERN_C
NTSTATUS
NTAPI
NtUnmapViewOfSection(
    _In_        HANDLE  ProcessHandle,
    _In_opt_    PVOID   BaseAddress
);

EXTERN_C
NTSTATUS
NTAPI
NtProtectVirtualMemory(
    _In_    HANDLE  ProcessHandle,
    _Inout_ PVOID*  BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_    ULONG   NewProtection,
    _Out_   PULONG  OldProtection
);

EXTERN_C
NTSTATUS
NTAPI
NtQueryVirtualMemory(
    _In_      HANDLE                   ProcessHandle,
    _In_opt_  PVOID                    BaseAddress,
    _In_      MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_     PVOID                    MemoryInformation,
    _In_      SIZE_T                   MemoryInformationLength,
    _Out_opt_ PSIZE_T                  ReturnLength
);

EXTERN_C
NTSTATUS
NTAPI
NtReadVirtualMemory(
    _In_        HANDLE  ProcessHandle,
    _In_        PVOID   BaseAddress,
    _Out_       PVOID   Buffer,
    _In_        SIZE_T  NumberOfBytesToRead,
    _Out_opt_   PSIZE_T NumberOfBytesReaded
);

EXTERN_C
NTSTATUS
NTAPI
NtWriteVirtualMemory(
    _In_        HANDLE  ProcessHandle,
    _In_        PVOID   BaseAddress,
    _In_        PVOID   Buffer,
    _In_        SIZE_T  NumberOfBytesToWrite,
    _Out_opt_   PSIZE_T NumberOfBytesWritten
);

EXTERN_C
NTSTATUS
NTAPI
RtlGetLastNtStatus();

EXTERN_C
NTSTATUS
NTAPI
NtQuerySystemInformation(
    _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Inout_   PVOID                    SystemInformation,
    _In_      ULONG                    SystemInformationLength,
    _Out_opt_ PULONG                   ReturnLength
);

EXTERN_C
NTSTATUS
NTAPI
NtLoadDriver(
    _In_ PUNICODE_STRING DriverServiceName
);

EXTERN_C
NTSTATUS
NTAPI
NtUnloadDriver(
    _In_ PUNICODE_STRING DriverServiceName
);

EXTERN_C
NTSTATUS
NTAPI
NtYieldExecution();

EXTERN_C
VOID
NTAPI
RtlInitUnicodeString(
    _Out_    PUNICODE_STRING DestinationString,
    _In_opt_ PCWSTR          SourceString
);

EXTERN_C
VOID
NTAPI
RtlInitAnsiString(
    PANSI_STRING          DestinationString,
    __drv_aliasesMem PCSZ SourceString
);

EXTERN_C
LONG
NTAPI
RtlCompareUnicodeString(
    _In_ PCUNICODE_STRING String1,
    _In_ PCUNICODE_STRING String2,
    _In_ BOOLEAN          CaseInSensitive
);

EXTERN_C
NTSTATUS
NTAPI
RtlAnsiStringToUnicodeString(
    PUNICODE_STRING DestinationString,
    PCANSI_STRING   SourceString,
    BOOLEAN         AllocateDestinationString
);

EXTERN_C
VOID
NTAPI
RtlFreeUnicodeString(
    PUNICODE_STRING UnicodeString
);

EXTERN_C
ULONG
RtlRandomEx(
    PULONG Seed
);

#pragma endregion Prototypes