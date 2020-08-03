/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#pragma once

#include <Windows.h>


typedef _Return_type_success_(return >= 0) LONG NTSTATUS;


//=============================================================================
// NTSTATUS Codes
//=============================================================================
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
#define STATUS_NOT_IMPLEMENTED           ((NTSTATUS)0xC0000002L)
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#define STATUS_INVALID_CID               ((NTSTATUS)0xC000000BL)
#define STATUS_NO_SUCH_DEVICE            ((NTSTATUS)0xC000000EL)
#define STATUS_NO_SUCH_FILE              ((NTSTATUS)0xC000000FL)
#define STATUS_INVALID_DEVICE_REQUEST    ((NTSTATUS)0xC0000010L)
#define STATUS_MORE_PROCESSING_REQUIRED  ((NTSTATUS)0xC0000016L)
#define STATUS_CONFLICTING_ADDRESSES     ((NTSTATUS)0xC0000018L)
#define STATUS_NO_MORE_ENTRIES           ((NTSTATUS)0x8000001AL)
#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
#define STATUS_INVALID_PAGE_PROTECTION   ((NTSTATUS)0xC0000045L)
#define STATUS_PROCEDURE_NOT_FOUND       ((NTSTATUS)0xC000007AL)
#define STATUS_INSUFFICIENT_RESOURCES    ((NTSTATUS)0xC000009AL)     // ntsubauth
#define STATUS_INSTRUCTION_MISALIGNMENT  ((NTSTATUS)0xC00000AAL)
#define STATUS_INTERNAL_ERROR            ((NTSTATUS)0xC00000E5L)
#define STATUS_INVALID_PARAMETER_1       ((NTSTATUS)0xC00000EFL)
#define STATUS_INVALID_PARAMETER_2       ((NTSTATUS)0xC00000F0L)
#define STATUS_INVALID_PARAMETER_3       ((NTSTATUS)0xC00000F1L)
#define STATUS_INVALID_PARAMETER_4       ((NTSTATUS)0xC00000F2L)
#define STATUS_INVALID_PARAMETER_5       ((NTSTATUS)0xC00000F3L)
#define STATUS_INVALID_PARAMETER_6       ((NTSTATUS)0xC00000F4L)
#define STATUS_INVALID_PARAMETER_7       ((NTSTATUS)0xC00000F5L)
#define STATUS_INVALID_PARAMETER_8       ((NTSTATUS)0xC00000F6L)
#define STATUS_INVALID_PARAMETER_9       ((NTSTATUS)0xC00000F7L)
#define STATUS_INVALID_PARAMETER_10      ((NTSTATUS)0xC00000F8L)
#define STATUS_INVALID_PARAMETER_11      ((NTSTATUS)0xC00000F9L)
#define STATUS_INVALID_PARAMETER_12      ((NTSTATUS)0xC00000FAL)
#define STATUS_INVALID_ADDRESS           ((NTSTATUS)0xC0000141L)
#define STATUS_DATATYPE_MISALIGNMENT_ERROR ((NTSTATUS)0xC00002C5L)

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

#define PAGE_SHIFT 12L

#define PAGE_ALIGN(Va)          ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))
#define ROUND_TO_PAGES(Size) \
    (((ULONG_PTR)(Size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

#define BYTE_OFFSET(Va) ((ULONG)((LONG_PTR)(Va) & (PAGE_SIZE - 1)))

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
    ((((ULONG_PTR) (_pointer)) & (((ULONG_PTR) (_alignment)) - 1)) == 0)

#define ADDRESS_AND_SIZE_TO_SPAN_PAGES(Va,Size) \
    ((BYTE_OFFSET (Va) + ((SIZE_T) (Size)) + (PAGE_SIZE - 1)) >> PAGE_SHIFT)

//=============================================================================
// Utility
//=============================================================================
#define ARGUMENT_PRESENT(ArgumentPointer)    (\
    (CHAR *)((ULONG_PTR)(ArgumentPointer)) != (CHAR *)(NULL) )

#define OFFSET_POINTER(Pointer, Offset, Type) \
    ((Type*)(((PUCHAR)(Pointer)) + (Offset)))

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define ZwCurrentProcess() NtCurrentProcess()
#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )
#define ZwCurrentThread() NtCurrentThread()
#define NtCurrentSession() ( (HANDLE)(LONG_PTR) -3 )
#define ZwCurrentSession() NtCurrentSession()

#ifndef FlagOn
#define FlagOn(_F,_SF)        ((_F) & (_SF))
#endif

#ifndef BooleanFlagOn
#define BooleanFlagOn(F,SF)   ((BOOLEAN)(((F) & (SF)) != 0))
#endif

#ifndef SetFlag
#define SetFlag(_F,_SF)       ((_F) |= (_SF))
#endif

#ifndef ClearFlag
#define ClearFlag(_F,_SF)     ((_F) &= ~(_SF))
#endif

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

//=============================================================================
// Enumerations
//=============================================================================
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemKernelDebuggerInformation = 35,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

//=============================================================================
// Types
//=============================================================================
typedef ULONG LOGICAL;
typedef ULONG *PLOGICAL;

typedef _Null_terminated_ CHAR *PSZ;
typedef _Null_terminated_ CONST char *PCSZ;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;
typedef const ANSI_STRING *PCANSI_STRING;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
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

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
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

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG NumberOfModules;
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

typedef LONG KPRIORITY;

typedef enum _KWAIT_REASON {
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

typedef struct _SYSTEM_THREAD_INFORMATION {
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

typedef struct _SYSTEM_PROCESS_INFORMATION {
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

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

//=============================================================================
// Inlines
//=============================================================================
FORCEINLINE
LOGICAL
MI_RESERVED_BITS_CANONICAL(
    _In_ PVOID VirtualAddress
)
{
    return ((ULONG64)(((LONG64)VirtualAddress >> 48) + 1) <= 1);
}

//=============================================================================
// Prototypes
//=============================================================================
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
NTSTATUS
NTAPI
NtWaitForSingleObject(
    _In_ HANDLE             Handle,
    _In_ BOOLEAN            Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
);

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
BOOLEAN
NTAPI
RtlEqualUnicodeString(
    _In_ PCUNICODE_STRING   String1,
    _In_ PCUNICODE_STRING   String2,
    _In_ BOOLEAN            CaseInSensitive
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
NTAPI
RtlRandomEx(
    PULONG Seed
);
