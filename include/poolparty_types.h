#pragma once

// ============================================================================
// Typhon — Undocumented Thread Pool Structures & NT Types
// ============================================================================
// Reverse-engineered structures from ntdll thread pool internals.
// These are the actual in-memory layouts that worker threads operate on.
// Offsets verified against Windows 10 22H2 / 11 23H2 / Server 2022.
// ============================================================================

#include <windows.h>
#include <winternl.h>

// PROCESS_BASIC_INFORMATION — may already be in winternl.h but guard it
#ifndef _PROCESS_BASIC_INFORMATION_DEFINED
#define _PROCESS_BASIC_INFORMATION_DEFINED
typedef struct _PROCESS_BASIC_INFORMATION_EX {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION_EX;
#endif

// ============================================================================
// NT API Typedefs — resolved at runtime via PEB walking
// ============================================================================

// Worker Factory
typedef NTSTATUS(NTAPI* NtQueryInformationWorkerFactory_t)(
    HANDLE WorkerFactoryHandle,
    ULONG  WorkerFactoryInformationClass,
    PVOID  WorkerFactoryInformation,
    ULONG  WorkerFactoryInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* NtSetInformationWorkerFactory_t)(
    HANDLE WorkerFactoryHandle,
    ULONG  WorkerFactoryInformationClass,
    PVOID  WorkerFactoryInformation,
    ULONG  WorkerFactoryInformationLength
);

// I/O Completion
typedef NTSTATUS(NTAPI* NtSetIoCompletion_t)(
    HANDLE IoCompletionHandle,
    PVOID  KeyContext,
    PVOID  ApcContext,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation
);

// Timer2 (high-resolution timer — used by thread pool timer queue)
typedef NTSTATUS(NTAPI* NtCreateTimer2_t)(
    PHANDLE            TimerHandle,
    PVOID              Reserved1,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG              Attributes,
    ACCESS_MASK        DesiredAccess
);

typedef NTSTATUS(NTAPI* NtSetTimer2_t)(
    HANDLE             TimerHandle,
    PLARGE_INTEGER     DueTime,
    PLARGE_INTEGER     Period,
    PVOID              Parameters
);

// Process handle duplication
typedef NTSTATUS(NTAPI* NtDuplicateObject_t)(
    HANDLE      SourceProcessHandle,
    HANDLE      SourceHandle,
    HANDLE      TargetProcessHandle,
    PHANDLE     TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG       HandleAttributes,
    ULONG       Options
);

// Process open
typedef NTSTATUS(NTAPI* NtOpenProcess_t)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PVOID              ClientId  // CLIENT_ID*
);

// Memory operations (remote)
typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress,
    PVOID  Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress,
    PVOID  Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

typedef NTSTATUS(NTAPI* NtFreeVirtualMemory_t)(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    PSIZE_T RegionSize,
    ULONG   FreeType
);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    PSIZE_T RegionSize,
    ULONG   NewProtect,
    PULONG  OldProtect
);

// Section operations (for shared memory injection)
typedef NTSTATUS(NTAPI* NtCreateSection_t)(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle
);

typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID*          BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    ULONG           InheritDisposition,  // 1=ViewShare, 2=ViewUnmap
    ULONG           AllocationType,
    ULONG           Win32Protect
);

typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress
);

// Handle query
typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* NtQueryObject_t)(
    HANDLE Handle,
    ULONG  ObjectInformationClass,
    PVOID  ObjectInformation,
    ULONG  ObjectInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE Handle);

// ALPC
typedef NTSTATUS(NTAPI* NtAlpcCreatePort_t)(
    PHANDLE            PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PVOID              PortAttributes  // ALPC_PORT_ATTRIBUTES*
);

typedef NTSTATUS(NTAPI* NtAlpcSetInformation_t)(
    HANDLE PortHandle,
    ULONG  PortInformationClass,
    PVOID  PortInformation,
    ULONG  Length
);

typedef NTSTATUS(NTAPI* NtAlpcConnectPort_t)(
    PHANDLE            PortHandle,
    PUNICODE_STRING    PortName,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PVOID              PortAttributes,
    ULONG              Flags,
    PVOID              RequiredServerSid,
    PVOID              ConnectionMessage,
    PULONG             BufferLength,
    PVOID              OutMessageAttributes,
    PVOID              InMessageAttributes,
    PLARGE_INTEGER     Timeout
);

// File I/O (for TP_IO variant)
typedef NTSTATUS(NTAPI* NtSetInformationFile_t)(
    HANDLE                 FileHandle,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    ULONG                  FileInformationClass  // FILE_INFORMATION_CLASS
);

// Wait completion packet (for TP_WAIT variant)
typedef NTSTATUS(NTAPI* NtAssociateWaitCompletionPacket_t)(
    HANDLE WaitCompletionPacketHandle,
    HANDLE IoCompletionHandle,
    HANDLE TargetObjectHandle,
    PVOID  KeyContext,
    PVOID  ApcContext,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation,
    PBOOLEAN AlreadySignaled
);

typedef NTSTATUS(NTAPI* NtCreateWaitCompletionPacket_t)(
    PHANDLE            WaitCompletionPacketHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

// ============================================================================
// System Handle Information (for handle hijacking)
// ============================================================================

#define SystemHandleInformationEx 64

#pragma pack(push, 8)
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID       Object;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   HandleValue;
    ULONG       GrantedAccess;
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;
#pragma pack(pop)

// Object type query
#define ObjectTypeInformation 2

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG          TotalNumberOfObjects;
    ULONG          TotalNumberOfHandles;
    // ... more fields we don't need
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

// ============================================================================
// Worker Factory Information Classes
// ============================================================================

// WORKERFACTORYINFOCLASS enum values:
// 0 = WorkerFactoryTimeout
// 1 = WorkerFactoryRetryTimeout
// 2 = WorkerFactoryIdleTimeout
// 3 = WorkerFactoryBindingCount
// 4 = WorkerFactoryThreadMinimum    (SET: ULONG)
// 5 = WorkerFactoryThreadMaximum    (SET: ULONG)
// 6 = WorkerFactoryPaused
// 7 = WorkerFactoryBasicInformation (QUERY)
// 8 = WorkerFactoryAdjustThreadGoal
#define WorkerFactoryBasicInformation 7

typedef struct _WORKER_FACTORY_BASIC_INFORMATION {
    LARGE_INTEGER Timeout;
    LARGE_INTEGER RetryTimeout;
    LARGE_INTEGER IdleTimeout;
    BOOLEAN       Paused;
    BOOLEAN       TimerSet;
    BOOLEAN       QueuedToExWorker;
    BOOLEAN       MayCreate;
    BOOLEAN       CreateInProgress;
    BOOLEAN       DetachAllowed;
    ULONG         ActiveThreads;
    ULONG         TotalWorkerCount;
    ULONG         AvailableWorkerCount;
    ULONG         TotalWaitCount;
    ULONG         PendingWorkerCount;
    ULONG         MinimumWorkerCount;
    ULONG         MaximumWorkerCount;
    ULONG         LastWorkerCreationStatus;
    HANDLE        CompletionPort;
    PVOID         StartRoutine;
    PVOID         StartParameter;       // → TP_POOL*
    DWORD         ProcessId;
    SIZE_T        StackReserve;
    SIZE_T        StackCommit;
    NTSTATUS      LastThreadCreationStatus;
} WORKER_FACTORY_BASIC_INFORMATION, *PWORKER_FACTORY_BASIC_INFORMATION;

#define WorkerFactoryThreadMinimum 4

// ============================================================================
// Thread Pool Internal Structures (Undocumented)
// ============================================================================
// These are the actual structures that ntdll's thread pool operates on.
// Worker threads dequeue from these and execute callbacks.

// TP_DIRECT — The simplest execution structure.
// Used by I/O completion-based variants (3-7).
// Worker thread reads CompletionKey as TP_DIRECT*, calls Callback.
typedef struct _TP_DIRECT {
    PVOID     Callback;         // +0x00: Function pointer executed by worker
    ULONG_PTR NumaNode;         // +0x08: NUMA node hint
    UCHAR     IdealProcessor;   // +0x10: Ideal processor hint
    UCHAR     Padding[7];       // +0x11: Alignment padding
} TP_DIRECT, *PTP_DIRECT;

// TP_TASK — Helper structure embedded in TP_WORK.
// Contains the LIST_ENTRY that links into the task queue.
typedef struct _TP_TASK {
    LIST_ENTRY ListEntry;       // +0x00: Doubly-linked list node
    LONG       PostCount;       // +0x10: Number of times posted
    LONG       Padding;         // +0x14: Alignment
} TP_TASK, *PTP_TASK;

// TP_CLEANUP_GROUP_MEMBER — Base structure for all pool-associated items.
// Contains the callback pointer and pool reference.
typedef struct _TP_CLEANUP_GROUP_MEMBER {
    PVOID     Callback;         // +0x00: The actual callback function
    PVOID     Context;          // +0x08: User context passed to callback
    PVOID     CleanupGroup;     // +0x10: TP_CLEANUP_GROUP*
    PVOID     CleanupGroupCancelCallback; // +0x18
    PVOID     FinalizationCallback;       // +0x20
    PVOID     Pool;             // +0x28: TP_POOL* — CRITICAL: must point to target's pool
    PVOID     Padding[2];       // +0x30: Alignment
    LONG      RefCount;         // +0x40: Reference count
    LONG      Flags;            // +0x44: State flags
} TP_CLEANUP_GROUP_MEMBER, *PTP_CLEANUP_GROUP_MEMBER;

// TP_WORK — Regular work item (Variant 2).
// Contains TP_TASK for task queue insertion.
typedef struct _TP_WORK {
    TP_CLEANUP_GROUP_MEMBER CleanupGroupMember; // +0x00
    TP_TASK                 Task;               // +0x48
    LONG volatile           WorkState;          // +0x60: 0x2 = queued
    LONG                    Padding;            // +0x64
} TP_WORK, *PTP_WORK;

// RTL_BALANCED_NODE — Red-black tree node (used in timer queue).
typedef struct _RTL_BALANCED_NODE {
    union {
        struct _RTL_BALANCED_NODE* Children[2]; // +0x00: Left/Right
        struct {
            struct _RTL_BALANCED_NODE* Left;
            struct _RTL_BALANCED_NODE* Right;
        };
    };
    union {
        UCHAR  Red : 1;        // +0x10: Color bit
        ULONG_PTR ParentValue; // +0x10: Parent pointer (low bit = color)
    };
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

// TP_TIMER window links — used for timer queue red-black tree insertion.
typedef struct _TP_TIMER_WINDOW_ENTRY {
    RTL_BALANCED_NODE Node;     // +0x00: Tree node
    LONGLONG          Key;      // +0x18: Sort key (due time)
} TP_TIMER_WINDOW_ENTRY, *PTP_TIMER_WINDOW_ENTRY;

// TP_TIMER — Timer work item (Variant 8).
typedef struct _TP_TIMER {
    TP_CLEANUP_GROUP_MEMBER CleanupGroupMember; // +0x00
    TP_DIRECT               Direct;             // +0x48: For I/O completion notification
    TP_TIMER_WINDOW_ENTRY   WindowStartLinks;   // +0x60
    TP_TIMER_WINDOW_ENTRY   WindowEndLinks;     // +0x80
    LONGLONG                DueTime;            // +0xA0: Absolute due time (100ns units)
    LONG volatile           State;              // +0xA8
    LONG                    Period;             // +0xAC: Repeat period (ms), 0 = one-shot
    ULONG                   WindowLength;       // +0xB0
} TP_TIMER, *PTP_TIMER;

// TP_POOL timer queue — red-black tree root.
typedef struct _TP_TIMER_QUEUE {
    RTL_BALANCED_NODE* WindowStartRoot; // +0x00: Root of WindowStart tree
    RTL_BALANCED_NODE* WindowEndRoot;   // +0x08: Root of WindowEnd tree
} TP_TIMER_QUEUE, *PTP_TIMER_QUEUE;

// TP_POOL task queue — doubly-linked list.
typedef struct _TP_TASK_QUEUE {
    LIST_ENTRY Queue;           // +0x00: Head of task queue
    LONG       Count;           // +0x10: Number of items
} TP_TASK_QUEUE, *PTP_TASK_QUEUE;

// TP_POOL — The main thread pool structure.
// Lives in usermode in the target process's address space.
// StartParameter of the worker factory points here.
//
// NOTE: This is a simplified layout. The actual structure is ~0x400 bytes
// with many more fields. We only define the offsets we need.
// Offsets may shift between Windows versions — the handle hijacking
// approach (Variants 3-7) avoids needing exact TP_POOL offsets.
typedef struct _TP_POOL_PARTIAL {
    BYTE                    Padding0[0x10];     // +0x00
    TP_TASK_QUEUE           TaskQueue;          // +0x10 (approximate)
    BYTE                    Padding1[0x100];    // Varies by version
    TP_TIMER_QUEUE          TimerQueue;         // Offset varies
} TP_POOL_PARTIAL, *PTP_POOL_PARTIAL;

// ============================================================================
// FILE_REPLACE_COMPLETION_INFORMATION (for TP_IO variant)
// ============================================================================

#define FileReplaceCompletionInformation 61

typedef struct _FILE_COMPLETION_INFORMATION {
    HANDLE Port;                // I/O completion port handle
    PVOID  Key;                 // Completion key (→ TP_DIRECT*)
} FILE_COMPLETION_INFORMATION, *PFILE_COMPLETION_INFORMATION;

// ============================================================================
// ALPC structures (for TP_ALPC variant)
// ============================================================================

#define AlpcAssociateCompletionPortInformation 2

typedef struct _ALPC_PORT_ASSOCIATE_COMPLETION_PORT {
    PVOID  CompletionKey;       // → TP_DIRECT*
    HANDLE CompletionPort;      // I/O completion port handle
} ALPC_PORT_ASSOCIATE_COMPLETION_PORT, *PALPC_PORT_ASSOCIATE_COMPLETION_PORT;

// ============================================================================
// Status codes
// ============================================================================

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS           ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef DUPLICATE_SAME_ACCESS
#define DUPLICATE_SAME_ACCESS 0x00000002
#endif