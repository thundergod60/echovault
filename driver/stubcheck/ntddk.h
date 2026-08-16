/* Stub ntddk.h — lets EchoVaultFilter.c be compiled for syntax/type
   checking without the WDK. Signatures mirror the real WDK APIs. */
#ifndef STUB_NTDDK_H
#define STUB_NTDDK_H

#include <stddef.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char  UCHAR;
typedef unsigned short USHORT;
typedef unsigned int   ULONG;
typedef unsigned long long ULONGLONG;
typedef unsigned __int64 ULONG_PTR;
typedef __int64 LONG_PTR;
typedef signed long LONG;
typedef int BOOLEAN;
typedef char CHAR;
typedef wchar_t WCHAR;
typedef void VOID;
typedef void* PVOID;
typedef const void* PCVOID;
typedef char* PCHAR;
typedef const char* PCSZ;
typedef WCHAR* PWSTR;
typedef const WCHAR* PCWSTR;
typedef WCHAR* PWCH;
typedef ULONG* PULONG;
typedef size_t SIZE_T;

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef NULL
#define NULL ((void*)0)
#endif

/* SAL-style annotations: empty in the stub (MSVC injects them). */
#define _In_
#define _Inout_
#define _In_opt_
#define _Out_
#define _Outptr_
#define _In_reads_(x)
#define _In_reads_opt_(x)
#define _In_reads_bytes_opt_(x)
#define _Out_writes_bytes_opt_(x)
#define _Flt_CompletionContext_Outptr_
typedef ULONG_PTR KSPIN_LOCK;
typedef UCHAR KIRQL;
typedef void* PEPROCESS;
typedef void* PSECURITY_DESCRIPTOR;
typedef LONG NTSTATUS;
typedef long long LONGLONG;
typedef struct _LARGE_INTEGER { LONGLONG QuadPart; } LARGE_INTEGER;
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    PVOID RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _ANSI_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;
typedef const ANSI_STRING* PCANSI_STRING;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _DRIVER_OBJECT { int placeholder; } DRIVER_OBJECT, *PDRIVER_OBJECT;

typedef struct _FAST_MUTEX { char data[16]; } FAST_MUTEX, *PFAST_MUTEX;

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#define STATUS_NOT_FOUND                 ((NTSTATUS)0xC0000225L)
#define STATUS_INSUFFICIENT_RESOURCES    ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL           ((NTSTATUS)0xC0000023L)

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define UNREFERENCED_PARAMETER(P) ((void)(P))
#define RtlZeroMemory(D, S) memset((D), 0, (S))
#define RtlCopyMemory(D, S, N) memcpy((D), (S), (N))
#define RtlEqualMemory(A, B, N) (memcmp((A), (B), (N)) == 0)
#define FIELD_OFFSET(Type, Field) ((ULONG)(size_t)&(((Type*)0)->Field))

#define OBJ_KERNEL_HANDLE        0x00000200
#define OBJ_CASE_INSENSITIVE     0x00000040

#define InitializeObjectAttributes(p, n, a, r, s) \
    do { \
        (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
        (p)->RootDirectory = (r); \
        (p)->Attributes = (a); \
        (p)->ObjectName = (n); \
        (p)->SecurityDescriptor = (s); \
        (p)->SecurityQualityOfService = NULL; \
    } while (0)

#define RTL_CONSTANT_STRING(s) \
    { sizeof(s) - sizeof(WCHAR), sizeof(s), (PWSTR)(s) }

#define POOL_FLAG_NON_PAGED ((ULONG)0x0000000000000040ULL)

void* ExAllocatePool2(ULONG Flags, SIZE_T NumberOfBytes, ULONG Tag);
void  ExFreePoolWithTag(void* P, ULONG Tag);
void  ExInitializeFastMutex(PFAST_MUTEX M);
void  ExAcquireFastMutex(PFAST_MUTEX M);
void  ExReleaseFastMutex(PFAST_MUTEX M);
void  KeInitializeSpinLock(KSPIN_LOCK* Lock);
typedef LARGE_INTEGER* PLARGE_INTEGER;
/* Faithful to the real wdm.h: KeQueryTickCount is a MACRO that writes
   the tick count through a caller-provided LARGE_INTEGER pointer, and
   returns nothing. Using it as a value-returning function is an error
   in the real WDK too. */
#define KeQueryTickCount(CurrentCount) \
    (*(PLARGE_INTEGER)(CurrentCount)).QuadPart = 0
void  ExAcquireSpinLock(KSPIN_LOCK* Lock, KIRQL* OldIrql);
void  ExReleaseSpinLock(KSPIN_LOCK* Lock, KIRQL OldIrql);
ULONG RtlRandomEx(PULONG Seed);

VOID RtlInitAnsiString(PANSI_STRING Dest, PCSZ Source);
VOID RtlInitUnicodeString(PUNICODE_STRING Dest, PCWSTR Source);
NTSTATUS RtlAnsiStringToUnicodeString(PUNICODE_STRING Dest, PCANSI_STRING Source, BOOLEAN Allocate);
BOOLEAN RtlEqualUnicodeString(PCUNICODE_STRING A, PCUNICODE_STRING B, BOOLEAN CaseInsensitive);

PCHAR PsGetProcessImageFileName(PEPROCESS Process);
NTSTATUS SeLocateProcessImageName(PEPROCESS Process, PUNICODE_STRING* ImageFileName);
void  ExFreePool(void* P);
NTSTATUS ZwQuerySymbolicLink(PUNICODE_STRING LinkName, PUNICODE_STRING TargetName);

typedef enum _WORK_QUEUE_TYPE {
    CriticalWorkQueue, DelayedWorkQueue, HyperCriticalWorkQueue,
    NormalWorkQueue, MaximumWorkQueue
} WORK_QUEUE_TYPE;

typedef VOID (*PWORKER_THREAD_ROUTINE)(PVOID Parameter);

typedef struct _WORK_QUEUE_ITEM {
    PWORKER_THREAD_ROUTINE WorkerRoutine;
    PVOID Parameter;
    PVOID ListEntry;
} WORK_QUEUE_ITEM, *PWORK_QUEUE_ITEM;

VOID ExInitializeWorkItem(PWORK_QUEUE_ITEM Item, PWORKER_THREAD_ROUTINE Routine, PVOID Context);
VOID ExQueueWorkItem(PWORK_QUEUE_ITEM Item, WORK_QUEUE_TYPE QueueType);

#endif /* STUB_NTDDK_H */
