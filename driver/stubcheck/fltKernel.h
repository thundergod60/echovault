/* Stub fltKernel.h — lets EchoVaultFilter.c be compiled for
   syntax/type checking without the WDK. Mirrors the real Filter
   Manager declarations (signatures only, no behavior). */
#ifndef STUB_FLTKERNEL_H
#define STUB_FLTKERNEL_H

#include "ntddk.h"

#define _FLT_KERNEL_MODE 1

#define CONST const

/* ---- Basic Filter Manager types -------------------------------- */

typedef struct _FLT_FILTER            FLT_FILTER;
typedef struct _FLT_INSTANCE          FLT_INSTANCE;
typedef struct _FLT_PORT              FLT_PORT;
typedef struct _FLT_FILE_NAME_INFORMATION FLT_FILE_NAME_INFORMATION;
typedef struct _FLT_CALLBACK_DATA     FLT_CALLBACK_DATA;

typedef FLT_FILTER* PFLT_FILTER;
typedef FLT_INSTANCE* PFLT_INSTANCE;
typedef FLT_PORT* PFLT_PORT;
typedef FLT_FILE_NAME_INFORMATION* PFLT_FILE_NAME_INFORMATION;
typedef FLT_CALLBACK_DATA* PFLT_CALLBACK_DATA;

typedef void* PFILE_OBJECT;

typedef struct _FLT_RELATED_OBJECTS {
    PFLT_FILTER   Filter;
    PFLT_INSTANCE Instance;
    PFILE_OBJECT  FileObject;
} FLT_RELATED_OBJECTS;
typedef const FLT_RELATED_OBJECTS* PCFLT_RELATED_OBJECTS;

typedef struct _FLT_FILE_NAME_INFORMATION {
    ULONG         FileNameType;
    ULONG         FileNameFlags;
    UNICODE_STRING Name;
} FLT_FILE_NAME_INFORMATION;

typedef struct _IO_STATUS_BLOCK {
    NTSTATUS   Status;
    ULONG_PTR  Information;
} IO_STATUS_BLOCK;

typedef struct _FLT_CALLBACK_DATA {
    IO_STATUS_BLOCK IoStatus;
    ULONG Flags;
} FLT_CALLBACK_DATA;

/* ---- Pre-op status / callbacks --------------------------------- */

typedef enum _FLT_PREOP_CALLBACK_STATUS {
    FLT_PREOP_SUCCESS_WITH_CALLBACK,
    FLT_PREOP_SUCCESS_NO_CALLBACK,
    FLT_PREOP_PENDING,
    FLT_PREOP_DISALLOW_FAST_IO,
    FLT_PREOP_COMPLETE,
    FLT_PREOP_SYNCHRONIZE,
    FLT_PREOP_MUST_REQUEUE
} FLT_PREOP_CALLBACK_STATUS;

typedef enum _FLT_POSTOP_CALLBACK_STATUS {
    FLT_POSTOP_FINISHED_PROCESSING,
    FLT_POSTOP_MORE_PROCESSING_REQUIRED
} FLT_POSTOP_CALLBACK_STATUS;

typedef FLT_PREOP_CALLBACK_STATUS (*PFLT_PRE_OPERATION_CALLBACK)(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext);

typedef FLT_PREOP_CALLBACK_STATUS (*PFLT_POST_OPERATION_CALLBACK)(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POSTOP_CALLBACK_STATUS* ReturnStatus);

/* ---- Operation registration ------------------------------------ */

#define IRP_MJ_CREATE           0x00
#define IRP_MJ_OPERATION_END    0x80
#define FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO 0x00000001

typedef struct _FLT_OPERATION_REGISTRATION {
    UCHAR   MajorFunction;
    ULONG   Flags;
    PFLT_PRE_OPERATION_CALLBACK  PreOperation;
    PFLT_POST_OPERATION_CALLBACK PostOperation;
    PVOID   Reserved1;
    ULONG   Reserved2;
} FLT_OPERATION_REGISTRATION;

typedef ULONG FLT_FILTER_UNLOAD_FLAGS;
typedef NTSTATUS (*PFLT_FILTER_UNLOAD_CALLBACK)(FLT_FILTER_UNLOAD_FLAGS Flags);

#define FLT_REGISTRATION_VERSION 0x00020002

typedef struct _FLT_REGISTRATION {
    USHORT Size;
    USHORT Version;
    ULONG Flags;
    const void* ContextRegistration;
    const void* OperationRegistration;
    USHORT NumberOfGenericCallbacks;
    const void* GenericOperationCallbacks;
    PFLT_FILTER_UNLOAD_CALLBACK FilterUnloadCallback;
    const void* InstanceSetup;
    const void* InstanceQueryTeardown;
    const void* InstanceTeardownStart;
    const void* InstanceTeardownComplete;
    const void* GenerateFileName;
    const void* NormalizeNameComponent;
    const void* NormalizeContextCleanup;
    const void* TransactionNotification;
    const void* NormalizeNameComponentEx;
    const void* SectionConflictNotification;
    const void* NotifyCallback;
    const void* OperationProcessNotify;
    const void* ProcessNotify;
    const void* IoQueueNotify;
    const void* VolumeNotify;
    const void* IoRingBufferNotify;
    const void* IoRingBufferErrorNotify;
} FLT_REGISTRATION;

/* ---- Port callbacks / flags ------------------------------------ */

typedef NTSTATUS (*PFLT_CONNECT_NOTIFY)(
    PFLT_PORT ClientPort,
    PVOID ServerPortCookie,
    PVOID ConnectionContext,
    ULONG SizeOfContext,
    PVOID* ConnectionPortCookie);

typedef VOID (*PFLT_DISCONNECT_NOTIFY)(PVOID ConnectionCookie);

typedef NTSTATUS (*PFLT_MESSAGE_NOTIFY)(
    PVOID PortCookie,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG ReturnOutputBufferLength);

#define FLT_PORT_ALL_ACCESS 0x000F0001

#define FLT_FILE_NAME_NORMALIZED    0x00000001
#define FLT_FILE_NAME_QUERY_DEFAULT 0x00000000

/* ---- Filter Manager APIs (signatures only) --------------------- */

NTSTATUS FltRegisterFilter(
    PDRIVER_OBJECT DriverObject,
    CONST FLT_REGISTRATION* Registration,
    PFLT_FILTER* RetFilter);

VOID FltUnregisterFilter(PFLT_FILTER Filter);

NTSTATUS FltBuildDefaultSecurityDescriptor(
    PSECURITY_DESCRIPTOR* SecuritDescriptor,
    ULONG DesiredAccess);

VOID FltFreeSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor);

NTSTATUS FltCreateCommunicationPort(
    PFLT_FILTER Filter,
    PFLT_PORT* ServerPort,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PVOID ServerPortCookie,
    PFLT_CONNECT_NOTIFY ConnectNotifyCallback,
    PFLT_DISCONNECT_NOTIFY DisconnectNotifyCallback,
    PFLT_MESSAGE_NOTIFY MessageNotifyCallback,
    ULONG MaxConnections);

VOID FltCloseCommunicationPort(PFLT_PORT Port);

VOID FltCloseClientPort(PFLT_FILTER Filter, PFLT_PORT* ClientPort);

NTSTATUS FltSendMessage(
    PFLT_FILTER Filter,
    PFLT_PORT* ClientPort,
    PVOID SenderBuffer,
    ULONG SenderBufferLength,
    PVOID ReplyBuffer,
    ULONG ReplyBufferLength,
    PULONG BytesReturned);

NTSTATUS FltGetFileNameInformation(
    PFLT_CALLBACK_DATA CallbackData,
    ULONG NameOptions,
    PFLT_FILE_NAME_INFORMATION* FileNameInformation);

VOID FltReleaseFileNameInformation(PFLT_FILE_NAME_INFORMATION FileNameInformation);

PEPROCESS FltGetRequestorProcess(PFLT_CALLBACK_DATA CallbackData);

#endif /* STUB_FLTKERNEL_H */
