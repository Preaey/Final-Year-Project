#include <fltKernel.h>

#define GUARD_TAG 'GbsU'
#define PORT_NAME L"\\UsbGuardPort"
#define GUARD_QUERY 1
#define GUARD_RELEASE 2
#define GUARD_PING 3
#define VOLUME_NAME_CAPACITY 128

typedef struct _GUARD_REQUEST {
    ULONG Operation;
    ULONG Reserved;
    ULONGLONG VolumeId;
    WCHAR VolumeName[VOLUME_NAME_CAPACITY];
} GUARD_REQUEST;

typedef struct _GUARD_REPLY {
    ULONGLONG VolumeId;
    ULONG Released;
    ULONG Reserved;
} GUARD_REPLY;

C_ASSERT(sizeof(GUARD_REQUEST) == 272);
C_ASSERT(sizeof(GUARD_REPLY) == 16);

typedef struct _GUARD_INSTANCE {
    ULONGLONG VolumeId;
    volatile LONG Released;
} GUARD_INSTANCE, *PGUARD_INSTANCE;

static PFLT_FILTER Filter;
static PFLT_PORT ServerPort;
static PFLT_PORT ClientPort;
static PEPROCESS ScannerProcess;
static FAST_MUTEX ClientLock;
static DECLSPEC_ALIGN(8) volatile LONG64 NextVolumeId;

DRIVER_INITIALIZE DriverEntry;

static BOOLEAN
IsRemovableVolume(PFLT_VOLUME Volume)
{
    FLT_VOLUME_PROPERTIES properties;
    ULONG returned;
    NTSTATUS status = FltGetVolumeProperties(Volume, &properties, sizeof(properties), &returned);

    // The fixed fields are valid even when the variable-length names do not fit.
    return (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) &&
        FlagOn(properties.DeviceCharacteristics, FILE_REMOVABLE_MEDIA);
}

static NTSTATUS
InstanceSetup(PCFLT_RELATED_OBJECTS Objects, FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE FileSystemType)
{
    PGUARD_INSTANCE instance;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(FileSystemType);

    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM || !IsRemovableVolume(Objects->Volume)) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    status = FltAllocateContext(Objects->Filter, FLT_INSTANCE_CONTEXT,
        sizeof(*instance), NonPagedPoolNx, (PFLT_CONTEXT *)&instance);

    if (NT_SUCCESS(status)) {
        instance->VolumeId = (ULONGLONG)InterlockedIncrement64(&NextVolumeId);
        instance->Released = FALSE;
        FltSetInstanceContext(Objects->Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, instance, NULL);
        FltReleaseContext(instance);
    }

    // An attached instance with no context denies opens and cannot be released.
    return STATUS_SUCCESS;
}

static FLT_PREOP_CALLBACK_STATUS
PreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects, PVOID *CompletionContext)
{
    PGUARD_INSTANCE instance;
    BOOLEAN permitted = FALSE;
    PEPROCESS requestor;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (NT_SUCCESS(FltGetInstanceContext(Objects->Instance, (PFLT_CONTEXT *)&instance))) {
        permitted = InterlockedCompareExchange(&instance->Released, FALSE, FALSE) != FALSE;
        FltReleaseContext(instance);
    }

    if (!permitted) {
        requestor = FltGetRequestorProcess(Data);
        ExAcquireFastMutex(&ClientLock);
        permitted = requestor != NULL && requestor == ScannerProcess;
        ExReleaseFastMutex(&ClientLock);
    }

    if (permitted) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static NTSTATUS
Connect(PFLT_PORT Port, PVOID ServerCookie, PVOID ConnectionContext,
    ULONG ContextSize, PVOID *ConnectionCookie)
{
    PEPROCESS process = PsGetCurrentProcess();

    UNREFERENCED_PARAMETER(ServerCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(ContextSize);

    ExAcquireFastMutex(&ClientLock);
    if (ScannerProcess != NULL) {
        ExReleaseFastMutex(&ClientLock);
        return STATUS_DEVICE_BUSY;
    }

    ObReferenceObject(process);
    ScannerProcess = process;
    ClientPort = Port;
    *ConnectionCookie = process;
    ExReleaseFastMutex(&ClientLock);
    return STATUS_SUCCESS;
}

static VOID
Disconnect(PVOID ConnectionCookie)
{
    // Filter Manager serializes connect and disconnect for a single-client port.
    FltCloseClientPort(Filter, &ClientPort);

    ExAcquireFastMutex(&ClientLock);
    ScannerProcess = NULL;
    ExReleaseFastMutex(&ClientLock);
    ObDereferenceObject(ConnectionCookie);
}

static NTSTATUS
Message(PVOID ConnectionCookie, PVOID InputBuffer, ULONG InputSize,
    PVOID OutputBuffer, ULONG OutputSize, PULONG ReturnedSize)
{
    GUARD_REQUEST request;
    GUARD_REPLY reply = {0};
    UNICODE_STRING name;
    PFLT_VOLUME volume;
    PFLT_INSTANCE filterInstance;
    PGUARD_INSTANCE state;
    NTSTATUS status;

    *ReturnedSize = 0;
    if (PsGetCurrentProcess() != ConnectionCookie) {
        return STATUS_ACCESS_DENIED;
    }

    if (InputBuffer == NULL || InputSize != sizeof(request) ||
        OutputBuffer == NULL || OutputSize < sizeof(reply)) {
        return STATUS_INVALID_PARAMETER;
    }

    // Filter Manager supplies raw user buffers to this callback.
    __try {
        RtlCopyMemory(&request, InputBuffer, sizeof(request));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    request.VolumeName[VOLUME_NAME_CAPACITY - 1] = UNICODE_NULL;
    RtlInitUnicodeString(&name, request.VolumeName);
    if (request.Reserved != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (request.Operation == GUARD_PING) {
        status = STATUS_SUCCESS;
        goto WriteReply;
    }

    if (name.Length == 0 ||
        (request.Operation != GUARD_QUERY && request.Operation != GUARD_RELEASE)) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltGetVolumeFromName(Filter, &name, &volume);
    if (NT_SUCCESS(status)) {
        status = FltGetVolumeInstanceFromName(Filter, volume, NULL, &filterInstance);
        FltObjectDereference(volume);
        if (NT_SUCCESS(status)) {
            status = FltGetInstanceContext(filterInstance, (PFLT_CONTEXT *)&state);
            FltObjectDereference(filterInstance);
            if (NT_SUCCESS(status)) {
                reply.VolumeId = state->VolumeId;
                if (request.Operation == GUARD_RELEASE) {
                    if (request.VolumeId == state->VolumeId) {
                        InterlockedExchange(&state->Released, TRUE);
                    } else {
                        status = STATUS_DEVICE_NOT_CONNECTED;
                    }
                }

                reply.Released = InterlockedCompareExchange(&state->Released, FALSE, FALSE) != FALSE;
                FltReleaseContext(state);
            }
        }
    }

    if (request.Operation == GUARD_QUERY &&
        (status == STATUS_FLT_INSTANCE_NOT_FOUND || status == STATUS_FLT_VOLUME_NOT_FOUND)) {
        status = STATUS_SUCCESS;
    }

    if (!NT_SUCCESS(status)) {
        return status;
    }

WriteReply:
    __try {
        RtlCopyMemory(OutputBuffer, &reply, sizeof(reply));
        *ReturnedSize = sizeof(reply);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
Unload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    FltCloseCommunicationPort(ServerPort);
    FltUnregisterFilter(Filter);
    return STATUS_SUCCESS;
}

static const FLT_CONTEXT_REGISTRATION Contexts[] = {
    { FLT_INSTANCE_CONTEXT, 0, NULL, sizeof(GUARD_INSTANCE), GUARD_TAG },
    { FLT_CONTEXT_END }
};

static const FLT_OPERATION_REGISTRATION Operations[] = {
    { IRP_MJ_CREATE, 0, PreCreate, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION Registration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    Contexts,
    Operations,
    Unload,
    InstanceSetup
};

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    PSECURITY_DESCRIPTOR security;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&name, PORT_NAME);
    ExInitializeFastMutex(&ClientLock);
    status = FltRegisterFilter(DriverObject, &Registration, &Filter);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltBuildDefaultSecurityDescriptor(&security, FLT_PORT_CONNECT);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
            NULL, security);
        status = FltCreateCommunicationPort(Filter, &ServerPort, &attributes, NULL,
            Connect, Disconnect, Message, 1);
        FltFreeSecurityDescriptor(security);
    }

    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(Filter);
        if (!NT_SUCCESS(status)) {
            FltCloseCommunicationPort(ServerPort);
        }
    }

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(Filter);
    }

    return status;
}
