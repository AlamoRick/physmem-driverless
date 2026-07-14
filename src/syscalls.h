#pragma once
#include <windows.h>

struct SyscallTable {
    DWORD NtLoadDriver;
    DWORD NtUnloadDriver;
    DWORD NtCreateFile;
    DWORD NtWriteFile;
    DWORD NtDeviceIoControlFile;
    DWORD NtClose;
    DWORD NtCreateKey;
    DWORD NtSetValueKey;
    DWORD NtDeleteKey;
};

bool ResolveSyscalls(SyscallTable* table);

extern "C" {
    NTSTATUS DoSyscall(DWORD syscallNumber,
        ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3, ULONG_PTR arg4);

    NTSTATUS DoSyscallEx(DWORD syscallNumber,
        ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3, ULONG_PTR arg4,
        ULONG_PTR arg5, ULONG_PTR arg6, ULONG_PTR arg7, ULONG_PTR arg8,
        ULONG_PTR arg9, ULONG_PTR arg10, ULONG_PTR arg11);
}

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#define OBJ_CASE_INSENSITIVE 0x40

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}

inline void InitUnicodeString(UNICODE_STRING* us, const wchar_t* str) {
    us->Length = (USHORT)(wcslen(str) * sizeof(wchar_t));
    us->MaximumLength = us->Length + sizeof(wchar_t);
    us->Buffer = (PWSTR)str;
}
