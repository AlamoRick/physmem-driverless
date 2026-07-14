#include <windows.h>
#include <stdio.h>
#include <urlmon.h>
#include <string>
#include <vector>
#include <fstream>
#include <atlbase.h>
#include <dia2.h>
#include "symbols.h"

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "diaguids.lib")
#pragma comment(lib, "ole32.lib")

struct PdbInfo {
    DWORD signature;
    GUID guid;
    DWORD age;
    char pdbFileName[1];
};

struct RTL_PROCESS_MODULE_INFORMATION {
    PVOID Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[256];
};

struct RTL_PROCESS_MODULES {
    ULONG Count;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
};

typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

static ULONG64 GetKernelBase() {
    auto NtQSI = (pNtQuerySystemInformation)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) return 0;

    ULONG size = 0;
    NtQSI(11, NULL, 0, &size);

    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) return 0;

    if (NtQSI(11, buffer, size, &size) != 0) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }

    RTL_PROCESS_MODULES* modules = (RTL_PROCESS_MODULES*)buffer;
    ULONG64 base = 0;

    for (ULONG i = 0; i < modules->Count; i++) {
        const char* name = (const char*)(
            modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName);
        if (_stricmp(name, "ntoskrnl.exe") == 0 ||
            _stricmp(name, "ntkrnlmp.exe") == 0 ||
            _stricmp(name, "ntkrnlpa.exe") == 0) {
            base = (ULONG64)modules->Modules[i].ImageBase;
            break;
        }
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    return base;
}

struct PdbDownloadInfo {
    GUID guid;
    DWORD age;
    std::string pdbFileName;
};

static bool GetPdbInfo(const char* pePath, PdbDownloadInfo* info) {
    std::ifstream file(pePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;

    auto fileSize = file.tellg();
    file.seekg(0);
    std::vector<char> fileData((size_t)fileSize);
    file.read(fileData.data(), fileSize);
    file.close();

    BYTE* raw = (BYTE*)fileData.data();
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    DWORD imageSize = nt->OptionalHeader.SizeOfImage;
    std::vector<BYTE> image(imageSize, 0);
    memcpy(image.data(), raw, nt->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (UINT i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData)
            memcpy(image.data() + section->VirtualAddress,
                   raw + section->PointerToRawData, section->SizeOfRawData);
    }

    IMAGE_DATA_DIRECTORY* debugDir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (!debugDir->Size) return false;

    IMAGE_DEBUG_DIRECTORY* dbgDir =
        (IMAGE_DEBUG_DIRECTORY*)(image.data() + debugDir->VirtualAddress);
    if (dbgDir->Type != IMAGE_DEBUG_TYPE_CODEVIEW) return false;

    PdbInfo* pdb = (PdbInfo*)(image.data() + dbgDir->AddressOfRawData);
    if (pdb->signature != 0x53445352) return false;

    info->guid = pdb->guid;
    info->age = pdb->age;
    info->pdbFileName = pdb->pdbFileName;
    return true;
}

static std::string DownloadPdb(const PdbDownloadInfo& info) {
    wchar_t wGuid[100] = {};
    StringFromGUID2(info.guid, wGuid, 100);

    char aGuid[100] = {};
    wcstombs(aGuid, wGuid, sizeof(aGuid));

    char filtered[256] = {};
    int j = 0;
    for (int i = 0; aGuid[i]; i++) {
        char c = aGuid[i];
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))
            filtered[j++] = c;
    }

    char ageStr[16] = {};
    sprintf(ageStr, "%X", info.age);

    std::string url = "https://msdl.microsoft.com/download/symbols/";
    url += info.pdbFileName + "/" + filtered + ageStr + "/" + info.pdbFileName;

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string pdbPath = std::string(tempPath) + info.pdbFileName;

    printf("[*] Downloading PDB...\n");
    if (FAILED(URLDownloadToFileA(NULL, url.c_str(), pdbPath.c_str(), 0, NULL))) {
        printf("[-] PDB download failed\n");
        return "";
    }

    std::ifstream verify(pdbPath, std::ios::binary | std::ios::ate);
    if (!verify.is_open() || verify.tellg() < 1024) {
        DeleteFileA(pdbPath.c_str());
        return "";
    }

    printf("[+] PDB downloaded\n");
    return pdbPath;
}

static IDiaDataSource* CreateDiaSource() {
    IDiaDataSource* source = nullptr;

    HRESULT hr = CoCreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER,
        IID_IDiaDataSource, (void**)&source);
    if (SUCCEEDED(hr)) return source;

    const wchar_t* versions[] = { L"msdia140.dll", L"msdia120.dll", L"msdia110.dll" };
    for (auto dll : versions) {
        HMODULE hMod = LoadLibraryW(dll);
        if (!hMod) continue;

        typedef HRESULT(WINAPI* pDllGetClassObject)(REFCLSID, REFIID, LPVOID*);
        auto getClass = (pDllGetClassObject)GetProcAddress(hMod, "DllGetClassObject");
        if (!getClass) continue;

        IClassFactory* factory = nullptr;
        hr = getClass(CLSID_DiaSource, IID_IClassFactory, (void**)&factory);
        if (FAILED(hr) || !factory) continue;

        hr = factory->CreateInstance(NULL, IID_IDiaDataSource, (void**)&source);
        factory->Release();
        if (SUCCEEDED(hr)) return source;
    }
    return nullptr;
}

static bool DiaGetGlobalRva(IDiaSession* session, IDiaSymbol* global,
                            const char* name, ULONG64* rva) {
    wchar_t wName[256];
    mbstowcs(wName, name, 256);

    CComPtr<IDiaEnumSymbols> enumSyms;
    if (FAILED(global->findChildren(SymTagPublicSymbol, wName, nsfCaseInsensitive, &enumSyms)))
        if (FAILED(global->findChildren(SymTagData, wName, nsfCaseInsensitive, &enumSyms)))
            return false;

    CComPtr<IDiaSymbol> sym;
    ULONG celt = 0;
    if (FAILED(enumSyms->Next(1, &sym, &celt)) || celt != 1) return false;

    DWORD rvaVal = 0;
    if (FAILED(sym->get_relativeVirtualAddress(&rvaVal))) return false;

    *rva = rvaVal;
    return true;
}

static bool DiaGetMemberOffset(IDiaSymbol* global, const char* typeName,
                               const char* memberName, ULONG* offset) {
    wchar_t wType[256], wMember[256];
    mbstowcs(wType, typeName, 256);
    mbstowcs(wMember, memberName, 256);

    CComPtr<IDiaEnumSymbols> enumTypes;
    if (FAILED(global->findChildren(SymTagUDT, wType, nsfCaseInsensitive, &enumTypes)))
        return false;

    CComPtr<IDiaSymbol> udt;
    ULONG celt = 0;
    if (FAILED(enumTypes->Next(1, &udt, &celt)) || celt != 1) return false;

    CComPtr<IDiaEnumSymbols> enumMembers;
    if (FAILED(udt->findChildren(SymTagData, wMember, nsfCaseInsensitive, &enumMembers)))
        return false;

    CComPtr<IDiaSymbol> member;
    if (FAILED(enumMembers->Next(1, &member, &celt)) || celt != 1) return false;

    LONG off = 0;
    if (FAILED(member->get_offset(&off))) return false;

    *offset = (ULONG)off;
    return true;
}

bool ResolveKernelOffsets(KernelOffsets* offsets) {
    CoInitialize(NULL);

    printf("[*] Finding ntoskrnl base...\n");
    offsets->NtoskrnlBase = GetKernelBase();
    if (!offsets->NtoskrnlBase) return false;
    printf("[+] ntoskrnl: 0x%llX\n", offsets->NtoskrnlBase);

    PdbDownloadInfo pdbInfo;
    if (!GetPdbInfo("C:\\Windows\\System32\\ntoskrnl.exe", &pdbInfo))
        return false;

    std::string pdbPath = DownloadPdb(pdbInfo);
    if (pdbPath.empty()) return false;

    IDiaDataSource* source = CreateDiaSource();
    if (!source) { DeleteFileA(pdbPath.c_str()); return false; }

    wchar_t wPdbPath[MAX_PATH];
    mbstowcs(wPdbPath, pdbPath.c_str(), MAX_PATH);

    if (FAILED(source->loadDataFromPdb(wPdbPath))) {
        source->Release();
        DeleteFileA(pdbPath.c_str());
        return false;
    }

    CComPtr<IDiaSession> session;
    if (FAILED(source->openSession(&session))) {
        source->Release();
        DeleteFileA(pdbPath.c_str());
        return false;
    }

    CComPtr<IDiaSymbol> global;
    if (FAILED(session->get_globalScope(&global))) {
        source->Release();
        DeleteFileA(pdbPath.c_str());
        return false;
    }

    bool ok = true;
    ok &= DiaGetGlobalRva(session, global, "PsActiveProcessHead", &offsets->PsActiveProcessHead);
    ok &= DiaGetGlobalRva(session, global, "PiDDBCacheTable", &offsets->PiDDBCacheTable);
    ok &= DiaGetGlobalRva(session, global, "PiDDBCacheList", &offsets->PiDDBCacheList);
    ok &= DiaGetGlobalRva(session, global, "PiDDBLock", &offsets->PiDDBLock);
    ok &= DiaGetGlobalRva(session, global, "MmUnloadedDrivers", &offsets->MmUnloadedDrivers);
    ok &= DiaGetGlobalRva(session, global, "MmLastUnloadedDriver", &offsets->MmLastUnloadedDriver);
    ok &= DiaGetGlobalRva(session, global, "PsInitialSystemProcess", &offsets->PsInitialSystemProcess);
    ok &= DiaGetGlobalRva(session, global, "HalpRMStub", &offsets->HalpRMStub);
    ok &= DiaGetGlobalRva(session, global, "RtlLookupElementGenericTableAvl", &offsets->RtlLookupElementGenericTableAvl);
    ok &= DiaGetGlobalRva(session, global, "RtlDeleteElementGenericTableAvl", &offsets->RtlDeleteElementGenericTableAvl);
    ok &= DiaGetGlobalRva(session, global, "ExAcquireResourceExclusiveLite", &offsets->ExAcquireResourceExclusiveLite);
    ok &= DiaGetGlobalRva(session, global, "ExReleaseResourceLite", &offsets->ExReleaseResourceLite);
    ok &= DiaGetGlobalRva(session, global, "ExFreePoolWithTag", &offsets->ExFreePoolWithTag);

    ok &= DiaGetMemberOffset(global, "_KPROCESS", "DirectoryTableBase", &offsets->DirectoryTableBase);
    ok &= DiaGetMemberOffset(global, "_KPROCESS", "UserDirectoryTableBase", &offsets->UserDirectoryTableBase);
    ok &= DiaGetMemberOffset(global, "_KPROCESS", "ThreadListHead", &offsets->ThreadListHead);
    ok &= DiaGetMemberOffset(global, "_EPROCESS", "UniqueProcessId", &offsets->UniqueProcessId);
    ok &= DiaGetMemberOffset(global, "_EPROCESS", "ActiveProcessLinks", &offsets->ActiveProcessLinks);
    ok &= DiaGetMemberOffset(global, "_EPROCESS", "ImageFileName", &offsets->ImageFileName);
    ok &= DiaGetMemberOffset(global, "_EPROCESS", "Protection", &offsets->Protection);
    ok &= DiaGetMemberOffset(global, "_EPROCESS", "SectionBaseAddress", &offsets->SectionBaseAddress);
    ok &= DiaGetMemberOffset(global, "_KTHREAD", "ThreadListEntry", &offsets->ThreadListEntry);
    ok &= DiaGetMemberOffset(global, "_EPROCESS", "VadRoot", &offsets->VadRoot);

    ok &= DiaGetMemberOffset(global, "_MMVAD_SHORT", "StartingVpn", &offsets->VadStartingVpn);
    ok &= DiaGetMemberOffset(global, "_MMVAD_SHORT", "EndingVpn", &offsets->VadEndingVpn);
    ok &= DiaGetMemberOffset(global, "_MMVAD_SHORT", "StartingVpnHigh", &offsets->VadStartingVpnHigh);
    ok &= DiaGetMemberOffset(global, "_MMVAD_SHORT", "EndingVpnHigh", &offsets->VadEndingVpnHigh);
    ok &= DiaGetMemberOffset(global, "_MMVAD_SHORT", "u", &offsets->VadFlags);

    if (!DiaGetMemberOffset(global, "_EPROCESS", "VirtualSize", &offsets->VirtualSize))
        offsets->VirtualSize = 0;

    global.Release();
    session.Release();
    source->Release();
    CoUninitialize();

    DeleteFileA(pdbPath.c_str());

    if (!ok) printf("[-] Some offsets failed to resolve\n");
    else printf("[+] All offsets resolved\n");

    return ok;
}
