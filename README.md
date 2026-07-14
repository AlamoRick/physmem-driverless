# physmem-driverless

driverless physical memory read/write from usermode. loads a signed vulnerable driver (tpwsav.sys), sets up a persistent physical memory window through leaked section handles, then unloads the driver and erases some evidence it was ever there. after bootstrap, you have full physical R/W with zero kernel footprint, no driver, no handles, no traces, HVCI compiant.


end state: full physical memory access through pointer dereferences. no syscalls, no API calls, no driver, no handles. includes a demo that brute-forces a target process CR3 and reads its memory.

## the driver

tpwsav.sys is a legitimate signed driver by Compal Electronic for Toshiba laptop power management. it exposes `\Device\PhysicalMemory` mapping through two IOCTLs that were never meant to be accessible from usermode. it was used in the wild by the Qilin ransomware group to blind EDR solutions via BYOVD.


## building

visual studio 2022+ with C++ desktop workload and DIA SDK. open `driverless.sln`, build Release x64. requires admin to run (SeLoadDriverPrivilege).

## structure

```
src/
  main.cpp          — bootstrap sequence
  resolver.cpp      — syscall number resolution from ntdll exports
  syscalls.h/asm    — direct syscall stubs and NT type definitions
  symbols.cpp/h     — PDB download + DIA SDK offset resolution
  physmem.cpp/h     — IOCTL-based physical memory primitives
  window.cpp/h      — leaked handle window, VAD spoofing, post-bootstrap R/W
  cleanup.cpp/h     — PiDDBCacheTable and MmUnloadedDrivers trace removal
  protect.cpp/h     — SYSTEM impersonation, PPL, DACL lock
  reader.cpp/h      — multi-threaded CR3 brute-force + cross-process read demo
  driver_bytes.h    — embedded tpwsav.sys
```

## hvci

works on HVCI enabled systems. everything here is data manipulation. no new code is ever executed in ring 0. the driver is legitimately signed so it passes DSE + HVCI.

## limitations

- If CR3 brute force has problems. You can find unpoisoned CR3 on windows through the PFN dtb using the R/W primitives.