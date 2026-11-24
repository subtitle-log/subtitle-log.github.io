---
title: "Windows Kernel 1-day EoP, Part 1: HEVD to CVE-2021-40449"
summary: "Starting with an educational UAF driver and working up to a real win32k CVE. Pool objects, dangling pointers, and usermode callback re-entry."
date: 2026-09-01
tags: ["WHS Kernel EoP", "UAF", "win32k"]
draft: false
featured: true
category: Kernel
---

This is the first part of a three-part series on Windows kernel Use-After-Free vulnerabilities and privilege escalation, based on a team project during WhiteHat School Phase 2. The project covered HEVD, CVE-2021-40449, CVE-2025-24983, and CVE-2026-58632. Each part is self-contained but follows the order we actually worked through them.

The goal was not just to trigger crashes. We wanted to trace every step from the vulnerable code path down to root cause, understand why the patch fixes it, and push toward exploitation where possible.

## Why start with HEVD

Before touching real CVEs, we needed to build intuition for how kernel UAF works end to end. HEVD (HackSys Extreme Vulnerable Driver) is a deliberately vulnerable driver with source code for both the vulnerable and secure builds. That makes it possible to verify everything statically before going into WinDbg.

We chose the NonPagedPool UAF module specifically because the CVEs we planned to analyze later all involved kernel pool object lifetime bugs. HEVD gave us a clean, controlled environment to learn the full cycle: IOCTL dispatch, pool allocation, object lifetime, dangling pointers, and controlled function pointer calls.

## Environment

- Guest: Windows 11 25H2 (Build 26200.8037), test signing on
- HEVD: v3.00, vulnerable x64 build (SHA256: `BFA54BF3...8818F2`)
- Debugger: WinDbg via serial named pipe, baud 115200
- Driver loaded with `sc create HEVD type= kernel binPath= ...` and `sc start HEVD`

Setting up kernel debugging itself was a learning process. We hit a VMware VMCI device error on VM power-on, which turned out to be a conflict with the virtual machine communication interface service. Disabling the VMCI adapter in VM settings resolved it. Small things like this are worth noting because they eat hours if you do not know the cause.

## Object structure

The first thing to nail down is what the vulnerable object looks like in memory. From the HEVD symbols:

```
x HEVD!*UaF*
  HEVD!g_UseAfterFreeObjectNonPagedPool       = 0x0
  HEVD!AllocateUaFObjectNonPagedPool
  HEVD!FreeUaFObjectNonPagedPool
  HEVD!UseUaFObjectNonPagedPool
  HEVD!UaFObjectCallbackNonPagedPool
```

Disassembling `AllocateUaFObjectNonPagedPool` reveals the layout:

- `ExAllocatePoolWithTag(NonPagedPool, 0x60, 'Hack')` allocates 0x60 bytes
- Offset +0x00: Callback function pointer (8 bytes), set to `UaFObjectCallbackNonPagedPool`
- Offset +0x08: Buffer (0x54 bytes), filled with 0x41 ('A'), last byte NUL
- The object address is stored in `g_UseAfterFreeObjectNonPagedPool`

The Fake object requested via IOCTL 0x22201F is 0x58 bytes. The first 8 bytes of user input land at offset +0x00 of the reallocated chunk, which is exactly where the Callback pointer sits.

## IOCTL codes

<div class="table-wrap">

| Action | Function Code | IOCTL | Input |
|:--|:--|:--|:--|
| Allocate UAF | 0x804 | 0x222013 | None |
| Use UAF | 0x805 | 0x222017 | None |
| Free UAF | 0x806 | 0x22201B | None |
| Allocate Fake | 0x807 | 0x22201F | 0x58 bytes |

</div>

These use `METHOD_NEITHER`, meaning the I/O Manager passes the user buffer pointer directly without copying. HEVD does call `ProbeForRead` and `RtlCopyMemory` internally, so it is not a raw user pointer dereference, but this is still important context for understanding the data flow.

## Root cause: the missing NULL

The vulnerable Free handler calls `ExFreePoolWithTag` on the object but does not clear `g_UseAfterFreeObjectNonPagedPool`. The global pointer keeps pointing at freed memory.

The Use handler checks:

```
if (g_UseAfterFreeObjectNonPagedPool != NULL)
    if (g_UseAfterFreeObjectNonPagedPool->Callback != NULL)
        g_UseAfterFreeObjectNonPagedPool->Callback();
```

After Free, the global is still non-NULL. If nobody has reused that pool chunk, the old Callback pointer might still be there, and the indirect call goes to the original function. But if we reclaim that chunk with controlled data via ALLOCATE FAKE, we control where that call goes.

The secure build adds one line after `ExFreePoolWithTag`:

```c
g_UseAfterFreeObjectNonPagedPool = NULL;
```

That is literally the entire fix. One line.

## Dynamic analysis: tracing the UAF

We wrote a trigger program (`uaf_trigger.c`) that sends the four IOCTLs in sequence with pauses between each step so we could inspect memory state in WinDbg. The following diagram shows the four-step sequence and what happens in memory at each stage:

![HEVD UAF flow: Allocate, Free, Fake, Use](/img/kernel-eop/hevd-uaf-flow.svg)

**Step 1: ALLOCATE.** After sending IOCTL 0x222013, we check the global:

```
dq HEVD!g_UseAfterFreeObjectNonPagedPool L1
  -> ffff8b8d`4b1ea050
```

Dumping that address shows the Callback pointer at +0x00 pointing to `HEVD!UaFObjectCallbackNonPagedPool`, followed by 0x41-filled buffer. The screenshot below shows the pool allocation details: 0x70-byte chunk with tag Hack, buffer filled with 0x41.

![WinDbg pool allocation: 0x70 size chunk, Hack tag, 0x41 buffer](/img/kernel-eop/hevd-pool-alloc.png)

**Step 2: FREE.** After IOCTL 0x22201B:

```
dq HEVD!g_UseAfterFreeObjectNonPagedPool L1
  -> ffff8b8d`4b1ea050   (unchanged!)
```

The global still holds the old address. The pool chunk has been freed, but the pointer does not know that. This is the dangling pointer. In WinDbg, we can confirm the global pointer is unchanged while the pool itself is marked as freed:

![WinDbg showing global pointer unchanged after free](/img/kernel-eop/hevd-dangling-ptr.png)

**Step 3: FAKE (reclaim).** We send IOCTL 0x22201F with 0x58 bytes of 0x42 ('B'):

```c
char fake[0x58];
memset(fake, 0x42, sizeof(fake));
DeviceIoControl(h, 0x22201F, fake, sizeof(fake), NULL, 0, &ret, NULL);
```

Checking the same address:

```
dq ffff8b8d`4b1ea050
  -> 42424242`42424242   42424242`42424242 ...
```

The freed slot got reclaimed by our Fake object. The Callback field at +0x00 is now `0x4242424242424242`.

**Step 4: USE.** When the Use handler calls `g_UseAfterFreeObjectNonPagedPool->Callback()`, it jumps to `0x4242424242424242`. On Windows with SMEP enabled, this is a non-canonical address, so we get a bugcheck rather than a clean crash. But the point is proven: we control RIP through a UAF.

![BugCheck after RIP control via UAF](/img/kernel-eop/hevd-bugcheck.png)

One thing that tripped us up: initially we filled the fake buffer with `0x41` and saw the original Callback being called successfully, because the pool allocator happened to return memory that still had the old data. Switching to `0x42` made the overwrite obvious. This is a basic mistake but it taught us to always use distinct marker values when debugging UAF.

## Takeaways from HEVD

The important lessons were not about HEVD itself but about the patterns that show up in real CVEs:

1. **Global pointer lifetime.** The root cause is a pointer that outlives the object it points to. This exact pattern appears in CVE-2021-40449 with DC/PDEV objects.
2. **Pool reclamation.** Getting the freed slot back requires matching the allocation size and pool type. In HEVD this is straightforward (0x60 bytes, NonPagedPool). In real exploits, heap spraying with the right object size is half the battle.
3. **Indirect call as the primitive.** A function pointer in a freed-then-reclaimed object gives code execution. CVE-2021-40449 uses the same primitive through `DrvResetPDEV`.

With these fundamentals in hand, we moved to the first real CVE.

---

## CVE-2021-40449: win32k UAF via usermode callback re-entry

CVE-2021-40449 is a Use-After-Free in `win32kfull.sys` that was exploited in the wild and reported by Kaspersky in 2021 as part of the MysterySnail campaign. The vulnerability is in the GDI ResetDC path, where a usermode callback creates a re-entry window that frees an object still in use by the outer call.

This was our first real CVE analysis. We had the Kaspersky report, the CallbackHell public PoC by ly4k, and a patch to diff. The goal was to understand every step of the chain, not just run the PoC.

### Background: DC, PDEV, and usermode callbacks

A few concepts are essential for understanding this bug:

**Device Context (DC):** An abstraction Windows uses for drawing operations. Applications get an HDC handle; internally, the kernel maintains a DC object with associated state.

**PDEV (Physical Device):** The kernel-side representation of an output device (printer, display). A DC points to a PDEV. When you call ResetDC to change printer settings, the kernel may replace the PDEV.

**Usermode callbacks:** The Windows kernel can call back into usermode during certain operations (via `KeUserModeCallback`). This is a known attack surface because it gives attacker-controlled code a chance to run while the kernel is in the middle of an operation. If the kernel does not properly guard its state during the callback, the usermode code can manipulate the same objects and create inconsistencies.

### The vulnerable flow

The chain goes like this. The diagram below shows the three phases: outer ResetDC, the re-entry through the callback, and how the freed PDEV gets reclaimed for exploitation.

![CVE-2021-40449 re-entry flow: Outer ResetDC, Inner ResetDC, Exploitation chain](/img/kernel-eop/40449-reentry-flow.svg)

```
User: ResetDC(hdc, ...)
  -> NtGdiResetDC
    -> GreResetDCInternal
      -> hdcOpenDCW
        -> KeUserModeCallback  (!)
          -> User: ResetDC(hdc, ...) again  (re-entry)
            -> NtGdiResetDC
              -> GreResetDCInternal (2nd time)
                -> creates new DC/PDEV
                -> frees old PDEV
      <- returns to first GreResetDCInternal
      -> uses freed PDEV pointer  (UAF!)
```

The key insight: `GreResetDCInternal` holds a pointer to the current PDEV. During `hdcOpenDCW`, a usermode callback fires. The attacker hooks this callback to call `ResetDC` on the same HDC again. The second (re-entrant) call replaces and frees the PDEV. When the first call resumes, it still holds the old PDEV pointer, which now points to freed memory.

### Patch analysis

We compared `win32kfull.sys` between builds 14393.4651 (vulnerable) and 14393.4704 (patched) using ghidriff. The key change in `GreResetDCInternal`:

```
// Patch adds this check:
if (pdc->cExclusiveLock > 1) {
    // Re-entry detected, bail out
    ...
}
```

The ghidriff output clearly shows the added check. In the diff below, red lines are removed (vulnerable) and green lines are added (patched):

![ghidriff patch diff: cExclusiveLock > 1 check added](/img/kernel-eop/40449-patch-diff.png)

The patch checks whether the DC is already exclusively locked. If `cExclusiveLock` is greater than 1, the function knows it has been called re-entrantly and aborts. This is a clean fix: it does not try to handle the re-entry case, it simply refuses to proceed.

### Exploitation concept

The public PoC (CallbackHell) achieves SYSTEM through these steps:

1. Set up a printer DC and hook the usermode callback to trigger re-entry.
2. The re-entrant ResetDC frees the old PDEV.
3. Use Palette objects as a heap spray to reclaim the freed PDEV slot. Palettes are useful here because their size can be controlled precisely to match the PDEV allocation size.
4. The first GreResetDCInternal resumes and calls through the PDEV function table. The entry at the `DrvResetPDEV` offset now points to attacker-controlled data from the Palette spray.
5. The function pointer is redirected to `RtlSetAllBits`, which is used to flip privilege bits in the current process token.

We reproduced this on Windows Server 2016 (Build 14393.4651) using the CallbackHell PoC and confirmed SYSTEM privilege escalation. `whoami` returning `nt authority\system` from a medium-integrity process was the verification.

### What we learned

Compared to HEVD, two things stand out:

**Re-entry as a UAF trigger.** HEVD uses explicit Allocate/Free/Use IOCTLs. In a real vulnerability, the Free happens implicitly through a re-entry path the developer did not anticipate. The usermode callback is what creates the window. This pattern of "kernel calls to usermode, usermode manipulates the same object" is a recurring theme in win32k vulnerabilities.

**Heap spray replaces brute force.** In HEVD, the Fake object directly reclaims the freed chunk because the sizes match trivially. In CVE-2021-40449, the attacker needs to spray Palette objects at the right size to probabilistically land in the freed PDEV slot. Getting this right requires understanding pool allocation internals, bucket sizes, and what other allocations might interfere.

The limitation of this analysis: we relied on a public PoC for exploitation. We understood every step, but we did not write it ourselves. That changes with CVE-2025-24983, which is covered in [Part 2](/research/win-kernel-eop-part2/).

---

**Series:**
- **Part 1: HEVD to CVE-2021-40449**
- [Part 2: CVE-2025-24983, writing our own EoP exploit](/research/win-kernel-eop-part2/)
- [Part 3: CVE-2026-58632, hunting a fresh CVE](/research/win-kernel-eop-part3/)
