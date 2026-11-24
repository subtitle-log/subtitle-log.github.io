---
title: "Windows Kernel 1-day EoP, Part 2: CVE-2025-24983"
summary: "A race condition in win32k W32PROCESS lifecycle. We wrote our own exploit and hit 97/100 SYSTEM."
date: 2026-09-18
tags: ["WHS Kernel EoP", "race condition", "win32k", "exploit dev"]
draft: false
featured: true
category: Kernel
---

In [Part 1](/research/win-kernel-eop-part1/) we covered HEVD and CVE-2021-40449. Both were Use-After-Free bugs where the core challenge was reclaiming freed memory. CVE-2025-24983 is different: it is a race condition in the W32PROCESS lifecycle inside `win32kfull.sys`, and exploiting it meant writing our own PoC from scratch. This was the most rewarding part of the project.

## Overview

CVE-2025-24983 was disclosed in March 2025 as part of Patch Tuesday. ESET reported it as exploited in the wild. The bug is in how `win32kfull.sys` manages `W32PROCESS` objects, specifically a gap between when the object address is exposed and when its owning reference is fully established.

We analyzed and exploited it on:
- **Vulnerable:** Windows Server 2016, build 14393.7783
- **Patched:** build 14393.7870
- **Debugger:** WinDbg via serial pipe

## W32PROCESS lifecycle and the bug

Every Windows process that touches the GUI subsystem gets a `W32PROCESS` structure (also called `PROCESSINFO`) allocated inside `win32kfull.sys`. This is the kernel-mode extension of the `EPROCESS` that holds win32k-specific state: window station, desktop, message queue pointers, and so on.

The lifecycle goes roughly:

1. `AllocateW32Process` allocates the structure and links it to the EPROCESS.
2. Various initialization steps fill in the fields and set status bits.
3. `xxxWaitForInputIdle` and other callers may reference the object during the process's lifetime.
4. On process exit, `DestroyW32Process` tears it down.

The problem is in step 1-2. `AllocateW32Process` stores the object address into a globally reachable location before all initialization is complete. Specifically, a certain bit (0x20) in the object's flags indicates whether initialization has finished. If another thread on a different CPU reads the object address before that bit is set, it sees a partially initialized structure.

This is where `xxxWaitForInputIdle` comes in. This function is supposed to wait until a GUI process is ready to accept input. It reads the W32PROCESS and checks various state. The vulnerable version does not verify that the 0x20 initialization bit is set before proceeding. So if a thread calls `WaitForInputIdle` on a process that is still in the middle of `AllocateW32Process`, it operates on a half-built object.

The race window is small but real: on a multi-core system, one CPU can be running `AllocateW32Process` for a new process while another CPU's thread calls `WaitForInputIdle` on that same process. The partially initialized fields can contain zeroed or stale values, leading to null pointer dereferences or, more interestingly, type confusion when function pointers or object pointers are used before they are set.

The following diagram shows how the race unfolds across two CPUs:

![CVE-2025-24983 race timeline: CPU0 parent, CPU0 victim T1, CPU1 PoC T2](/img/kernel-eop/24983-race-flow.svg)

## Patch diff

Comparing builds 14393.7783 and 14393.7870:

The patch adds a check in `xxxWaitForInputIdle` for the 0x20 bit in the W32PROCESS flags before proceeding with the wait logic. If the bit is not set, the function bails out early. This is the same pattern as CVE-2021-40449's patch: rather than trying to handle the edge case, the fix simply refuses to proceed when the state is incomplete.

The side-by-side diff below shows the difference clearly. On the left is the vulnerable code that only checks `flags & 1`, on the right is the patched version that also checks `flags & 0x20`:

![Patch diff: vulnerable checks flags&1 only, patched adds flags&0x20](/img/kernel-eop/24983-patch-diff.png)

There is also a change in `AllocateW32Process` to ensure the reference is properly accounted for before the address becomes visible. The combination closes the race from both sides.

## Writing the exploit

This is where CVE-2025-24983 differs fundamentally from CVE-2021-40449. For 40449, we used a public PoC. For this one, there was no complete exploit available for our target platform. We had to build it ourselves.

### The race setup

The core idea:

1. **Thread A** creates a new process that will initialize win32k (by calling a GDI function, which triggers `AllocateW32Process`).
2. **Thread B** immediately calls `WaitForInputIdle` on that process, trying to hit the window between address exposure and initialization completion.

If Thread B wins the race, it enters `xxxWaitForInputIdle` with a partially initialized W32PROCESS. The specific uninitialized field we targeted allows us to redirect execution.

We used a delay/resume approach: Thread A creates the child process in a suspended state, sets up the race conditions, then resumes it. Thread B is already spinning on `WaitForInputIdle`. The timing is tight but on our test system (2 vCPUs), the race hit reliably within about 5-7 seconds of repeated attempts.

### From race win to kernel R/W

Winning the race gives us a corrupted state inside the win32k subsystem. The next step is turning that into something useful. We went for PreviousMode modification.

`PreviousMode` is a field in the kernel's `KTHREAD` structure that tells the kernel whether the current syscall originated from usermode or kernelmode. When `PreviousMode` is `KernelMode` (0), the kernel skips access checks on user-supplied pointers. If we can flip `PreviousMode` from 1 to 0 for our thread, we effectively get arbitrary kernel read/write through normal syscalls like `NtReadVirtualMemory` and `NtWriteVirtualMemory`.

The chain:

1. Win the race to get controlled state inside a win32k object.
2. Use the corrupted object to overwrite our thread's `PreviousMode` from `UserMode` (1) to `KernelMode` (0).
3. With PreviousMode = 0, use `NtReadVirtualMemory` / `NtWriteVirtualMemory` to read and write arbitrary kernel memory.
4. Walk the EPROCESS list to find our process and the System process (PID 4).
5. Copy the System process's Token pointer to our process's Token field.
6. `whoami` -> `nt authority\system`.

### Results

On the vulnerable build (14393.7783), our PoC achieved SYSTEM **97 out of 100 runs**. Each run took approximately 5-7 seconds, most of which was spent winning the race. The 3 failures were cases where the race did not trigger within the timeout, not crashes.

The screenshot below shows the PoC running: race attempts, Thread2 creation, shellcode injection, and the final SYSTEM confirmation.

![PoC execution: race attempts, Thread2 creation, shellcode injection](/img/kernel-eop/24983-poc-run.png)

On the patched build (14393.7870), the exploit fails cleanly because `xxxWaitForInputIdle` now checks the initialization bit and returns before touching the partially initialized object.

### What the 97/100 means

A 97% success rate on a race condition exploit is actually quite good. Race conditions are inherently probabilistic. The main failure mode is not hitting the timing window, not causing a crash. This matters because a failed attempt leaves the system in a clean state (the process just initializes normally), so you can retry immediately.

We did not aim for 100%. Improving reliability further would require more precise CPU pinning, priority manipulation, or interrupt timing tricks that add complexity without changing the fundamental technique. For a proof-of-concept demonstrating the vulnerability and the exploitation path, 97/100 is solid.

## Comparison with CVE-2021-40449

<div class="table-wrap">

| Aspect | CVE-2021-40449 | CVE-2025-24983 |
|:--|:--|:--|
| Bug class | UAF via re-entry | Race condition |
| Component | DC/PDEV objects | W32PROCESS lifecycle |
| Trigger | Deterministic (callback) | Probabilistic (timing) |
| Primitive | Function pointer hijack | PreviousMode corruption |
| Escalation | Token bit flip via RtlSetAllBits | Token pointer copy |
| Our PoC | Reproduced public exploit | Written from scratch |
| Success rate | ~100% | 97% |

</div>

The biggest lesson: a re-entry UAF gives you deterministic control (you decide exactly when the callback fires), while a race condition requires accepting probabilistic outcomes and designing for retry. Both are powerful, but they demand different mindsets.

## Mentor feedback

Our team mentor noted that the race condition analysis was thorough but suggested we dig deeper into the specific field that gets corrupted when the race is won. This is a fair point. We focused heavily on getting the exploit working and less on documenting exactly which uninitialized field provides the primitive. In a real advisory or write-up for a vendor, that level of detail would be essential.

---

In [Part 3](/research/win-kernel-eop-part3/), we cover CVE-2026-58632, a fresh vulnerability we identified ourselves through patch diffing. That analysis went in a very different direction: we found the bug, confirmed the crash, but could not achieve privilege escalation.

**Series:**
- [Part 1: HEVD to CVE-2021-40449](/research/win-kernel-eop-part1/)
- **Part 2: CVE-2025-24983**
- [Part 3: CVE-2026-58632, hunting a fresh CVE](/research/win-kernel-eop-part3/)
