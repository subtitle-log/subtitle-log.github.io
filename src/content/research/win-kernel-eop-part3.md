---
title: "Windows Kernel 1-day EoP, Part 3: CVE-2026-58632"
summary: "Identifying a fresh CVE through patch diffing and feature flag clustering. We found the bug, confirmed the crash, but EoP was out of reach."
date: 2026-10-17
tags: ["WHS Kernel EoP", "patch diffing", "win32k", "UAF"]
draft: false
featured: true
category: CVE
---

This is the final part of the series. In [Part 1](/research/win-kernel-eop-part1/) we built UAF fundamentals with HEVD and CVE-2021-40449. In [Part 2](/research/win-kernel-eop-part2/) we wrote our own race condition exploit for CVE-2025-24983. Here, we tackle something different: identifying a vulnerability from a patch diff when over 600 functions changed between builds.

CVE-2026-58632 is a Use-After-Free in `win32kfull.sys` in the edge swipe gesture handler. We found the root cause, triggered a Special Pool crash, and analyzed the primitive. We did not achieve privilege escalation. This write-up is honest about what worked and what did not.

## Starting point: 600+ changed functions

We began with two builds of `win32kfull.sys` for Windows Server 2016:
- **Vulnerable:** build 14393.9234
- **Patched:** build 14393.9339

Running ghidriff on these two binaries produced a diff with over 600 changed functions. This is a common problem with Windows cumulative updates: each patch rollup bundles fixes for multiple CVEs, feature changes, and even compiler differences. The challenge is figuring out which changes correspond to which CVE.

Most of these 600+ changes are noise: recompilation artifacts, unrelated feature work, or minor code reorganization. Finding the security-relevant changes requires a strategy.

## Feature flag clustering

This is the technique that made the analysis tractable. Instead of reading every changed function, we grouped them by feature.

Windows uses feature flags (sometimes called velocity keys or flighting features) throughout the codebase. Functions related to the same feature often share references to the same flag constants or configuration paths. By tracing which feature flags are referenced by which changed functions, you can cluster the 600+ changes into groups that likely correspond to the same fix or feature.

We noticed a cluster of changes in functions related to edge gestures (the swipe-from-edge interaction on touch devices). These functions referenced common structures and had the kind of changes you see in a UAF fix: added reference counting, pointer nullification, and bounds checking. This cluster stood out from the rest as a likely security fix.

The other clusters were either clearly non-security (UI string changes, telemetry updates) or too small to represent a meaningful vulnerability. Edge gestures had the right profile: a kernel-mode handler processing input events with complex object lifetime management.

## The Edgy subsystem

Edge swipe gestures in Windows are handled by what the code calls the "Edgy" subsystem. The relevant structures:

**tagEDGY_DATA** (the main container):
- +0x00: listener count
- +0x04: capacity
- +0x08: pointer to listener array
- +0x10: state
- +0xB8: cache pointer (points into the listener array)

**tagEDGY_LISTENER** (32 bytes each):
- +0x00: device handle
- +0x08: hwnd (window handle)
- +0x10: location (which screen edge)

An application registers for edge gesture notifications via `NtUserRegisterEdgy`. Internally this calls:

```
NtUserRegisterEdgy
  -> EdgyRegisterListener
    -> _AddOrUpdateListener
      -> _AllocListener
        -> _GrowListeners  (when array is full)
```

`_GrowListeners` is called when the listener array runs out of capacity. It allocates a new, larger array, copies the existing listeners over, and frees the old array. The growth pattern follows powers of 2: at count 4, the capacity doubles to 8, then 16, then 32.

## Root cause: the stale cache pointer

Here is the bug. The `tagEDGY_DATA` structure has a cache pointer at offset +0xB8 that points directly into the listener array. When `_GrowListeners` reallocates the array, it updates the main array pointer at +0x08 but does not update the cache pointer at +0xB8.

After reallocation:
- +0x08 points to the new array (valid)
- +0xB8 still points into the old array (freed)

Any subsequent access through the cache pointer at +0xB8 is a Use-After-Free. The old array has been freed, and the cache pointer is dangling.

The following diagram shows the state before reallocation (both pointers valid), after reallocation in the vulnerable version (cache pointer stale), and how the patch fixes it:

![CVE-2026-58632: _GrowListeners stale cache pointer before/after reallocation](/img/kernel-eop/58632-stale-cache.svg)

The patch adds a line that updates the +0xB8 cache pointer after reallocation. Same pattern as HEVD: a pointer that outlives the object it references, fixed by updating the pointer when the object moves.

## Triggering the bug

Triggering `_GrowListeners` requires registering enough edge gesture listeners to exceed the current capacity. We needed to:

1. Get our process recognized as the shell process (required for edge gesture registration).
2. Synthesize touch input events to trigger edge swipe handling.
3. Register enough listeners to force array reallocation.

### IsShellProcess bypass

Edge gesture registration checks whether the calling process is the shell process (Explorer). A non-shell process gets rejected. We bypassed this by:

1. `CreateDesktop` to create a new desktop.
2. `SetShellWindow` on the new desktop to designate our window as the shell window.
3. Now our process passes the `IsShellProcess` check for that desktop.

This is not an exploit for `IsShellProcess` itself. It is a known technique for getting access to APIs that are normally shell-only. The important thing is that it works from a standard user account.

### Touch injection

Edge gestures require actual touch input, not mouse events. We used `InjectTouchInput` to synthesize touch contacts that start from a screen edge and swipe inward. This triggers the Edgy subsystem to process the gesture and invoke the registered listeners.

### Forcing reallocation

We registered listeners in a loop, incrementing a counter. The array starts small and grows at powers of 2. After registering the 4th listener, `_GrowListeners` fires for the first time (capacity goes from 4 to 8). We set a breakpoint on `_GrowListeners` and confirmed the reallocation.

After reallocation, we checked the cache pointer:

```
dt tagEDGY_DATA [address]
  +0x08: 0xffff9a01`12340000  (new array)
  +0xB8: 0xffff9a01`abcd0000  (old array, FREED)
```

The +0xB8 pointer still holds the old address. Classic dangling pointer, confirmed dynamically.

## Special Pool crash

To verify the UAF is a real memory safety issue and not just a stale-but-harmless pointer, we enabled Special Pool for `win32kfull.sys`. Special Pool places guard pages around pool allocations so that accessing freed memory triggers an immediate bugcheck instead of silently reading stale data.

The screenshot below shows Special Pool enabled via Driver Verifier:

![WinDbg !verifier showing Special Pool enabled for win32kfull.sys](/img/kernel-eop/58632-special-pool.png)

With Special Pool enabled, triggering the bug produced:

```
BugCheck 0xD5 (DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL)
  at _GetArcData+0x1e3
```

BugCheck 0xD5 at an offset within `_GetArcData` confirms that the code is accessing memory beyond a freed allocation. The crash point is in a function that reads arc gesture data from the listener structure through the stale cache pointer.

The `!analyze -v` output confirms the access was a **read** operation (Arg2=0), which is key for understanding the primitive:

![!analyze -v: DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL (d5), Arg2=0 read](/img/kernel-eop/58632-analyze.png)

The full callstack shows the crash path: `_GetArcData` trying to read through the stale cache, hitting the freed page:

![Crash callstack: _GetArcData+0x1e3 -> MmAccessFault -> KeBugCheck](/img/kernel-eop/58632-callstack.png)

This is clean confirmation: the dangling pointer at +0xB8 is dereferenced during gesture processing, hitting the freed page.

## Analyzing the primitive

A UAF is only as useful as the primitive it gives you. Here, we had to figure out: what happens when the cache pointer is dereferenced? Can we control what lands in the freed slot? Can we get a write, or only a read?

The answer was disappointing.

The cache pointer at +0xB8 is used to look up a `tagEDGY_LISTENER` entry, and from that entry, the hwnd field (at +0x08) is passed to `ValidateHwnd`. `ValidateHwnd` is a kernel function that takes a window handle, validates it against the handle table, and returns the kernel window object pointer.

The problem: `ValidateHwnd` is a **read operation**. It reads the hwnd value from the freed memory and uses it as a handle lookup. This gives us:

1. **A read primitive**, not a write primitive. We can influence which handle gets validated by controlling what data lands in the freed listener slot.
2. **No direct code execution.** Unlike CVE-2021-40449 where the freed PDEV had a function pointer table, here the freed data goes through a handle validation function. There is no indirect call through the freed data.
3. **No straightforward path to EoP.** A read-only primitive through `ValidateHwnd` can potentially leak kernel addresses (useful for KASLR bypass), but on its own, it does not give write-what-where or code execution.

We explored several ideas:
- **Heap spray the freed slot** with a fake listener containing a crafted hwnd. `ValidateHwnd` would process it, but the return value flows into code paths we could not redirect to anything useful.
- **Chain with another bug.** A kernel address leak from this primitive could enhance a separate write primitive, but we did not have one for this target.
- **Look for other code paths** that use the cache pointer differently. We did not find any that gave a write.

## Honest assessment

We identified the vulnerability, confirmed the root cause, triggered the crash, and analyzed the primitive in depth. But we did not achieve privilege escalation. The primitive is read-only through a validated handle path, which significantly limits exploitation.

This is not unusual for real-world vulnerability research. Not every bug is exploitable, and not every UAF gives you a function pointer to hijack. The ability to find the bug, understand why it is a bug, and correctly assess the exploitability is itself a valuable skill, arguably more valuable than following a known exploitation recipe.

What we learned:
1. **Patch diffing at scale** requires a systematic approach. Feature flag clustering turned 600+ function changes into manageable groups.
2. **Not all UAFs are equal.** The object being freed, the code path that dereferences it, and the operations performed on the stale data determine the primitive class. A function pointer in the freed object (like CVE-2021-40449) gives code execution. A data field that goes through validation (like this one) gives, at best, an info leak.
3. **IsShellProcess and touch injection** are practical obstacles that can eat days of work if you do not know the tricks. Documenting the bypass path is valuable for future work.
4. **Special Pool is essential** for confirming UAF. Without it, the bug might silently succeed on stale-but-valid data, making it hard to tell whether you are even hitting the right code path.

## Series summary

Across three CVEs and one educational driver, we went from pool allocation basics to writing our own exploit to identifying a fresh vulnerability through patch analysis:

<div class="table-wrap">

| Target | Bug class | Trigger | Exploitation | Key technique |
|:--|:--|:--|:--|:--|
| HEVD | UAF | Direct IOCTL | RIP control | Pool spray |
| CVE-2021-40449 | UAF (re-entry) | Usermode callback | SYSTEM (public PoC) | Palette heap spray |
| CVE-2025-24983 | Race condition | Thread timing | SYSTEM 97/100 (own PoC) | PreviousMode flip |
| CVE-2026-58632 | UAF (realloc) | Listener overflow | Crash only | Feature flag clustering |

</div>

The progression was deliberate. HEVD taught the mechanics. CVE-2021-40449 showed how those mechanics appear in real vulnerabilities. CVE-2025-24983 proved we could build an exploit independently. CVE-2026-58632 demonstrated that finding the bug is only half the battle.

---

**Series:**
- [Part 1: HEVD to CVE-2021-40449](/research/win-kernel-eop-part1/)
- [Part 2: CVE-2025-24983, writing our own EoP exploit](/research/win-kernel-eop-part2/)
- **Part 3: CVE-2026-58632**
