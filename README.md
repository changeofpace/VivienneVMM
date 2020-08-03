VivienneVMM
===========

VivienneVMM is a stealthy debugging framework implemented via an Intel VT-x hypervisor. The VMM driver implements multiple breakpoint control managers which allow a user mode client to set, clear, and inspect VMM-backed breakpoints. These breakpoints are invisible to the guest.

This project is an extension of the [HyperPlatform](https://github.com/tandasat/HyperPlatform) framework by [tandasat](https://github.com/tandasat).


What's New
----------
## [1.0.0] - 2020-08-02

VivienneVMM 1.0.0 released. :birthday:

### Added
- **Ept breakpoints**: a new breakpoint type with many advantages over the now deprecated Vivienne hardware breakpoint type.
- New VivienneCL commands: GetProcessInformation, QueryEptBpInfo, SetEptBpBasic, SetEptBpRegisters, SetEptBpKeyed, DisableEptBp, ClearEptBp, PrintEptBpLogHeader, and PrintEptBpLogElements. See the VivienneCL [README](./VivienneCL/README.md) for more information.
- Added extended information for many VivienneCL commands. Type 'help command_name' in the VivienneCL console to see a command's extended information.
- Most commands now have an abbreviated command name.

See the [CHANGELOG](./CHANGELOG.md) for additional information.


Breakpoint Control Manager
--------------------------
The VivienneVMM driver contains two breakpoint control manager modules which implement their own style of breakpoint:

#### Ept Breakpoint Manager
* Implements **ept breakpoints** using extended page tables.
* + Ept breakpoints are undetectable by user mode processes in the guest.
* + Supports unlimited number of ept breakpoints.
* - Only execution and data breakpoints are supported.
* ~ Data breakpoint events are processed as **faults** instead of **traps**.

#### Hardware Breakpoint Manager
* Implements **hardware breakpoints** by hooking the debug exception vector and monitoring debug register accesses.
* + Faster than ept breakpoints.
* - Susceptible to certain anti-debug detection techniques.


Ept Breakpoint Manager
----------------------
The ept breakpoint manager module implements ept breakpoints using Intel VT-x extended page tables (ept) and the monitor trap flag VM execution control.

### Ept Breakpoints

Ept breakpoints are effectively hardware breakpoints with the following differences:

* Each processor can have an unlimited number of active ept breakpoints.
* Only execution and data breakpoints are supported.
* Data breakpoint events are processed as **faults** instead of **traps**. i.e., When a data ept breakpoint condition is triggered the VMM logs the event before the read or write occurs in the guest.
* Ept breakpoints cannot be detected by user mode processes in the guest OS. (See 'Limitations')

Each ept breakpoint has a corresponding ept breakpoint log.

### Ept Breakpoint Log
An ept breakpoint log contains the "breakpoint hit history" for its corresponding ept breakpoint. The contents of the log depend on the ept breakpoint log type:

#### Basic
Records each unique guest virtual address that triggers the breakpoint condition and its hit count. Traditional hardware breakpoint functionality. Can be used to discover addresses which read, write, and execute a target breakpoint address.

#### General Register Context
Records the general purpose register context each time the guest triggers the breakpoint condition.

#### Keyed Register Context
Similar to **General Register Context**, except that guest state is only recorded when the value in the *key register* is not already in the log.

### Using Ept Breakpoints

VivienneCL contains several commands for setting, disabling, clearing, and viewing ept breakpoints. The **SetEptBp\*** commands install an ept breakpoint on all processors and return a log handle. This log handle is the primary input argument for the other ept breakpoint commands.

#### Example

The following example shows the VivienneCL output of the **PrintEptBpLogElements** command for a **Keyed Register Context** ept breakpoint.

Given the following function, we want to know all possible values of the **DecryptedValue** variable:

```C
VOID
EptBreakpointExample(
    _In_ ULONG_PTR EncryptedValue
)
{
    ULONG_PTR DecryptedValue = 0;

    DecryptedValue = Decrypt(EncryptedValue);

    // ...
}
```

Disassembly:

```
;
; ImageBase = 0x140000000
;
.text:0000000140001030     mov     [rsp+EncryptedValue], rcx
.text:0000000140001035     sub     rsp, 38h
.text:0000000140001039     mov     [rsp+38h+var_18], 0
.text:0000000140001042     mov     rcx, [rsp+38h+EncryptedValue] ; EncryptedValue
.text:0000000140001047     call    Decrypt(unsigned __int64)
.text:0000000140001047
.text:0000000140001047     ; rax contains the decrypted value
.text:0000000140001047
.text:000000014000104C     mov     [rsp+38h+var_18], rax
;                          ...
```

Suppose that process **X** is executing this function randomly and uses many anti-debug techniques. Assume that the process id of process X is **5600** and the image base is **0x140000000**. We can use the **SetEptBpKeyed** command to log guest state whenever a unique value is returned from the **Decrypt** routine at **0000000140001027**:

Set the ept breakpoint with 'rax' as the key register:

```
> SetEptBpKeyed 5600 e1 14000104C 10000 1 rax
Log Handle: 1
```

Print the log elements.

```
> PrintEptBpLogElements 1
EPTBP Log #1 | PID: 5600, Address: 000000014000104C, BP: X , Status: Active, KeyedRegisterContext RAX
    NumberOfElements: 4, MaxIndex: 409
    Elements:
        0   rip: 000000014000104C flg: 0000000000010202
            rax: 138582AFE1835301 rbx: 000007FEF03369F8 rbp: 0000000000000000 rsp: 000000000012FE70
            rcx: FFFFFFFFFFFFFF7F rdx: 0000000000000000 r8:  000007FFFFFDE000 r9:  000007FEF0303BD0
            rdi: 0000000000368120 rsi: 0000000000000000 r10: B0003A0D060A5F66 r11: 00003A0D067C9178
            r12: 0000000000000000 r13: 0000000000000000 r14: 0000000000000000 r15: 0000000000000000

        1   rip: 000000014000104C flg: 0000000000010202
            rax: FFF83815FA800890 rbx: 000007FEF03369F8 rbp: 0000000000000000 rsp: 000000000012FE70
            rcx: FFFFFFFFFFFFB123 rdx: 0000000000000000 r8:  000007FFFFFDE000 r9:  000007FEF0303BD0
            rdi: 0000000000368120 rsi: 0000000000000000 r10: B0003A0D060A5F66 r11: 00003A0D067C9178
            r12: 0000000000000000 r13: 0000000000000000 r14: 0000000000000000 r15: 0000000000000000

        2   rip: 000000014000104C flg: 0000000000010202
            rax: FFFFFFFFFFFFFFFF rbx: 000007FEF03369F8 rbp: 0000000000000000 rsp: 000000000012FE70
            rcx: FFFFFFFFFFFFEDED rdx: 0000000000000000 r8:  000007FFFFFDE000 r9:  000007FEF0303BD0
            rdi: 0000000000368120 rsi: 0000000000000000 r10: B0003A0D060A5F66 r11: 00003A0D067C9178
            r12: 0000000000000000 r13: 0000000000000000 r14: 0000000000000000 r15: 0000000000000000

        3   rip: 000000014000104C flg: 0000000000010202
            rax: 00103350308F80CD rbx: 000007FEF03369F8 rbp: 0000000000000000 rsp: 000000000012FE70
            rcx: FFFFFFFFFFFFDB89 rdx: 0000000000000000 r8:  000007FFFFFDE000 r9:  000007FEF0303BD0
            rdi: 0000000000368120 rsi: 0000000000000000 r10: B0003A0D060A5F66 r11: 00003A0D067C9178
            r12: 0000000000000000 r13: 0000000000000000 r14: 0000000000000000 r15: 0000000000000000
```

From the log output above we can see that there were four decrypted values used by process X: **138582AFE1835301**, **FFF83815FA800890**, **FFFFFFFFFFFFFFFF**, and **00103350308F80CD**.

Now suppose that we are finished with this ept breakpoint, but we want to continue debugging process X. We can use the **DisableEptBp** command to uninstall the breakpoint while keeping the breakpoint log valid:

```
> DisableEptBp 1

```

If we print the log elements again then we can see that the breakpoint is inactive:

```
> PrintEptBpLogElements 1
EPTBP Log #1 | PID: 5600, Address: 000000014000104C, BP: X , Status: Inactive, KeyedRegisterContext RAX
    NumberOfElements: 4, MaxIndex: 409
    Elements:
        0   rip: 000000014000104C flg: 0000000000010202
            rax: 138582AFE1835301 rbx: 000007FEF03369F8 rbp: 0000000000000000 rsp: 000000000012FE70
            rcx: FFFFFFFFFFFFFF7F rdx: 0000000000000000 r8:  000007FFFFFDE000 r9:  000007FEF0303BD0
            rdi: 0000000000368120 rsi: 0000000000000000 r10: B0003A0D060A5F66 r11: 00003A0D067C9178
            r12: 0000000000000000 r13: 0000000000000000 r14: 0000000000000000 r15: 0000000000000000

        1   rip: 000000014000104C flg: 0000000000010202
            rax: FFF83815FA800890 rbx: 000007FEF03369F8 rbp: 0000000000000000 rsp: 000000000012FE70
            rcx: FFFFFFFFFFFFB123 rdx: 0000000000000000 r8:  000007FFFFFDE000 r9:  000007FEF0303BD0
            rdi: 0000000000368120 rsi: 0000000000000000 r10: B0003A0D060A5F66 r11: 00003A0D067C9178
            r12: 0000000000000000 r13: 0000000000000000 r14: 0000000000000000 r15: 0000000000000000

        2   rip: 000000014000104C flg: 0000000000010202
            rax: FFFFFFFFFFFFFFFF rbx: 000007FEF03369F8 rbp: 0000000000000000 rsp: 000000000012FE70
            rcx: FFFFFFFFFFFFEDED rdx: 0000000000000000 r8:  000007FFFFFDE000 r9:  000007FEF0303BD0
            rdi: 0000000000368120 rsi: 0000000000000000 r10: B0003A0D060A5F66 r11: 00003A0D067C9178
            r12: 0000000000000000 r13: 0000000000000000 r14: 0000000000000000 r15: 0000000000000000

        3   rip: 000000014000104C flg: 0000000000010202
            rax: 00103350308F80CD rbx: 000007FEF03369F8 rbp: 0000000000000000 rsp: 000000000012FE70
            rcx: FFFFFFFFFFFFDB89 rdx: 0000000000000000 r8:  000007FFFFFDE000 r9:  000007FEF0303BD0
            rdi: 0000000000368120 rsi: 0000000000000000 r10: B0003A0D060A5F66 r11: 00003A0D067C9178
            r12: 0000000000000000 r13: 0000000000000000 r14: 0000000000000000 r15: 0000000000000000
```

Ept breakpoints can have a significant performance cost because an ept violation occurs whenever the guest accesses the target page in a manner which matches the ept breakpoint condition. e.g., If we set an execute ept breakpoint in an an address in a page, then the guest will experience an ept violation VM exit whenever it executes an instruction inside that page.

We can use the **QueryEptBpInfo** command to get a list of all ept breakpoints on the system:

```
> QueryEptBpInfo
Ept Breakpoint Information
    0 active breakpoints.
    1 inactive breakpoints.
    0 locked pages.
    0 hooked pages.
    Breakpoints:
        Handle   PID          Address BP     Status                LogType #Elements MaxIndex
        -------------------------------------------------------------------------------------
             1  5600 000000014000104C X    Inactive   KeyedRegisterContext         4      409
```

Finally, we can release the resources for an ept breakpoint log using the **ClearEptBp** command:

```
> ClearEptBp 1

```

See the VivienneCL [README](./VivienneCL/README.md) for more command information.

### Limitations

* Currently only user mode clients are supported. Kernel support is in development.
* Unhandled edge cases may reveal the presence of ept breakpoints to user processes in the guest OS.


Hardware Breakpoint Manager
---------------------------
The hardware breakpoint manager is deprecated since the release of the ept breakpoint manager. Developers can enable the hardware breakpoint manager by modifying the [config file](./common/config.h).

Legacy documentation can be found [here](./Documentation/HardwareBreakpointManager.md).


Project Structure
-----------------

### VivienneVMM
The core driver project containing the Vivienne virtual machine monitor.

### VivienneCL
A command line VivienneVMM client which makes use of the breakpoint control interfaces. A simple debugger.

### VivienneTests
VivienneVMM test cases.

This project uses [HyperPlatform](https://github.com/tandasat/HyperPlatform) as a git subtree with prefix='VivienneVMM/HyperPlatform'. We subtree the project instead of using a git submodule because we must modify HyperPlatform files to implement VivienneVMM features. This allows us to merge HyperPlatform updates from upstream with minimal merge conflicts.

The following list of console commands are an example of how to pull HyperPlatform updates into a local VivienneVMM repository:

    # Remote configuration.
    cd VivienneVMM/
    git checkout master
    git remote add upstream https://github.com/tandasat/HyperPlatform.git
    git remote set-url --push upstream DISABLED

    # Pulling updates.
    cd VivienneVMM/
    git fetch upstream
    git subtree pull --prefix=VivienneVMM/HyperPlatform upstream master


Related Projects
----------------

* HyperPlatform
* https://github.com/tandasat/HyperPlatform

HyperPlatform is an Intel VT-x based hypervisor (a.k.a. virtual machine monitor) aiming to provide a thin platform for research on Windows. HyperPlatform is capable of monitoring a wide range of events, including but not limited to, access to virtual/physical memory and system registers, occurrences of interrupts and execution of certain instructions.

* DdiMon
* https://github.com/tandasat/DdiMon

DdiMon is a hypervisor performing inline hooking that is invisible to a guest (ie, any code other than DdiMon) by using extended page table (EPT).


Notes
-----

* This project was developed and tested on Windows 7 x64 SP1.
* All binaries are PatchGuard safe on Windows 7.
* x86 is not supported and WoW64 is untested.


Special Thanks
--------------

* [tandasat](https://github.com/tandasat)
* [dude719](https://github.com/dude719)
