VivienneVMM
===========

VivienneVMM is a stealthy debugging framework implemented via an Intel VT-x hypervisor. The driver exposes a hardware breakpoint control interface which allows a user mode client to set and clear breakpoints. These breakpoints are invisible to the guest.

This project uses the [HyperPlatform](https://github.com/tandasat/HyperPlatform) framework by [tandasat](https://github.com/tandasat).


Projects
--------

### VivienneVMM
The core driver project containing the Vivienne Virtual Machine Monitor.

### VivienneCL
A command line VivienneVMM client which makes use of the hardware breakpoint control interface. A simple debugger.

### Tests
VivienneVMM test cases.


Implementation
--------------

### Breakpoint Manager
The breakpoint manager (BPM) modifies processor debug registers to install and uninstall hardware breakpoints. Each modification is performed synchronously on all logical processors using the following protocol:

1. The client requests a breakpoint change via an IOCTL.
2. BPM receives the client request and validates the input parameters.
3. BPM issues an IPI broadcast so that all processors synchronously execute a vmcall.
4. Each processor modifies its debug registers in VMX root mode so that a MovDr event does not occur.

Processors generate a debug exception when the execution of an instruction satisfies a hardware breakpoint condition. The breakpoint manager monitors these exceptions via a debug exception VM exit handler, and consumes exceptions caused by BPM-managed breakpoints.

Users can customize breakpoint behavior by registering a callback during breakpoint installation. Callbacks are executed in VMX root mode, in the context of the target process, whenever the breakpoint condition is met. **Capture execution context** is an example callback which acts as an execution hook to read register state.

### Debug Register Facade
The debug register facade prevents the guest from accessing processor debug registers via a MovDr VM exit handler. This handler emulates debug register access instructions using a set of processor-specific, 'fake' debug registers.


Capture Execution Context
-------------------------

The capture execution context (CEC) module implements two breakpoint callbacks: capture execution context register (CECR) and capture execution context memory (CECM).

### Capture Execution Context Register (CECR)
This callback samples the contents of a target register and records unique values to a user-supplied buffer.

#### Example
For this example, we must reverse engineer the 'player' data structure(s) of a multiplayer FPS game. Our goal is to be able to reliably obtain all player pointers for an in game 'round' from our out-of-process client.

We have identified the following function in the game's code which constantly iterates a list of player pointers:

```C++
VOID
ProcessGameTick(
    _In_ ULONG NumberOfPlayers
)
{
    for (ULONG i = 0; i < NumberOfPlayers; ++i)
    {
        PVOID pPlayer = GetDecryptedPlayerPointer(i);
        SimulatePlayerTick(pPlayer);
    }
}
```

Disassembly of the for loop:

```
.text:0000000140001032 loc_140001032:
.text:0000000140001032     mov     eax, [rsp+38h+PlayerIndex]
.text:0000000140001036     inc     eax
.text:0000000140001038     mov     [rsp+38h+PlayerIndex], eax
.text:000000014000103C
.text:000000014000103C loc_14000103C:
.text:000000014000103C     mov     eax, [rsp+38h+arg_0]
.text:0000000140001040     cmp     [rsp+38h+PlayerIndex], eax
.text:0000000140001044     jnb     short loc_140001060
.text:0000000140001046     mov     ecx, [rsp+38h+PlayerIndex]
.text:000000014000104A     call    GetDecryptedPlayerPointer
.text:000000014000104F     mov     [rsp+38h+pPlayer], rax       ; target.
.text:0000000140001054     mov     rcx, [rsp+38h+pPlayer]
.text:0000000140001059     call    SimulatePlayerTick
.text:000000014000105E     jmp     short loc_140001032
```

We determine that we can calculate player pointers if we are able to recreate the **GetDecryptedPlayerPointer** function. Now, imagine that this function is heavily obfuscated to the point that it would require an unrealistic amount of time to reverse. Normally we would dismiss this code snippet because the reward is not worth the time investment.

We can accomplish our goal without reversing **GetDecryptedPlayerPointer** by executing a **capture register values** (CECR) IOCTL for register **RAX** at address **0x14000104F**. The CEC module satisfies this CECR request by installing an ephemeral hardware breakpoint at **0x14000104F** for the target process. When the target process executes the instruction at this address, a debug exception is generated and processed by BPM. BPM then invokes the CECR callback which records every unique value in the **RAX** register to the IOCTL buffer. The unique values buffer is returned to the client when the breakpoint duration expires.

The following snippet is the client code for this example's CECR request:

```C++
UCHAR pBuffer[PAGE_SIZE] = {};
PCEC_REGISTER_VALUES pRegisterValues = (PCEC_REGISTER_VALUES)pBuffer;
BOOL status = TRUE;

status = DrvCaptureRegisterValues(
    GetTargetProcessId(),
    0,
    (ULONG_PTR)0x14000104F,
    HWBP_TYPE::Execute,
    HWBP_SIZE::Byte,
    REGISTER_RAX,
    5000,
    pRegisterValues,
    sizeof(pBuffer));
```

### Capture Execution Context Memory (CECM)
This callback samples the memory-data-typed contents of a memory address defined by a memory expression.

A memory expression can either be an absolute, virtual address or an indirect address in x64 addressing-mode form. The following are examples of valid memory expressions and their evaluations:

    14000           ; effective address = [14000]
    rax             ; effective address = [rax]
    rcx+rax-20      ; effective address = [rcx+rax-20]
    rcx+rax*8       ; effective address = [rcx+rax*8]
    rcx+rax*8-20    ; effective address = [rcx+rax*8-20]

For each callback invocation, the effective address is calculated, validated, and interpreted as a pointer to one of the following user-specified types:

    byte
    word
    dword
    qword
    float
    double

The value obtained by dereferencing the effective pointer is the value recorded in the unique values buffer.

#### Example
For this example, we want to sample float values stored in xmm0 in the following instruction:

```
.text:0000000140001066     movss   dword ptr [rsp+rax*4+30h], xmm0
.text:000000014000106C     ret
```

We can easily capture these values using the following CECM request:

```C++
UCHAR pBuffer[PAGE_SIZE] = {};
CEC_MEMORY_DESCRIPTION MemoryDescription = {};
PCEC_MEMORY_VALUES pMemoryValues = NULL;
PMEMORY_DATA_VALUE pMemoryDataValue = NULL;
BOOL status = TRUE;

// Translate the memory expression and data type into a memory description.
status = ParseMemoryDescriptionToken(
    "rsp+rax*4+30",
    MDT_FLOAT,
    &MemoryDescription);
if (!status)
{
    goto exit;
}

// Issue the CECM request.
status = DrvCaptureMemoryValues(
    GetTargetProcessId(),
    0,
    (ULONG_PTR)0x14000106C,
    HWBP_TYPE::Execute,
    HWBP_SIZE::Byte,
    &MemoryDescription,
    5000,
    pMemoryValues,
    sizeof(pBuffer));
if (!status)
{
    goto exit;
}

// Log the results.
for (ULONG i = 0; i < pValuesCtx->NumberOfValues; ++i)
{
    pMemoryDataValue = (PMEMORY_DATA_VALUE)&pValuesCtx->Values[i];
    printf("    %u: %f\n", i, pMemoryDataValue->Float);
}
```

See the CECM command description in the VivienneCL README for more information.


Limitations
-----------

When the debug register facade is active, hardware breakpoints installed by the guest (into the fake debug registers) cannot be triggered. A process can detect this side effect by installing a breakpoint, triggering the breakpoint condition, and then waiting for a single-step exception that will never be delivered.


EPT Hooking Comparison
----------------------

EPT hooking is a viable alternative for implementing stealth debugging which does not have the limitation(s) described above. The trade-offs are:

* Maintaining EPT page mappings is arguably more complex than debug register bookkeeping.
* EPT hooks are slower than hardware breakpoint hooks because EPT hooks have a page-sized trigger range versus the byte, word, dword, and qword trigger range of hardware breakpoints.
* The target machine must use a processor that supports EPT.


Project Structure
-----------------

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


Notes
-----

* This project was developed and tested on Windows 7 x64 SP1.
* All binaries are PatchGuard safe on Windows 7.
* x86 is not supported and WoW64 is untested.
* Hardware breakpoints are restricted to user space addresses (for now).


Special Thanks
--------------

* [tandasat](https://github.com/tandasat)
* [dude719](https://github.com/dude719)
