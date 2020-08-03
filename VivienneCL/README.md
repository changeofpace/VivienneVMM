VivienneCL
==========

VivienneCL is a command line VivienneVMM client which exposes the VivienneVMM breakpoint control interfaces through commands.


Installation
------------

1. Enable test signing on the target machine.
2. Load the driver.
3. Execute **VivienneCL.exe**.


Commands
--------

### General

**commands**

    Short Name
        cmds

    Summary
        Display a list of available commands.

**help**

    Usage
        help [command_name]

    Summary
        Display extended command information.

    Parameters
        command_name (optional)
            If a valid command name is specified then that command's extended
            information is displayed.

            If an invalid command name is specified or no command name is
            specified then the available command list is displayed.

**exit**

    Summary
        Terminate the VivienneCL session.

### Process

**GetProcessId**

    Short Name
        procid

    Summary
        Lookup process ids by process name.

    Parameters
        process_name (string)
            The target process name including file extension.

    Example
        procid calc.exe

**GetProcessInformation**

    Short Name
        procinfo

    Summary
        Query general information for the specified process.

    Parameters
        process_id (decimal)
            The target process id.

### Ept Breakpoints (Requires Ept Breakpoint Manager module)

**QueryEptBpInfo**

    Usage: QueryEptBpInfo

    Short Name
        qebi

    Summary
        Print ept breakpoint log header information for all installed ept
        breakpoints. Print general statistics about the ept breakpoint manager.

**SetEptBpBasic**

    Usage: SetEptBpBasic pid access|size address log_size make_page_resident

    Short Name
        sebb

    Summary
        Set an ept breakpoint in the target process context. The corresponding
        breakpoint log contains 'basic' elements. Each element contains the
        following fields:

            TriggerAddress - Unique address of the instruction that triggered
                the breakpoint condition.

            HitCount - Number of times this element triggered the breakpoint
                condition.

    Parameters
        pid (decimal)
            The target process id.

        access|size (WinDbg hardware breakpoint syntax)
            access (one character)
                The ept breakpoint type:

                    'e'     execute
                    'r'     read
                    'w'     write

            size (one decimal integer)
                The ept breakpoint size:

                    '1'     byte
                    '2'     word
                    '4'     dword
                    '8'     qword

            NOTE Execution breakpoints must be '1' byte size.

        address (hex, '0x' prefix optional)
            The target virtual address.

        log_size (hex, '0x' prefix optional)
            The size in bytes of the returned log. i.e., How many elements the
            log can store.

        make_page_resident (decimal)
            If non-zero then the physical page that contains the target virtual
            address is made resident if it is currently paged out.

    Return Value
        A handle (decimal) to the breakpoint log.

    Remarks
        Ept breakpoints are in one of the following states at any given time:

            Installing
            Active
            Inactive

        If an ept breakpoint is in the 'installing' state then it is currently
        being installed on all processors. The breakpoint becomes 'active' as
        soon as installation succeeds.

        The breakpoint log for an 'active' ept breakpoint is valid, readable,
        and the breakpoint log elements are updated by the ept breakpoint
        manager.

        Ept breakpoints become 'inactive' when their target process terminates,
        or they are manually disabled by calling 'DisableEptBp'. The breakpoint
        log for an 'inactive' ept breakpoint is valid and readable, but its
        breakpoint log elements are no longer updated by the ept breakpoint
        manager. Inactive ept breakpoints are uninstalled from all processors.
        Inactive breakpoints remain in the 'inactive' state until they are
        manually cleared by calling 'ClearEptBp' or the VivienneCL session
        ends.

        The 'BreakpointStatus' field of a breakpoint log header contains the
        current state of its corresponding ept breakpoint.

        Ept breakpoints can have a significant performance cost because an ept
        violation occurs whenever the guest accesses the target page in a
        manner which matches the ept breakpoint condition. e.g., If we set an
        execute ept breakpoint in an an address in a page, then the guest will
        experience an ept violation VM exit whenever it executes an instruction
        inside that page. Users should disable ept breakpoints when they are
        no longer required.

    Example
        Set an execution breakpoint at 0x70000 in process 314, use 0x1000 bytes
        for the breakpoint log, and make the physical page resident:

            sebb 314 e1 70000 1000 1

**SetEptBpRegisters**

    Usage: SetEptBpRegisters pid access|size address log_size make_page_resident

    Short Name
        sebg

    Summary
        Set an ept breakpoint in the target process context. The corresponding
        breakpoint log contains 'general register context' elements. Each
        element contains the following fields:

            TriggerAddress - Non-unique address of the instruction that
                triggered the breakpoint condition.

            Registers - The values in the general purpose registers when the
                breakpoint condition was triggered.

            Flags - The value in the RFLAGS register when the breakpoint
                condition was triggered.

    Parameters
        pid (decimal)
            The target process id.

        access|size (WinDbg hardware breakpoint syntax)
            access (one character)
                The ept breakpoint type:

                    'e'     execute
                    'r'     read
                    'w'     write

            size (one decimal integer)
                The ept breakpoint size:

                    '1'     byte
                    '2'     word
                    '4'     dword
                    '8'     qword

            NOTE Execution breakpoints must be '1' byte size.

        address (hex, '0x' prefix optional)
            The target virtual address.

        log_size (hex, '0x' prefix optional)
            The size in bytes of the returned log. i.e., How many elements the
            log can store.

        make_page_resident (decimal)
            If non-zero then the physical page that contains the target virtual
            address is made resident if it is currently paged out.

    Return Value
        A handle (decimal) to the breakpoint log.

    Remarks
        Ept breakpoints are in one of the following states at any given time:

            Installing
            Active
            Inactive

        If an ept breakpoint is in the 'installing' state then it is currently
        being installed on all processors. The breakpoint becomes 'active' as
        soon as installation succeeds.

        The breakpoint log for an 'active' ept breakpoint is valid, readable,
        and the breakpoint log elements are updated by the ept breakpoint
        manager.

        Ept breakpoints become 'inactive' when their target process terminates,
        or they are manually disabled by calling 'DisableEptBp'. The breakpoint
        log for an 'inactive' ept breakpoint is valid and readable, but its
        breakpoint log elements are no longer updated by the ept breakpoint
        manager. Inactive ept breakpoints are uninstalled from all processors.
        Inactive breakpoints remain in the 'inactive' state until they are
        manually cleared by calling 'ClearEptBp' or the VivienneCL session
        ends.

        The 'BreakpointStatus' field of a breakpoint log header contains the
        current state of its corresponding ept breakpoint.

        Ept breakpoints can have a significant performance cost because an ept
        violation occurs whenever the guest accesses the target page in a
        manner which matches the ept breakpoint condition. e.g., If we set an
        execute ept breakpoint in an an address in a page, then the guest will
        experience an ept violation VM exit whenever it executes an instruction
        inside that page. Users should disable ept breakpoints when they are
        no longer required.

    Example
        Set a write-access breakpoint for a word-sized value at 0x141800 in
        process 2000, use 0x20000 bytes for the breakpoint log, and do not make
        the physical page resident:

            sebg 2000 w2 141800 20000 0

**SetEptBpKeyed**

    Usage: SetEptBpKeyed pid access|size address log_size make_page_resident register_key

    Short Name
        sebk

    Summary
        Set an ept breakpoint in the target process context. The corresponding
        breakpoint log contains 'keyed register context' elements. Each
        element contains the following fields:

            KeyValue - The unique value of the register specified in the
                'RegisterKey' field of the log header.

            TriggerAddress - Address of the instruction that triggered the
                breakpoint condition.

            HitCount - Number of times this element triggered the breakpoint
                condition.

            Registers - The values in the general purpose registers when the
                breakpoint condition was triggered.

            Flags - The value in the RFLAGS register when the breakpoint
                condition was triggered.

        The ept breakpoint manager updates the breakpoint log for unique values
        in the key register. e.g., If an ept breakpoint uses 'rax' for its
        register key, and the guest triggers the breakpoint condition twice
        with rax = 4, then only the first trigger event is recorded in the log.
        If the guest triggers the breakpoint condition again with rax = 5 then
        the log is updated because there is no element whose rax value is 5.

    Parameters
        pid (decimal)
            The target process id.

        access|size (WinDbg hardware breakpoint syntax)
            access (one character)
                The ept breakpoint type:

                    'e'     execute
                    'r'     read
                    'w'     write

            size (one decimal integer)
                The ept breakpoint size:

                    '1'     byte
                    '2'     word
                    '4'     dword
                    '8'     qword

            NOTE Execution breakpoints must be '1' byte size.

        address (hex, '0x' prefix optional)
            The target virtual address.

        log_size (hex, '0x' prefix optional)
            The size in bytes of the returned log. i.e., How many elements the
            log can store.

        make_page_resident (decimal)
            If non-zero then the physical page that contains the target virtual
            address is made resident if it is currently paged out.

        register_key (register string)
            Specify which register is used to determine uniqueness of a guest
            context when the breakpoint condition is triggered.

            e.g., If 'register_key' is 'rax' then each element in the
            breakpoint log will have a unique value in the rax register.

    Return Value
        A handle (decimal) to the breakpoint log.

    Remarks
        Ept breakpoints are in one of the following states at any given time:

            Installing
            Active
            Inactive

        If an ept breakpoint is in the 'installing' state then it is currently
        being installed on all processors. The breakpoint becomes 'active' as
        soon as installation succeeds.

        The breakpoint log for an 'active' ept breakpoint is valid, readable,
        and the breakpoint log elements are updated by the ept breakpoint
        manager.

        Ept breakpoints become 'inactive' when their target process terminates,
        or they are manually disabled by calling 'DisableEptBp'. The breakpoint
        log for an 'inactive' ept breakpoint is valid and readable, but its
        breakpoint log elements are no longer updated by the ept breakpoint
        manager. Inactive ept breakpoints are uninstalled from all processors.
        Inactive breakpoints remain in the 'inactive' state until they are
        manually cleared by calling 'ClearEptBp' or the VivienneCL session
        ends.

        The 'BreakpointStatus' field of a breakpoint log header contains the
        current state of its corresponding ept breakpoint.

        Ept breakpoints can have a significant performance cost because an ept
        violation occurs whenever the guest accesses the target page in a
        manner which matches the ept breakpoint condition. e.g., If we set an
        execute ept breakpoint in an an address in a page, then the guest will
        experience an ept violation VM exit whenever it executes an instruction
        inside that page. Users should disable ept breakpoints when they are
        no longer required.

    Example
        Set a read-access breakpoint for a qword-sized value at 0x21210 in
        process 5004, use 0x1000 bytes for the breakpoint log, and do not make
        the physical page resident:

            sebk 5004 a8 0x21210 0x1000 0

**DisableEptBp**

    Usage: DisableEptBp log_handle

    Short Name
        deb

    Summary
        Disable an active ept breakpoint.

        The disabled breakpoint becomes 'inactive' after it is successfully
        uninstalled from all processors. The breakpoint log for an 'inactive'
        ept breakpoint is valid and readable, but its breakpoint log elements
        are no longer updated by the ept breakpoint manager.

        Inactive breakpoints remain in the 'inactive' state until they are
        manually cleared by calling 'ClearEptBp' or the VivienneCL session
        ends.

        Disabling an ept breakpoint removes the performance cost associated
        with handling its ept violations while still allowing the user to read
        its breakpoint log.

    Parameters
        log_handle (decimal)
            The handle for the ept breakpoint to be disabled.

    Example
        Disable the ept breakpoint whose handle value is 133:

            deb 133

**ClearEptBp**

    Usage: ClearEptBp log_handle

    Short Name
        ceb

    Summary
        Uninstall the target ept breakpoint from all processors and unmap the
        corresponding breakpoint log.

    Parameters
        log_handle (decimal)
            The handle for the ept breakpoint to be cleared.

    Example
        Clear the ept breakpoint whose handle value is 6:

            ceb 6

**PrintEptBpLogHeader**

    Usage: PrintEptBpLogHeader log_handle

    Short Name
        peblh

    Summary
        Print the breakpoint log header for the specified ept breakpoint.

    Parameters
        log_handle (decimal)
            The handle for the target ept breakpoint.

    Example
        Print the breakpoint log header for the ept breakpoint whose handle
        value is 20:

            peblh 20

**PrintEptBpLogElements**

    Usage: PrintEptBpLogElements log_handle [start_index] l[count]

    Short Name
        peble

    Summary
        Print breakpoint log elements for the specified ept breakpoint.

    Parameters
        log_handle (decimal)
            The handle for the target ept breakpoint.

        start_index (decimal, optional)
            Specify the index of the element to begin printing at.

        count (decimal, 'l' or 'L' prefix, optional)
            Specify the number of elements to print.

            If no 'start_index' parameter is specified then the first 'count'
            elements of the log are printed.

            This parameter must be prefixed with an 'l' or 'L' character. This
            syntax is similar to the 'Address Range' syntax in WinDbg.

    Example
        Print the first element of the breakpoint log for the ept breakpoint
        whose handle value is 31:

            peble 31 1

        Print the first 101 elements of the breakpoint log for the ept
        breakpoint whose handle value is 90909:

            peble 90909 L101

        Print 222 elements starting at the 50th element of the breakpoint log
        for the ept breakpoint whose handle value is 3:

            peble 3 50 l222

### Hardware Breakpoints (Requires Hardware Breakpoint Manager module)

**QuerySystemDebugState**

    Short Name
        qsds

    Summary
        Query the hardware breakpoint manager's debug register state for all processors.

**SetHwBp**

    Usage
        SetHwBp index pid access|size address

    Short Name
        shb

    Summary
        Install a hardware breakpoint on all processors.

    Parameters
        index
            The debug address register index used for the hardware breakpoint. (0,1,2,3)

        pid
            The target process id. (decimal)

        access
            The hardware breakpoint type (WinDbg format):
                'e'     execute
                'r'     read
                'w'     write

        size
            The hardware breakpoint size (WinDbg format):
                '1'     byte
                '2'     word
                '4'     dword
                '8'     qword

        address
            The hardware breakpoint address. (hex, '0x' prefix optional)

    Example
        shb 0 1002 w4 77701650

**ClearHwBp**

    Usage
        ClearHwBp index

    Short Name
        chb

    Summary
        Clear a hardware breakpoint on all processors.

    Parameters
        index
            The debug address register index used for the hardware breakpoint. (0,1,2,3)

    Example
        chb 0

### Capture Execution Context (Requires Hardware Breakpoint Manager module)

**CaptureExecCtxRegister**

    Usage
        CaptureExecCtxRegister index pid access|size address register duration

    Short Name
        cecr

    Summary
        Capture unique register context at a target address.

    Parameters
        index
            The debug address register index used for the hardware breakpoint. (0,1,2,3)

        pid
            The target process id. (decimal)

        access
            The hardware breakpoint type (WinDbg format):
                'e'     execute
                'r'     read
                'w'     write

        size
            The hardware breakpoint size (WinDbg format):
                '1'     byte
                '2'     word
                '4'     dword
                '8'     qword

        address
            The hardware breakpoint address. (hex, '0x' prefix optional)

        register
            The target register:
                rip, rax, rcx, rdx, rdi, rsi, rbx, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15

        duration
            The amount of time in milliseconds in which the hardware breakpoint
            is installed to sample the target register.

    Example
        cecr 0 1002 w4 77701650 rbx 5000

**CaptureExecCtxMemory**

    Usage
        CaptureExecCtxMemory index pid access|size bp_address mem_type mem_expression duration

    Short Name
        cecm

    Summary
        Capture unique values of type mem_type at the memory address described
        by mem_expression.

        This command sets a hardware breakpoint specified by 'access', 'size',
        and 'bp_address' using the debug address register specified by 'index'.
        The breakpoint callback calculates the effective address by evaluating
        the memory expression (mem_expression) using the guest context. A value
        of type 'mem_type' is read from the effective address. Unique values
        are stored to the user data buffer.

    Parameters
        index
            The debug address register index used for the hardware breakpoint. (0,1,2,3)

        pid
            The target process id. (decimal)

        access
            The hardware breakpoint type (WinDbg format):
                'e'     execute
                'r'     read
                'w'     write

        size
            The hardware breakpoint size (WinDbg format):
                '1'     byte
                '2'     word
                '4'     dword
                '8'     qword

        address
            The hardware breakpoint address. (hex, '0x' prefix optional)

        mem_type
            The data type used to interpret the effective address:
                'b'     byte
                'w'     word
                'd'     dword
                'q'     qword
                'f'     float
                'o'     double

        mem_expression
            An absolute virtual address or a valid indirect address in assembly
            language format (without spaces). Indirect addresses have the form:

                base_register + index_register * scale_factor +- displacement

            Examples of valid indirect address expressions:
                0x140000
                140000
                rax
                rax+FF
                rax+rdi
                rax+rdi*8
                rax+rdi*8-20
                rdi*8+20

        duration
            The amount of time in milliseconds in which the hardware breakpoint
            is installed to sample the effective address.

    Example
        The target instruction:

            0x1400000   mov     rcx, [rcx+rax*8]    ; an array of floats

        The following command captures a float array element whenever the
        instruction at address 0x140000 is executed:

            cecm 0 123 e1 1400000 f rcx+rax*8 5000
