VivienneCL
==========

VivienneCL is a command line VivienneVMM client which exposes the hardware breakpoint control interface through commands.


Installation
------------

1. Enable test signing on the target machine.
2. Load the driver.
3. Execute **VivienneCL.exe**.


Commands
--------

**setbp**

    Usage
        setbp index pid access|size address

    Summary
        Install a hardware breakpoint on all processors.

    Args
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
        setbp 0 1002 w4 77701650

---

**clear**

    Usage
        clear index

    Summary
        Clear a hardware breakpoint on all processors.

    Args
        index
            The debug address register index used for the hardware breakpoint. (0,1,2,3)

    Example
        clear 0

---

**cecr**

    Usage
        cecr index pid access|size address register duration

    Summary
        Capture unique register context at a target address.

    Args
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

---

**cecm**

    Usage
        cecm index pid access|size bp_address mem_type mem_expression duration

    Summary
        Capture unique values of type mem_type at the memory address described
        by mem_expression.

        This command sets a hardware breakpoint specified by 'access', 'size',
        and 'bp_address' using the debug address register specified by 'index'.
        The breakpoint callback calculates the effective address by evaluating
        the memory expression (mem_expression) using the guest context. A value
        of type 'mem_type' is read from the effective address. Unique values
        are stored to the user data buffer.

    Args
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

---

**qdr**

    Summary
        Query the breakpoint manager's debug register state for all processors.

---

**pid**

    Usage
        pid process_name

    Summary
        Obtain a list of process ids whose names match the specified process name.

    Args
        process_name
            The target process name including file extension.

    Example
        pid calc.exe

---

**commands**

    Summary
        Display a list of supported commands.

---

**help**

    Usage
        help command_name

    Summary
        Display extended command information.

    Args
        command_name
            A command from the command list. NOTE Some commands do not have extended information.

    Example
        help cecm

---

**exit**

    Summary
        Terminate the VivienneCL session.


Notes
-----

* The debug configuration uses the multi-threaded debug runtime library to reduce library requirements in virtual machines.
