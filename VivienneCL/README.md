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
        index:     [0-3]        debug address register index
        pid:       #            an active process id (integer)
        access:    'e,r,w'      execution, read, write
        size:      '1,2,4,8'    byte, word, dword, qword
        address:   #            valid user mode address (hex)

    Example
        setbp 0 1002 w4 77701650

---

**clear**

    Usage
        clear index

    Summary
        Clear a hardware breakpoint on all processors.

    Args
        index:     [0-3]        debug address register index

    Example
        clear 0

---

**cecr**

    Usage
        cecr index pid access|size address register duration

    Summary
        Capture unique register context at a target address.

    Args
        index:     [0-3]           debug address register index
        pid:       #               an active process id (integer)
        access:    'e,r,w'         execution, read, write
        size:      '1,2,4,8'       byte, word, dword, qword
        address:   #               valid user mode address (hex)
        register:  'rip,rax,etc'   the target register
        duration:  #               capture duration in milliseconds

    Example
        cecr 0 1002 w4 77701650 rbx 5000

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
        process_name:  process name (including file extension)

    Example
        pid calc.exe

---

**help, commands**

    Summary
        Display a list of supported commands.

---

**exit**

    Summary
        Terminate the VivienneCL session.


Notes
-----

* The debug configuration uses the multi-threaded debug runtime library to reduce library requirements in virtual machines.
