Tests
=====

VivienneVMM test cases.


Notes
-----

* Some test cases require debugger configuration if the test case is executed while a debugger attached. These cases contain WinDbg-specific details in the function comments.
* Optimizations are disabled in Release builds to prevent optimized code from violating test assumptions.
* The debug configuration uses the multi-threaded debug runtime library to reduce library requirements in virtual machines.
