#include "system_util.h"

#include <intrin.h>


//
// VMware's recommended strategy for determining if an application is executing
//  inside a VMware hypervisor.
//
BOOL
SyuIsVMwareHypervisorPresent()
{
    int cpu_info[4] = {};
    char hyper_vendor_id[13] = {};
    BOOL status = FALSE;

    //
    // Check if a hypervisor is present.
    //
    __cpuid(cpu_info, 1);

    if (cpu_info[2] & (1 << 31))
    {
        //
        // A hypervisor is running on the machine. Query the vendor id.
        //
        __cpuid(cpu_info, 0x40000000);

        memcpy(hyper_vendor_id + 0, &cpu_info[1], 4);
        memcpy(hyper_vendor_id + 4, &cpu_info[2], 4);
        memcpy(hyper_vendor_id + 8, &cpu_info[3], 4);
        hyper_vendor_id[12] = '\0';

        if (!strcmp(hyper_vendor_id, "VMwareVMware"))
        {
            status = TRUE;
        }
    }

    return status;
}
