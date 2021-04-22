#pragma once

#ifndef _HVM_IA32STRUCTURES_H_
#define _HVM_IA32STRUCTURES_H_

#include "Common.h"

EXTERN_C_BEGIN


#define MSR_APIC_BASE                       0x01B
#define MSR_IA32_FEATURE_CONTROL            0x03A

#define MSR_IA32_VMX_BASIC                  0x480
#define MSR_IA32_VMX_PINBASED_CTLS          0x481
#define MSR_IA32_VMX_PROCBASED_CTLS         0x482
#define MSR_IA32_VMX_EXIT_CTLS              0x483
#define MSR_IA32_VMX_ENTRY_CTLS             0x484
#define MSR_IA32_VMX_MISC                   0x485
#define MSR_IA32_VMX_CR0_FIXED0             0x486
#define MSR_IA32_VMX_CR0_FIXED1             0x487
#define MSR_IA32_VMX_CR4_FIXED0             0x488
#define MSR_IA32_VMX_CR4_FIXED1             0x489
#define MSR_IA32_VMX_VMCS_ENUM              0x48A
#define MSR_IA32_VMX_PROCBASED_CTLS2        0x48B
#define MSR_IA32_VMX_EPT_VPID_CAP           0x48C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS     0x48D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS    0x48E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS         0x48F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS        0x490
#define MSR_IA32_VMX_VMFUNC                 0x491

#define MSR_IA32_SYSENTER_CS                0x174
#define MSR_IA32_SYSENTER_ESP               0x175
#define MSR_IA32_SYSENTER_EIP               0x176
#define MSR_IA32_DEBUGCTL                   0x1D9

#define MSR_LSTAR                           0xC0000082

#define MSR_FS_BASE                         0xC0000100
#define MSR_GS_BASE                         0xC0000101
#define MSR_SHADOW_GS_BASE                  0xC0000102        // SwapGS GS shadow


/*
 * Intel CPU  MSR
 */
 /* MSRs & bits used for VMX enabling */

#define CPU_BASED_VIRTUAL_INTR_PENDING          0x00000004
#define CPU_BASED_USE_TSC_OFFSETING             0x00000008
#define CPU_BASED_HLT_EXITING                   0x00000080
#define CPU_BASED_INVLPG_EXITING                0x00000200
#define CPU_BASED_MWAIT_EXITING                 0x00000400
#define CPU_BASED_RDPMC_EXITING                 0x00000800
#define CPU_BASED_RDTSC_EXITING                 0x00001000
#define CPU_BASED_CR3_LOAD_EXITING		        0x00008000
#define CPU_BASED_CR3_STORE_EXITING		       0x00010000
#define CPU_BASED_CR8_LOAD_EXITING              0x00080000
#define CPU_BASED_CR8_STORE_EXITING             0x00100000
#define CPU_BASED_TPR_SHADOW                    0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING		     0x00400000
#define CPU_BASED_MOV_DR_EXITING                0x00800000
#define CPU_BASED_UNCOND_IO_EXITING             0x01000000
#define CPU_BASED_USE_IO_BITMAPS                0x02000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP           0x10000000
#define CPU_BASED_MTF_TRAP_EXITING              0x08000000
#define CPU_BASED_USE_MSR_BITMAPS               0x10000000
#define CPU_BASED_MONITOR_EXITING               0x20000000
#define CPU_BASED_PAUSE_EXITING                 0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS   0x80000000

#define PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR	0x00000016
#define VM_EXIT_SAVE_DEBUG_CONTROLS      0x00000004
#define VM_EXIT_IA32E_MODE              0x00000200
#define VM_EXIT_ACK_INTR_ON_EXIT        0x00008000
#define VM_EXIT_SAVE_IA32_PAT			0x00040000
#define VM_EXIT_LOAD_IA32_PAT			0x00080000
#define VM_EXIT_SAVE_IA32_EFER          0x00100000
#define VM_EXIT_LOAD_IA32_EFER          0x00200000
#define VM_EXIT_SAVE_VMX_PREEMPTION_TIMER       0x00400000
#define VM_EXIT_CLEAR_BNDCFGS                   0x00800000

#define VM_ENTRY_LOAD_DEBUG_CONTROLS            0x00000004
#define VM_ENTRY_IA32E_MODE             0x00000200
#define VM_ENTRY_SMM                    0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR     0x00000800
#define VM_ENTRY_LOAD_IA32_PAT			0x00004000
#define VM_ENTRY_LOAD_IA32_EFER         0x00008000
#define VM_ENTRY_LOAD_BNDCFGS           0x00010000

#define MSR_IA32_VMX_BASIC   		0x480
#define MSR_IA32_FEATURE_CONTROL 		0x03a
#define MSR_IA32_VMX_PINBASED_CTLS		0x481
#define MSR_IA32_VMX_PROCBASED_CTLS		0x482
#define MSR_IA32_VMX_EXIT_CTLS		0x483
#define MSR_IA32_VMX_ENTRY_CTLS		0x484

#define MSR_IA32_SYSENTER_CS		0x174
#define MSR_IA32_SYSENTER_ESP		0x175
#define MSR_IA32_SYSENTER_EIP		0x176
#define MSR_IA32_DEBUGCTL			0x1d9


#define MSR_EFER 0xc0000080           /* extended feature register */
#define MSR_STAR 0xc0000081           /* legacy mode SYSCALL target */
#define MSR_LSTAR 0xc0000082          /* long mode SYSCALL target */
#define MSR_CSTAR 0xc0000083          /* compatibility mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084   /* EFLAGS mask for syscall */
#define MSR_FS_BASE 0xc0000100                /* 64bit FS base */
#define MSR_GS_BASE 0xc0000101                /* 64bit GS base */
#define MSR_SHADOW_GS_BASE  0xc0000102        /* SwapGS GS shadow */

	enum VM_EXIT_REASON
{
	EXIT_REASON_EXCEPTION_NMI = 0,    // Exception or non-maskable interrupt (NMI).
	EXIT_REASON_EXTERNAL_INTERRUPT = 1,    // External interrupt.
	EXIT_REASON_TRIPLE_FAULT = 2,    // Triple fault.
	EXIT_REASON_INIT = 3,    // INIT signal.
	EXIT_REASON_SIPI = 4,    // Start-up IPI (SIPI).
	EXIT_REASON_IO_SMI = 5,    // I/O system-management interrupt (SMI).
	EXIT_REASON_OTHER_SMI = 6,    // Other SMI.
	EXIT_REASON_PENDING_INTERRUPT = 7,    // Interrupt window exiting.
	EXIT_REASON_NMI_WINDOW = 8,    // NMI window exiting.
	EXIT_REASON_TASK_SWITCH = 9,    // Task switch.
	EXIT_REASON_CPUID = 10,   // Guest software attempted to execute CPUID.
	EXIT_REASON_GETSEC = 11,   // Guest software attempted to execute GETSEC.
	EXIT_REASON_HLT = 12,   // Guest software attempted to execute HLT.
	EXIT_REASON_INVD = 13,   // Guest software attempted to execute INVD.
	EXIT_REASON_INVLPG = 14,   // Guest software attempted to execute INVLPG.
	EXIT_REASON_RDPMC = 15,   // Guest software attempted to execute RDPMC.
	EXIT_REASON_RDTSC = 16,   // Guest software attempted to execute RDTSC.
	EXIT_REASON_RSM = 17,   // Guest software attempted to execute RSM in SMM.
	EXIT_REASON_VMCALL = 18,   // Guest software executed VMCALL.
	EXIT_REASON_VMCLEAR = 19,   // Guest software executed VMCLEAR.
	EXIT_REASON_VMLAUNCH = 20,   // Guest software executed VMLAUNCH.
	EXIT_REASON_VMPTRLD = 21,   // Guest software executed VMPTRLD.
	EXIT_REASON_VMPTRST = 22,   // Guest software executed VMPTRST.
	EXIT_REASON_VMREAD = 23,   // Guest software executed VMREAD.
	EXIT_REASON_VMRESUME = 24,   // Guest software executed VMRESUME.
	EXIT_REASON_VMWRITE = 25,   // Guest software executed VMWRITE.
	EXIT_REASON_VMXOFF = 26,   // Guest software executed VMXOFF.
	EXIT_REASON_VMXON = 27,   // Guest software executed VMXON.
	EXIT_REASON_CR_ACCESS = 28,   // Control-register accesses.
	EXIT_REASON_DR_ACCESS = 29,   // Debug-register accesses.
	EXIT_REASON_IO_INSTRUCTION = 30,   // I/O instruction.
	EXIT_REASON_MSR_READ = 31,   // RDMSR. Guest software attempted to execute RDMSR.
	EXIT_REASON_MSR_WRITE = 32,   // WRMSR. Guest software attempted to execute WRMSR.
	EXIT_REASON_INVALID_GUEST_STATE = 33,   // VM-entry failure due to invalid guest state.
	EXIT_REASON_MSR_LOADING = 34,   // VM-entry failure due to MSR loading.
	EXIT_REASON_RESERVED_35 = 35,   // Reserved
	EXIT_REASON_MWAIT_INSTRUCTION = 36,   // Guest software executed MWAIT.
	EXIT_REASOM_MTF = 37,   // VM-exit due to monitor trap flag.
	EXIT_REASON_RESERVED_38 = 38,   // Reserved
	EXIT_REASON_MONITOR_INSTRUCTION = 39,   // Guest software attempted to execute MONITOR.
	EXIT_REASON_PAUSE_INSTRUCTION = 40,   // Guest software attempted to execute PAUSE.
	EXIT_REASON_MACHINE_CHECK = 41,   // VM-entry failure due to machine-check.
	EXIT_REASON_RESERVED_42 = 42,   // Reserved
	EXIT_REASON_TPR_BELOW_THRESHOLD = 43,   // TPR below threshold. Guest software executed MOV to CR8.
	EXIT_REASON_APIC_ACCESS = 44,   // APIC access. Guest software attempted to access memory at a physical address on the APIC-access page.
	EXIT_REASON_VIRTUALIZED_EIO = 45,   // EOI virtualization was performed for a virtual interrupt whose vector indexed a bit set in the EOIexit bitmap
	EXIT_REASON_XDTR_ACCESS = 46,   // Guest software attempted to execute LGDT, LIDT, SGDT, or SIDT.
	EXIT_REASON_TR_ACCESS = 47,   // Guest software attempted to execute LLDT, LTR, SLDT, or STR.
	EXIT_REASON_EPT_VIOLATION = 48,   // An attempt to access memory with a guest-physical address was disallowed by the configuration of the EPT paging structures.
	EXIT_REASON_EPT_MISCONFIG = 49,   // An attempt to access memory with a guest-physical address encountered a misconfigured EPT paging-structure entry.
	EXIT_REASON_INVEPT = 50,   // Guest software attempted to execute INVEPT.
	EXIT_REASON_RDTSCP = 51,   // Guest software attempted to execute RDTSCP.
	EXIT_REASON_PREEMPT_TIMER = 52,   // VMX-preemption timer expired. The preemption timer counted down to zero.
	EXIT_REASON_INVVPID = 53,   // Guest software attempted to execute INVVPID.
	EXIT_REASON_WBINVD = 54,   // Guest software attempted to execute WBINVD
	EXIT_REASON_XSETBV = 55,   // Guest software attempted to execute XSETBV.
	EXIT_REASON_APIC_WRITE = 56,   // Guest completed write to virtual-APIC.
	EXIT_REASON_RDRAND = 57,   // Guest software attempted to execute RDRAND.
	EXIT_REASON_INVPCID = 58,   // Guest software attempted to execute INVPCID.
	EXIT_REASON_VMFUNC = 59,   // Guest software attempted to execute VMFUNC.
	EXIT_REASON_RESERVED_60 = 60,   // Reserved
	EXIT_REASON_RDSEED = 61,   // Guest software attempted to executed RDSEED and exiting was enabled.
	EXIT_REASON_RESERVED_62 = 62,   // Reserved
	EXIT_REASON_XSAVES = 63,   // Guest software attempted to executed XSAVES and exiting was enabled.
	EXIT_REASON_XRSTORS = 64,   // Guest software attempted to executed XRSTORS and exiting was enabled.

	VMX_MAX_GUEST_VMEXIT = 65
};


#define KGDT64_NULL (0*16) //NULL descriptor
#define KGDT64_R0_CODE (1*16) //Kernel mode 64-bit code
#define KGDT64_R0_DATA (1*16)+8 //Kernel mode 64-bit data (stack)
#define KGDT64_R3_CMCODE (2*16) //User mode 32-bit code
#define KGDT64_R3_DATA (2*16)+8 //User mode 32-bit data
#define KGDT64_R3_CODE (3*16) //User mode 64-bit code
#define KGDT64_SYS_TSS (4*16) //Kernel mode system task state
#define KGDT64_R3_CMTEB (5*16) //User mdoe 32-bit TEB
#define KGDT64_R0_CMCODE (6*16) //Kernel mode 32-bit code



typedef struct _CPUID
{
	int rax;
	int rbx;
	int rcx;
	int rdx;
} CPUID, * PCPUID;


union CPUID_ECX
{
	ULONG32 all;
	struct
	{
		ULONG32 sse3 : 1;       //!< [0] Streaming SIMD Extensions 3 (SSE3)
		ULONG32 pclmulqdq : 1;  //!< [1] PCLMULQDQ
		ULONG32 dtes64 : 1;     //!< [2] 64-bit DS Area
		ULONG32 monitor : 1;    //!< [3] MONITOR/WAIT
		ULONG32 ds_cpl : 1;     //!< [4] CPL qualified Debug Store
		ULONG32 vmx : 1;        //!< [5] Virtual Machine Technology
		ULONG32 smx : 1;        //!< [6] Safer Mode Extensions
		ULONG32 est : 1;        //!< [7] Enhanced Intel Speedstep Technology
		ULONG32 tm2 : 1;        //!< [8] Thermal monitor 2
		ULONG32 ssse3 : 1;      //!< [9] Supplemental Streaming SIMD Extensions 3
		ULONG32 cid : 1;        //!< [10] L1 context ID
		ULONG32 sdbg : 1;       //!< [11] IA32_DEBUG_INTERFACE MSR
		ULONG32 fma : 1;        //!< [12] FMA extensions using YMM state
		ULONG32 cx16 : 1;       //!< [13] CMPXCHG16B
		ULONG32 xtpr : 1;       //!< [14] xTPR Update Control
		ULONG32 pdcm : 1;       //!< [15] Performance/Debug capability MSR
		ULONG32 reserved : 1;   //!< [16] Reserved
		ULONG32 pcid : 1;       //!< [17] Process-context identifiers
		ULONG32 dca : 1;        //!< [18] prefetch from a memory mapped device
		ULONG32 sse4_1 : 1;     //!< [19] SSE4.1
		ULONG32 sse4_2 : 1;     //!< [20] SSE4.2
		ULONG32 x2_apic : 1;    //!< [21] x2APIC feature
		ULONG32 movbe : 1;      //!< [22] MOVBE instruction
		ULONG32 popcnt : 1;     //!< [23] POPCNT instruction
		ULONG32 reserved3 : 1;  //!< [24] one-shot operation using a TSC deadline
		ULONG32 aes : 1;        //!< [25] AESNI instruction
		ULONG32 xsave : 1;      //!< [26] XSAVE/XRSTOR feature
		ULONG32 osxsave : 1;    //!< [27] enable XSETBV/XGETBV instructions
		ULONG32 avx : 1;        //!< [28] AVX instruction extensions
		ULONG32 f16c : 1;       //!< [29] 16-bit floating-point conversion
		ULONG32 rdrand : 1;     //!< [30] RDRAND instruction
		ULONG32 not_used : 1;   //!< [31] Always 0 (a.k.a. HypervisorPresent)
	} fields;
};

union CR0
{
	ULONG_PTR all;
	struct
	{
		unsigned pe : 1;          //!< [0] Protected Mode Enabled
		unsigned mp : 1;          //!< [1] Monitor Coprocessor FLAG
		unsigned em : 1;          //!< [2] Emulate FLAG
		unsigned ts : 1;          //!< [3] Task Switched FLAG
		unsigned et : 1;          //!< [4] Extension Type FLAG
		unsigned ne : 1;          //!< [5] Numeric Error
		unsigned reserved1 : 10;  //!< [6:15]
		unsigned wp : 1;          //!< [16] Write Protect
		unsigned reserved2 : 1;   //!< [17]
		unsigned am : 1;          //!< [18] Alignment Mask
		unsigned reserved3 : 10;  //!< [19:28]
		unsigned nw : 1;          //!< [29] Not Write-Through
		unsigned cd : 1;          //!< [30] Cache Disable
		unsigned pg : 1;          //!< [31] Paging Enabled
	} fields;
};

union CR4
{
	ULONG_PTR all;
	struct
	{
		unsigned vme : 1;         //!< [0] Virtual Mode Extensions
		unsigned pvi : 1;         //!< [1] Protected-Mode Virtual Interrupts
		unsigned tsd : 1;         //!< [2] Time Stamp Disable
		unsigned de : 1;          //!< [3] Debugging Extensions
		unsigned pse : 1;         //!< [4] Page Size Extensions
		unsigned pae : 1;         //!< [5] Physical Address Extension
		unsigned mce : 1;         //!< [6] Machine-Check Enable
		unsigned pge : 1;         //!< [7] Page Global Enable
		unsigned pce : 1;         //!< [8] Performance-Monitoring Counter Enable
		unsigned osfxsr : 1;      //!< [9] OS Support for FXSAVE/FXRSTOR
		unsigned osxmmexcpt : 1;  //!< [10] OS Support for Unmasked SIMD Exceptions
		unsigned reserved1 : 2;   //!< [11:12]
		unsigned vmxe : 1;        //!< [13] Virtual Machine Extensions Enabled
		unsigned smxe : 1;        //!< [14] SMX-Enable Bit
		unsigned reserved2 : 2;   //!< [15:16]
		unsigned pcide : 1;       //!< [17] PCID Enable
		unsigned osxsave : 1;  //!< [18] XSAVE and Processor Extended States-Enable
		unsigned reserved3 : 1;  //!< [19]
		unsigned smep : 1;  //!< [20] Supervisor Mode Execution Protection Enable
		unsigned smap : 1;  //!< [21] Supervisor Mode Access Protection Enable
	} fields;
};

union IA32_FEATURE_CONTROL_MSR
{
	ULONG64 all;
	struct
	{
		unsigned lock : 1;                  //!< [0]
		unsigned enable_smx : 1;            //!< [1]
		unsigned enable_vmxon : 1;          //!< [2]
		unsigned reserved1 : 5;             //!< [3:7]
		unsigned enable_local_senter : 7;   //!< [8:14]
		unsigned enable_global_senter : 1;  //!< [15]
		unsigned reserved2 : 16;            //!<
		unsigned reserved3 : 32;            //!< [16:63]
	} fields;
};

union IA32_VMX_BASIC_MSR
{
	ULONG64 all;
	struct
	{
		unsigned revision_identifier : 31;    //!< [0:30]
		unsigned reserved1 : 1;               //!< [31]
		unsigned region_size : 12;            //!< [32:43]
		unsigned region_clear : 1;            //!< [44]
		unsigned reserved2 : 3;               //!< [45:47]
		unsigned supported_ia64 : 1;          //!< [48]
		unsigned supported_dual_moniter : 1;  //!< [49]
		unsigned memory_type : 4;             //!< [50:53]
		unsigned vm_exit_report : 1;          //!< [54]
		unsigned vmx_capability_hint : 1;     //!< [55]
		unsigned reserved3 : 8;               //!< [56:63]
	} fields;
};

/// See: VPID AND EPT CAPABILITIES
union IA32_VMX_EPT_VPID_CAP_MSR
{
	ULONG64 all;
	struct {
		unsigned support_execute_only_pages : 1;                        //!< [0]
		unsigned reserved1 : 5;                                         //!< [1:5]
		unsigned support_page_walk_length4 : 1;                         //!< [6]
		unsigned reserved2 : 1;                                         //!< [7]
		unsigned support_uncacheble_memory_type : 1;                    //!< [8]
		unsigned reserved3 : 5;                                         //!< [9:13]
		unsigned support_write_back_memory_type : 1;                    //!< [14]
		unsigned reserved4 : 1;                                         //!< [15]
		unsigned support_pde_2mb_pages : 1;                             //!< [16]
		unsigned support_pdpte_1_gb_pages : 1;                          //!< [17]
		unsigned reserved5 : 2;                                         //!< [18:19]
		unsigned support_invept : 1;                                    //!< [20]
		unsigned support_accessed_and_dirty_flag : 1;                   //!< [21]
		unsigned reserved6 : 3;                                         //!< [22:24]
		unsigned support_single_context_invept : 1;                     //!< [25]
		unsigned support_all_context_invept : 1;                        //!< [26]
		unsigned reserved7 : 5;                                         //!< [27:31]
		unsigned support_invvpid : 1;                                   //!< [32]
		unsigned reserved8 : 7;                                         //!< [33:39]
		unsigned support_individual_address_invvpid : 1;                //!< [40]
		unsigned support_single_context_invvpid : 1;                    //!< [41]
		unsigned support_all_context_invvpid : 1;                       //!< [42]
		unsigned support_single_context_retaining_globals_invvpid : 1;  //!< [43]
		unsigned reserved9 : 20;                                        //!< [44:63]
	} fields;
};

union RFLAGS
{
	ULONG64 all;
	struct
	{
		unsigned CF : 1;
		unsigned Unknown_1 : 1;	//Always 1
		unsigned PF : 1;
		unsigned Unknown_2 : 1;	//Always 0
		unsigned AF : 1;
		unsigned Unknown_3 : 1;	//Always 0
		unsigned ZF : 1;
		unsigned SF : 1;
		unsigned TF : 1;
		unsigned IF : 1;
		unsigned DF : 1;
		unsigned OF : 1;
		unsigned TOPL : 2;
		unsigned NT : 1;
		unsigned Unknown_4 : 1;
		unsigned RF : 1;
		unsigned VM : 1;
		unsigned AC : 1;
		unsigned VIF : 1;
		unsigned VIP : 1;
		unsigned ID : 1;
		unsigned Reserved : 10;	//Always 0
		unsigned Reserved_64 : 32;	//Always 0
	}fields;
};

/// See: Memory Types That Can Be Encoded With PAT Memory Types Recommended for
/// VMCS and Related Data Structures
enum  memory_type : unsigned __int8
{
	kUncacheable = 0,
	kWriteCombining = 1,
	kWriteThrough = 4,
	kWriteProtected = 5,
	kWriteBack = 6,
	kUncached = 7,
};

typedef union _VMX_PIN_BASED_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 ExternalInterruptExiting : 1;    // [0]
		ULONG32 Reserved1 : 2;                   // [1-2]
		ULONG32 NMIExiting : 1;                  // [3]
		ULONG32 Reserved2 : 1;                   // [4]
		ULONG32 VirtualNMIs : 1;                 // [5]
		ULONG32 ActivateVMXPreemptionTimer : 1;  // [6]
		ULONG32 ProcessPostedInterrupts : 1;     // [7]
	} Fields;
} VMX_PIN_BASED_CONTROLS, * PVMX_PIN_BASED_CONTROLS;

typedef union _VMX_VM_ENTER_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 Reserved1 : 2;                       // [0-1]
		ULONG32 LoadDebugControls : 1;               // [2]
		ULONG32 Reserved2 : 6;                       // [3-8]
		ULONG32 IA32eModeGuest : 1;                  // [9]
		ULONG32 EntryToSMM : 1;                      // [10]
		ULONG32 DeactivateDualMonitorTreatment : 1;  // [11]
		ULONG32 Reserved3 : 1;                       // [12]
		ULONG32 LoadIA32_PERF_GLOBAL_CTRL : 1;       // [13]
		ULONG32 LoadIA32_PAT : 1;                    // [14]
		ULONG32 LoadIA32_EFER : 1;                   // [15]
	} Fields;
} VMX_VM_ENTER_CONTROLS, * PVMX_VM_ENTER_CONTROLS;

typedef union _VMX_VM_EXIT_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 Reserved1 : 2;                    // [0-1]
		ULONG32 SaveDebugControls : 1;            // [2]
		ULONG32 Reserved2 : 6;                    // [3-8]
		ULONG32 HostAddressSpaceSize : 1;         // [9]
		ULONG32 Reserved3 : 2;                    // [10-11]
		ULONG32 LoadIA32_PERF_GLOBAL_CTRL : 1;    // [12]
		ULONG32 Reserved4 : 2;                    // [13-14]
		ULONG32 AcknowledgeInterruptOnExit : 1;   // [15]
		ULONG32 Reserved5 : 2;                    // [16-17]
		ULONG32 SaveIA32_PAT : 1;                 // [18]
		ULONG32 LoadIA32_PAT : 1;                 // [19]
		ULONG32 SaveIA32_EFER : 1;                // [20]
		ULONG32 LoadIA32_EFER : 1;                // [21]
		ULONG32 SaveVMXPreemptionTimerValue : 1;  // [22]
	} Fields;
} VMX_VM_EXIT_CONTROLS, * PVMX_VM_EXIT_CONTROLS;

typedef union _VMX_CPU_BASED_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 Reserved1 : 2;                 // [0-1]
		ULONG32 InterruptWindowExiting : 1;    // [2]
		ULONG32 UseTSCOffseting : 1;           // [3]
		ULONG32 Reserved2 : 3;                 // [4-6]
		ULONG32 HLTExiting : 1;                // [7]
		ULONG32 Reserved3 : 1;                 // [8]
		ULONG32 INVLPGExiting : 1;             // [9]
		ULONG32 MWAITExiting : 1;              // [10]
		ULONG32 RDPMCExiting : 1;              // [11]
		ULONG32 RDTSCExiting : 1;              // [12]
		ULONG32 Reserved4 : 2;                 // [13-14]
		ULONG32 CR3LoadExiting : 1;            // [15]
		ULONG32 CR3StoreExiting : 1;           // [16]
		ULONG32 Reserved5 : 2;                 // [17-18]
		ULONG32 CR8LoadExiting : 1;            // [19]
		ULONG32 CR8StoreExiting : 1;           // [20]
		ULONG32 UseTPRShadowExiting : 1;       // [21]
		ULONG32 NMIWindowExiting : 1;          // [22]
		ULONG32 MovDRExiting : 1;              // [23]
		ULONG32 UnconditionalIOExiting : 1;    // [24]
		ULONG32 UseIOBitmaps : 1;              // [25]
		ULONG32 Reserved6 : 1;                 // [26]
		ULONG32 MonitorTrapFlag : 1;           // [27]
		ULONG32 UseMSRBitmaps : 1;             // [28]
		ULONG32 MONITORExiting : 1;            // [29]
		ULONG32 PAUSEExiting : 1;              // [30]
		ULONG32 ActivateSecondaryControl : 1;  // [31]
	} Fields;
} VMX_CPU_BASED_CONTROLS, * PVMX_CPU_BASED_CONTROLS;

typedef union _VMX_SECONDARY_CPU_BASED_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 VirtualizeAPICAccesses : 1;      // [0]
		ULONG32 EnableEPT : 1;                   // [1]
		ULONG32 DescriptorTableExiting : 1;      // [2]
		ULONG32 EnableRDTSCP : 1;                // [3]
		ULONG32 VirtualizeX2APICMode : 1;        // [4]
		ULONG32 EnableVPID : 1;                  // [5]
		ULONG32 WBINVDExiting : 1;               // [6]
		ULONG32 UnrestrictedGuest : 1;           // [7]
		ULONG32 APICRegisterVirtualization : 1;  // [8]
		ULONG32 VirtualInterruptDelivery : 1;    // [9]
		ULONG32 PAUSELoopExiting : 1;            // [10]
		ULONG32 RDRANDExiting : 1;               // [11]
		ULONG32 EnableINVPCID : 1;               // [12]
		ULONG32 EnableVMFunctions : 1;           // [13]
		ULONG32 VMCSShadowing : 1;               // [14]
		ULONG32 Reserved1 : 1;                   // [15]
		ULONG32 RDSEEDExiting : 1;               // [16]
		ULONG32 Reserved2 : 1;                   // [17]
		ULONG32 EPTViolation : 1;                // [18]
		ULONG32 Reserved3 : 1;                   // [19]
		ULONG32 EnableXSAVESXSTORS : 1;          // [20]
	} Fields;
} VMX_SECONDARY_CPU_BASED_CONTROLS, * PVMX_SECONDARY_CPU_BASED_CONTROLS;

#pragma pack(1)
// 默认8字节对齐,会导致lgdt和lidt指令无法成功执行

struct IDTR
{
	USHORT limit;
	ULONG_PTR base;
};

struct GDTR
{
	USHORT limit;
	ULONG_PTR base;
};
#pragma pack()

union VmExitInformation
{
	unsigned int all;
	struct
	{
		unsigned short reason;                     //!< [0:15] VmxExitReason
		unsigned short reserved1 : 12;             //!< [16:30]
		unsigned short pending_mtf_vm_exit : 1;    //!< [28]
		unsigned short vm_exit_from_vmx_root : 1;  //!< [29]
		unsigned short reserved2 : 1;              //!< [30]
		unsigned short vm_entry_failure : 1;       //!< [31]
	} fields;
};

union VmxRegmentDescriptorAccessRight
{
	unsigned int all;
	struct
	{
		unsigned type : 4;        //!< [0:3]
		unsigned system : 1;      //!< [4]
		unsigned dpl : 2;         //!< [5:6]
		unsigned present : 1;     //!< [7]
		unsigned reserved1 : 4;   //!< [8:11]
		unsigned avl : 1;         //!< [12]
		unsigned l : 1;           //!< [13] Reserved (except for CS) 64-bit mode
		unsigned db : 1;          //!< [14]
		unsigned gran : 1;        //!< [15]
		unsigned unusable : 1;    //!< [16] Segment unusable
		unsigned reserved2 : 15;  //!< [17:31]
	} fields;
};


struct Registers64
{
	RFLAGS rflags;
	ULONG_PTR r15;
	ULONG_PTR r14;
	ULONG_PTR r13;
	ULONG_PTR r12;
	ULONG_PTR r11;
	ULONG_PTR r10;
	ULONG_PTR r9;
	ULONG_PTR r8;
	ULONG_PTR rdi;
	ULONG_PTR rsi;
	ULONG_PTR rbp;
	ULONG_PTR rsp;
	ULONG_PTR rbx;
	ULONG_PTR rdx;
	ULONG_PTR rcx;
	ULONG_PTR rax;
};

struct VmxoffContext
{
	ULONG_PTR rflags;
	ULONG_PTR rsp;
	ULONG_PTR rip;
};

enum AccessType
{
	MOV_TO_CR = 0,
	MOV_FROM_CR = 1,
	CLTS,
	LMSW
};

union ExitQualification
{
	ULONG_PTR all;

	// Task Switch 
	// See:Table  27-2
	struct
	{

	}TaskSwitch;

	// Control-Registers Accesses
	// See:Table 27-3
	struct
	{
		ULONG_PTR registerNumber : 4;   //!< [0:3]
		AccessType accessType : 2;        //!< [4:5]
		ULONG_PTR lmswOperandType : 1;  //!< [6]
		ULONG_PTR reserved1 : 1;          //!< [7]
		ULONG_PTR generalRegister : 4;        //!< [8:11]
		ULONG_PTR reserved2 : 4;          //!< [12:15]
		ULONG_PTR lmswSourceData : 16;  //!< [16:31]
		ULONG_PTR reserved3 : 32;         //!< [32:63]
	} crAccess;

	// Mov Debug-Regsters
	// See:Table 27-4
	struct
	{
		ULONG_PTR registerNumber : 3;  //!< [0:2] 
		ULONG_PTR reserved1 : 1;        //!< [3]
		ULONG_PTR direction : 1;        //!< [4] (0=mov to dr,1=mov from dr)
		ULONG_PTR reserved2 : 3;        //!< [5:7]
		ULONG_PTR generalRegister : 4;      //!< [8:11]
		ULONG_PTR reserved3 : 20;       //!<
		ULONG_PTR reserved4 : 32;       //!< [12:63]
	}  drAccess;

	// I/O Instructions
	// See:Table 27-5
	struct
	{
		ULONG_PTR accessSize : 3;      //!< [0:2] (0=1byte,1=2byte,2=4byte)
		ULONG_PTR direction : 1;           //!< [3] (0=out,1=in)
		ULONG_PTR stringInstruction : 1;  //!< [4] (0=not string,1=string)
		ULONG_PTR repPrefixed : 1;        //!< [5] (0=not rep,1=rep)
		ULONG_PTR operandEncoding : 1;    //!< [6] (0=dx,1=immediate)
		ULONG_PTR reserved1 : 9;           //!< [7:15] 
		ULONG_PTR portNumber : 16;        //!< [16:31]
	} ioInst;

	// APIC-Access
	// See:Table 27-6
	struct
	{

	}apicAccess;

	// EPT Violations
	// See:Table 27-7
	struct
	{
		ULONG64 readAccess : 1;                   //!< [0]
		ULONG64 writeAccess : 1;                  //!< [1]
		ULONG64 executeAccess : 1;                //!< [2]
		ULONG64 eptReadable : 1;                  //!< [3]
		ULONG64 eptWriteable : 1;                 //!< [4]
		ULONG64 eptExecutable : 1;                //!< [5]
		ULONG64 reserved1 : 1;					 //!< [6]
		ULONG64 validGuestLinearAddress : 1;    //!< [7]
		ULONG64 causedByTranslation : 1;         //!< [8]
		ULONG64 reserved2 : 3;					//!< [9:11]
		ULONG64 nmiUnblocking : 1;                //!< [12]
		ULONG64 reserved3 : 51;					//!< [13:63]
	} eptViolation;
};

EXTERN_C_END
#endif // !_HVM_IA32STRUCTURES_H_
