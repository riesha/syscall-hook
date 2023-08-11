use std::{
    env, mem,
    ptr::{null, null_mut},
};

use libloading::Library;
use ntapi::{
    ntexapi::NtQuerySystemInformation,
    ntmmapi::{MemoryBasicInformation, NtQueryVirtualMemory},
    ntpsapi::NtSetInformationProcess,
};
use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::ULONG,
        ntdef::PVOID,
        ntstatus::{STATUS_ACCESS_DENIED, STATUS_SUCCESS},
    },
    um::{
        dbghelp::{SymSetOptions, SYMOPT_UNDNAME},
        libloaderapi::GetModuleHandleA,
        processthreadsapi::GetCurrentProcess,
        winnt::{MEMORY_BASIC_INFORMATION, PMEMORY_BASIC_INFORMATION},
    },
};

#[repr(C)]
struct ProcessInstrumentationCallbackInformation
{
    pub version:  ULONG,
    pub reserved: ULONG,
    pub callback: PVOID,
}
extern "C" {
    fn medium();
}

static mut FLAG: bool = false;

#[link_name = "hook"]
#[no_mangle]
unsafe extern "C" fn hook(r10: usize, rax: usize) -> usize { return 0x1337 as _; }
fn main()
{
    env::set_var("RUST_BACKTRACE", "1");
    unsafe {
        let mut mbi: PMEMORY_BASIC_INFORMATION = mem::zeroed();
        let status = NtQueryVirtualMemory(
            GetCurrentProcess(),
            GetModuleHandleA(null_mut()) as _,
            MemoryBasicInformation,
            mbi as _,
            mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            null_mut(),
        );
        println!(
            "Original NtQueryVirtualMemory... NTSTATUS -> {:#x?}",
            status
        );

        let mut callback = ProcessInstrumentationCallbackInformation {
            version:  0,
            reserved: 0,
            callback: medium as _,
        };
        let callback_ptr = &mut callback as *mut ProcessInstrumentationCallbackInformation;
        let status = NtSetInformationProcess(
            GetCurrentProcess(),
            0x28 as _,
            callback_ptr as _,
            mem::size_of::<ProcessInstrumentationCallbackInformation>() as _,
        );
        println!(
            "Calling NtSetInformationProcess... (CALLBACK_ADD), NTSTATUS -> {:#x?}",
            status
        );

        let status = NtQueryVirtualMemory(
            GetCurrentProcess(),
            GetModuleHandleA(null_mut()) as _,
            MemoryBasicInformation,
            mbi as _,
            mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            null_mut(),
        );
        println!("Tried NtQueryVirtualMemory... NTSTATUS -> {:#x?}", status);
        //NtQuerySystemInformation(0, null_mut(), 0, null_mut());
        callback.callback = null_mut();
        let status = NtSetInformationProcess(
            GetCurrentProcess(),
            0x28 as _,
            callback_ptr as _,
            mem::size_of::<ProcessInstrumentationCallbackInformation>() as _,
        );
        println!(
            "Calling NtSetInformationProcess... (CALLBACK_REMOVE), NTSTATUS -> {:#x?}",
            status
        );
        let status = NtQueryVirtualMemory(
            GetCurrentProcess(),
            GetModuleHandleA(null_mut()) as _,
            MemoryBasicInformation,
            mbi as _,
            mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            null_mut(),
        );
        println!(
            "Calling NtQueryVirtualMemory again... NTSTATUS -> {:#x?}",
            status
        );
    }
}
