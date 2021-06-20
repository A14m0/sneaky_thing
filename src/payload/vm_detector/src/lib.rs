#![feature(asm)]
use std::str::from_utf8;
use std::env::consts::OS;

// define static strings here
static AMD_BOCHS: &str = "AMD Athlon(tm) processor";
static INTEL_BOCHS: &str = "              Intel(R) Pentium(R) 4 CPU        ";
static QEMU: &str = "QEMU Virtual CPU";


// Our general-purpose detection structure
pub struct CheckVM{
}

impl CheckVM {
    /// NOTE: THE BELOW IS BASICALLY THE WORK OF a0rtega's pafish PROGRAM
    // doubley-internal cpu brand getter (uses CPUID)
    fn _get_cpu_brand(&mut self, buffer: &mut [u8], offset: usize, level: u32){
        let mut rax: u32 = level;
        let mut rbx: u32;
        let mut rcx: u32;
        let mut rdx: u32;

        // run CPUID with special flags
        unsafe{asm!{"xchg rcx, rbx",
                    "mov rax, rbx", in("rcx") level}};
        unsafe{asm!{"cpuid", in("rax") rax}};
        unsafe{asm!{"mov {:e}, rax", out(reg) rax}};
        unsafe{asm!{"mov {:e}, rbx", out(reg) rbx}};
        unsafe{asm!{"mov {:e}, rcx", out(reg) rcx}};
        unsafe{asm!{"mov {:e}, rdx", out(reg) rdx}};
                                            
        // convert to u8 bytes
        let eax_bytes = rax.to_be_bytes();
        let ebx_bytes = rbx.to_be_bytes();
        let ecx_bytes = rcx.to_be_bytes();
        let edx_bytes = rdx.to_be_bytes();


        //https://github.com/a0rtega/pafish/blob/master/pafish/bochs.c

        // write the data to the stuff
        buffer[0+offset] = eax_bytes[3];
        buffer[1+offset] = eax_bytes[2];
        buffer[2+offset] = eax_bytes[1];
        buffer[3+offset] = eax_bytes[0];

        buffer[4+offset] = ebx_bytes[3];
        buffer[5+offset] = ebx_bytes[2];
        buffer[6+offset] = ebx_bytes[1];
        buffer[7+offset] = ebx_bytes[0];

        buffer[8+offset] = ecx_bytes[3];
        buffer[9+offset] = ecx_bytes[2];
        buffer[10+offset] = ecx_bytes[1];
        buffer[11+offset] = ecx_bytes[0];

        buffer[12+offset] = edx_bytes[3];
        buffer[13+offset] = edx_bytes[2];
        buffer[14+offset] = edx_bytes[1];
        buffer[15+offset] = edx_bytes[0];

        // terminate the string
        buffer[16] = 0;

    }

    fn get_cpu_brand(&mut self, cpu_brand: &mut [u8]){
        let mut eax: u32;

        unsafe{asm!{"mov eax, 0x80000000"}};
        unsafe{asm!{"cpuid"}};
        unsafe{asm!{"cmp eax, 0x80000004"}};
        unsafe{asm!{"xor eax, eax"}};
        unsafe{asm!{"setge al", out("eax") eax}};

        if eax != 0 {
            self._get_cpu_brand(cpu_brand, 0usize, 0x80000002);
            self._get_cpu_brand(cpu_brand, 16usize, 0x80000003);
            self._get_cpu_brand(cpu_brand, 32usize, 0x80000004);
            // zero the string
            cpu_brand[48] = 0;
        }

    }

    fn get_cpu_vendor(&mut self, cpu_vendor: &mut [u8]){
        let mut rbx: u32;
        let mut rcx: u32;
        let mut rdx: u32;

        // so this is actually the part that doesnt work...
        unsafe{asm!{"xor eax, eax"}};
        unsafe{asm!{"cpuid"}};
        // fetch the stuff
        unsafe{asm!{"mov {:e}, rbx", out(reg) rbx}};
        unsafe{asm!{"mov {:e}, rcx", out(reg) rcx}};
        unsafe{asm!{"mov {:e}, rdx", out(reg) rdx}};
        

        // convert to u8 bytes
        let ebx_bytes = rbx.to_be_bytes();
        let ecx_bytes = rcx.to_be_bytes();
        let edx_bytes = rdx.to_be_bytes();


        //https://github.com/a0rtega/pafish/blob/master/pafish/bochs.c

        // write the data to the stuff
        cpu_vendor[0] = ebx_bytes[3];
        cpu_vendor[1] = ebx_bytes[2];
        cpu_vendor[2] = ebx_bytes[1];
        cpu_vendor[3] = ebx_bytes[0];

        cpu_vendor[4] = edx_bytes[3];
        cpu_vendor[5] = edx_bytes[2];
        cpu_vendor[6] = edx_bytes[1];
        cpu_vendor[7] = edx_bytes[0];

        cpu_vendor[8] = ecx_bytes[3];
        cpu_vendor[8] = ecx_bytes[2];
        cpu_vendor[10] = ecx_bytes[1];
        cpu_vendor[11] = ecx_bytes[0];

        // terminate the string
        cpu_vendor[12] = 0;

    }

    fn check_bochs_amd1(&mut self) -> bool {
        let mut cpu_brand = [0 as u8; 49];

        self.get_cpu_brand(&mut cpu_brand);
        let vendor_str = from_utf8(&cpu_brand).unwrap();

        if vendor_str.eq(AMD_BOCHS){
            return true;
        }

        false
    }

    // check secondary AMD problem
    fn check_bochs_amd2(&mut self) -> bool {
        let mut dat: i32;

        unsafe{asm!("xor eax, eax;")}; // zero out eax
        unsafe{asm!("cpuid;")}; // CPUID
        unsafe{asm!("cmp ecx, 0x444d4163;")}; // AMD CPU?
        unsafe{asm!("jne b2not_detected;")};
        unsafe{asm!("mov eax, 0x8fffffff;")}; // magic crap
        unsafe{asm!("cpuid;")};
        unsafe{asm!("jecxz b2detected;")};
        unsafe{asm!("b2not_detected: xor ebx, ebx; jmp b2exit;")};
        unsafe{asm!("b2detected: mov ebx, 0x1;")};
        unsafe{asm!("b2exit: nop", out("eax") dat)};

        dat == 1
    }

    fn check_bochs_intel(&mut self) -> bool {
        let mut cpu_brand = [0 as u8; 49];

        self.get_cpu_brand(&mut cpu_brand);
        let vendor_str = from_utf8(&cpu_brand).unwrap();

        if vendor_str.eq(INTEL_BOCHS){
            return true;
        }

        false
    }

    fn check_qemu_cpu(&mut self) -> bool{
        let mut cpu_brand = [0 as u8; 49];

        self.get_cpu_brand(&mut cpu_brand);
        let vendor_str = from_utf8(&cpu_brand).unwrap();

        if vendor_str.eq(QEMU){
            return true;
        }

        false
    }

    /// END PAFISH CODE
    ///
    /// START Windows-specific detections

    fn win_checks(&mut self) -> bool {
        false
    }

    /// END Windows-specific detections
    ///
    /// START Linux-specific detections

    fn lin_check(&mut self) -> bool {
        false
    }

    /// END Linux-specific detections

    pub fn check_vm(&mut self) -> bool{
        let mut is_ok = false;
        is_ok |= self.check_bochs_amd1();
        is_ok |= self.check_bochs_amd2();
        is_ok |= self.check_bochs_intel();
        is_ok |= self.check_qemu_cpu();

        if OS.eq("windows"){
            // windows-specific detections
            println!("[INFO] windows detections");
            is_ok |= self.win_checks();
        } else if OS.eq("linux"){
            // Linux-specific detections
            println!("[INFO] linux detections");
            is_ok |= self.lin_check();
        } else if OS.eq("android") {
            println!("[INFO] android detections (UNIM)");
            unimplemented!();
        } else {
            println!("[ERR] Unknown OS {}", OS);
        }


        is_ok
    }

}
