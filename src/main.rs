use vm_detector::CheckVM;
use std::{net::TcpStream, io::{Read,Write}};


/// Eventually we wanna implement these things:
/// 
/// MS17-010 EternalBlue --> https://github.com/worawit/MS17-010/blob/master/eternalblue_exploit7.py
/// CVE-2020-1350 WDNS Server RCE --> https://github.com/ZephrFish/CVE-2020-1350
/// 
/// Non-critical exploits we could use
/// MS08-067 NETAPI --> https://github.com/fahrishb/Exploits/blob/master/MS08-067/ms08-067-poc.py
/// 
/// Additional features we should look into (totally not inspired by NotPetya...)
/// Mimikatz password exposing --> https://github.com/gentilkiwi/mimikatz

struct SneakiNet{
    id: u32, 
}


impl SneakiNet {
    fn initialize(&mut self, target: &str){
        // attept to connect to the target 
        match TcpStream::connect(target) {
            Ok(mut stream) => {
                // connected
                println!("[INFO] Connected...");
                
                // write test message
                let msg = b"hola";
                stream.write(msg).unwrap();

                println!("[INFO] Message sent, awaiting reply...");

                let mut data = [0 as u8; 4];
                match stream.read_exact(&mut data){
                    Ok(_) => {
                        // woo our stuff matched :)
                        if &data == msg {
                            println!("[INFO] Completed message cycle");                        }
                    },
                    Err(e) => {
                        println!("[ERR] Failed: {}", e);
                    }
                }
            },
            Err(e) => {
                println!("[ERR] Failed: {}", e);
            } 
        }
        println!("[INFO] Terminated");
    }

    fn check_vm(&mut self) -> bool {
        let mut cvm = CheckVM{};
        //let mut cpu_brand = [0 as u8; 49];

        //cvm.get_cpu_brand(&mut cpu_brand);

        //for bit in cpu_brand.iter() {
        //    print!("{} ", bit);
        //}


        //let vendor_str = from_utf8(&cpu_brand).unwrap();

        //println!("CPU STRING: {}", vendor_str);

        cvm.check_vm()
    }

}



fn main() {
    let id = 1;
    let mut t = SneakiNet{ id };
    if t.check_vm(){
        println!("WE IN A MF VM LOL");
    } else {
        println!("We good :)");
    }
}
