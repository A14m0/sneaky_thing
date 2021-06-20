use vm_detector::CheckVM;


struct SneakiNet{}


impl SneakiNet {
    pub fn new() -> Self {
        SneakiNet{}
    }

    /*(fn initialize(&mut self, target: &str){
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
    }*/

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
    let mut t = SneakiNet::new();
    
    println!("[PAYLOAD] Hello world!");
}