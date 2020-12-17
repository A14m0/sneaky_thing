/// Library to determine potential targets on the network
/// We disregard any machines that are not Windows


/// base structure/class thing for IP targeting 
pub mod targeter {
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::TcpStream;
    use std::str::FromStr;

    use num::bigint::BigUint;
    use num::One;
    use num::ToPrimitive;
    use core::ops::Add;


    #[derive(Debug)]
    pub enum NetError {NoNet, NoValIP, IpDown}

    impl std::fmt::Display for NetError{
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match *self {
                NetError::NoNet => write!(f, "No Network"),
                NetError::NoValIP => write!(f, "No Valid IP Addresses Found"),
                NetError::IpDown => write!(f, "Ip Is Down"),
            }
        }
    }


    /// Targeter Structure
    pub struct Targeter {
        id: u32,
        pub valid_ips: Vec<String>,
    }

    impl Targeter{
        // constructor
        pub fn new() -> Self{
            Targeter{id: 0, valid_ips: Vec::new()}
        }

        fn get_locip(&mut self) -> Result<ipaddress::IPAddress, NetError>{
            
            let ip = match ipaddress::ipv4::new("192.168.0.30/24") {
                Ok(ip) => ip,
                Err(e) => panic!("[TARGETER] Caught error {}", e)
            };


            Ok(ip)
        }

        fn check_target(&self, ip: &ipaddress::IPAddress) -> 
                                Result<ipaddress::IPAddress, NetError> {
            let mut o = 0;
            if ip.is_network(){
                println!("Network IP Address detected");
            } else {
                print!("IP: {}... \n", ip.to_s());
                
                let v4 = match Ipv4Addr::from_str(ip.to_s().as_str()){
                    Ok(i) => i,
                    Err(e) => panic!("Failed to convert address to IpvrAddr: {}", e)
                };

                let t_ip = IpAddr::V4(v4);
                
                // determine if the target is up
                o = match ping::ping(t_ip, None, None, None, None, None) {
                    Ok(_) => {println!("Address is up!"); 0},
                    Err(e) => {println!("\tdown ({})", e); 1},
                };
            }
            
            
            Err(NetError::NoValIP)
        }

        // determine what IPs are valid on the subnet
        fn determine_ips(&mut self) -> Result<u32, NetError> {
            let locip = self.get_locip()?;
            let network = locip.network();
            println!("Network: {}", network.to_s());

            let x = &network.prefix;

            let bc = match network.broadcast().host_address.to_u64(){
                Some(x) => x,
                None => 0,
            };

            let mut i = match network.host_address.to_u64(){
                Some(x) => x,
                None => 0,
            };
            
            while i <= bc {
                // do stuff
                let re = &BigUint::from(i);

                match self.check_target(&network.from(re, x)){
                    // need to find work around for non-mutable access to variables
                    Ok(x) => {self.valid_ips.push(x.to_s()); ()},
                    Err(_) => ()
                }

                i += 1;
            }
        
            Ok(0)
        }

        pub fn determine_targets(&mut self) -> Result<u32, NetError> {
            self.determine_ips()?;

            Ok(0)
        }
    }
}
