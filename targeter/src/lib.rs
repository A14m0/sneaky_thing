/// Library to determine potential targets on the network
/// We disregard any machines that are not Windows


/// base structure/class thing for IP targeting 
pub mod targeter {
    mod ping::errors;

    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::TcpStream;
    use std::str::FromStr;

    use num::bigint::BigUint;
    use num::ToPrimitive;
    
    static PING_FREQ: f32 = 0.2;


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
        pub valid_ips: Vec<String>,
    }

    impl Targeter{
        // constructor
        pub fn new() -> Self{
            Targeter{valid_ips: Vec::new()}
        }

        fn get_locip(&mut self) -> Result<ipaddress::IPAddress, NetError>{
            
            let ip = match ipaddress::ipv4::new("192.168.0.30/24") {
                Ok(ip) => ip,
                Err(e) => panic!("[TARGETER] Caught error {}", e)
            };


            Ok(ip)
        }

        fn check_target(&self, ip: &ipaddress::IPAddress) -> 
                                Result<(), NetError> {
            if ip.is_network(){
                println!("Network IP Address detected");
            } else {
                
                let v4 = match Ipv4Addr::from_str(ip.to_s().as_str()){
                    Ok(i) => i,
                    Err(e) => panic!("Failed to convert address to IpvrAddr: {}", e)
                };

                let t_ip = IpAddr::V4(v4);
                
                // determine if the target is up
                match ping::ping(t_ip, Some(std::time::Duration::from_secs_f32(PING_FREQ)), None, None, None, None) {
                    Ok(_) => { return Ok(())}, //println!("IP: {} -> Address is up!", ip.to_s());
                    Err(errors::Error{errors::ErrorKind::InternalError})  => (),
                    Err(e) => {println!("Unexpected error: {}", e); ()},
                };
            }
            
            
            Err(NetError::NoValIP)
        }

        // determine what IPs are valid on the subnet
        fn determine_ips(&mut self) -> Result<u32, NetError> {
            let locip = self.get_locip()?;
            let network = locip.network();
            println!("Network: {}", network.to_s());

            // define network prefix
            let x = &network.prefix;

            // define broadcast address, converted to u64
            let bc = match network.broadcast().host_address.to_u64(){
                Some(x) => x,
                None => 0,
            };

            // define host address, also converted to u64
            let mut i = match network.host_address.to_u64(){
                Some(x) => x,
                None => 0,
            };
            
            // loop over all addresses
            while i <= bc {
                // prep variables
                let re = &BigUint::from(i);
                let tmpip = network.from(re, x);

                // check the target
                match self.check_target(&tmpip){
                    Ok(_) => {self.valid_ips.push(tmpip.to_s()); ()},
                    Err(_) => ()
                }

                // move on
                i += 1;
            }

            // print up addresses
            for i in self.valid_ips.iter(){
                println!("Up IP: {}", i);
            }
        
            Ok(0)
        }

        pub fn determine_targets(&mut self) -> Result<u32, NetError> {
            self.determine_ips()?;

            Ok(0)
        }
    }
}
