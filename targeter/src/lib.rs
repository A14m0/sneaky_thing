/// Library to determine potential targets on the network
/// We disregard any machines that are not Windows


/// base structure/class thing for IP targeting 
pub mod targeter {
    // uses for the module
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::TcpStream;
    use std::str::FromStr;

    use num::bigint::BigUint;
    use num::ToPrimitive;
    

    /// Defines the timeout value for pings
    /// The smaller the value, the faster pings will declare a failed ping
    /// 
    /// This speeds up the scan at the cost of potentially 
    /// missing higher-latency machines 
    static PING_FREQ: f32 = 0.2;


    #[derive(Debug)]
    pub enum NetError {NoNet, NoValIP, IpDown, ResourceBusy}

    impl std::fmt::Display for NetError{
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match *self {
                NetError::NoNet => write!(f, "No Network"),
                NetError::NoValIP => write!(f, "No Valid IP Addresses Found"),
                NetError::IpDown => write!(f, "Ip Is Down"),
                NetError::ResourceBusy => write!(f, "Resource is busy"),
            }
        }
    }


    /// Targeter Structure
    pub struct Targeter {
        pub valid_ips: Vec<String>,
    }

    impl Targeter{
        /// constructor
        pub fn new() -> Self{
            Targeter{valid_ips: Vec::new()}
        }

        /// gets the current local IP address(es) of the machine
        /// CURRENTLY DOESN'T WORK AND JUST RETURNS A DEFAULT ADDRESS
        fn get_locip(&mut self) -> Result<ipaddress::IPAddress, NetError>{
            
            let ip = match ipaddress::ipv4::new("192.168.0.30/24") {
                Ok(ip) => ip,
                Err(e) => panic!("[TARGETER] Caught error {}", e)
            };


            Ok(ip)
        }


        /// checks if a target is valid
        /// for right now, it is only checking if the address is up.
        /// Potentially, we will do the valid target check in a separate function,
        /// but for now we are just putting it all here. 
        fn check_target(&self, ip: &ipaddress::IPAddress) -> 
                                Result<(), NetError> {
            if ip.is_network(){
                println!("[TARGETER] Network IP Address detected");
            } else {
                
                // convert IPAddress to std IpAddr
                let v4 = match Ipv4Addr::from_str(ip.to_s().as_str()){
                    Ok(i) => i,
                    Err(e) => panic!("Failed to convert address to IpvrAddr: {}", e)
                };

                let t_ip = IpAddr::V4(v4);
                
                // determine if the target is up
                match ping::ping(t_ip, Some(std::time::Duration::from_secs_f32(PING_FREQ)), None, None, None, None) {
                    Ok(_) => { return Ok(())}, //println!("IP: {} -> Address is up!", ip.to_s());
                    Err(e) => {
                        let tmp = format!("{}", e);
                        // filter off the resource busy errors so we can retry them
                        if tmp.starts_with("io error: Resource temporarily unavailable"){
                            return Err(NetError::ResourceBusy)
                        }
                        // unknown/unexpected errors
                        else if !tmp.eq("internal error"){
                            println!("[TARGETER] Unexpected error: {}", e);
                        }
                        
                        ()},
                };
            }
            
            
            Err(NetError::NoValIP)
        }

        /// determine what IPs are valid on the subnet
        fn determine_ips(&mut self) -> Result<u32, NetError> {
            let locip = self.get_locip()?;
            let network = locip.network();
            println!("[TARGETER] Network: {}", network.to_s());

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

            // retry counter
            let mut retry = 0;
            
            // loop over all addresses
            while i <= bc {
                // prep variables
                let re = &BigUint::from(i);
                let tmpip = network.from(re, x);

                // check the target
                match self.check_target(&tmpip){
                    Ok(_) => self.valid_ips.push(tmpip.to_s()),
                    Err(NetError::ResourceBusy) => {
                        println!("[TARGETER] Trying {} again...", tmpip.to_s()); 
                        retry += 1;
                        i -= 1
                    },
                    Err(_) => ()
                }

                // check if we have hit the maximum number of retries
                if retry > 10{
                    println!("[TARGETER] Reached max retries, giving up on {}", tmpip.to_s());
                    retry = 0; // reset retry counter
                    i += 1; // negate our decriment from above
                }

                // move on
                i += 1;
            }

            // print up addresses
            for i in self.valid_ips.iter(){
                println!("[TARGETER] Up IP: {}", i);
            }
        
            Ok(0)
        }

        /// Populates the struct's vector with possible exploitable targets
        /// currently available on the network. This is the only public function
        /// implemented for the structure (outside of `new`, of course)
        /// 
        /// Returns a Result<u32, NetError> 
        pub fn determine_targets(&mut self) -> Result<u32, NetError> {
            self.determine_ips()?;

            Ok(0)
        }
    }
}
