/// Library to determine potential targets on the network
/// We disregard any machines that are not Windows

extern crate smbclient_sys as smb;
extern crate libc;


/// SMB-based functions, uses smbclient bindings
pub mod smblib {
    use std::str;
    use std::ffi::{CStr, CString};
    use libc::{c_char, c_int, strncpy, O_RDONLY};

    extern "C" fn auth_data(_srv: *const c_char,
                _shr: *const c_char,
                _wg: *mut c_char,
                _wglen: c_int,
                _un: *mut c_char,
                _unlen: c_int,
                _pw: *mut c_char,
                _pwlen: c_int) {

        unsafe {
            // dummy login info. wont need this once we have a working exploit
            strncpy(_un, CString::new("W. Churchill").unwrap().as_ptr(), 13);
            strncpy(_pw, CString::new("Password123").unwrap().as_ptr(), 12);
        }
    }

    static mut AUTH_CALLBACK: smb::smbc_get_auth_data_fn = Some(auth_data);

    pub fn connect() {
        println!("Launch...");
        unsafe {
            // test server. eventually we want to make the device discoverable on its own
            let fname = CString::new("smb://192.168.97.132/Documents/test.txt").unwrap();

            // Buffer for contents
            let dstlen = 300;
            let mut file_contents = Vec::with_capacity(dstlen as usize);

            smb::smbc_init(AUTH_CALLBACK, 0);
            let retval: i32 = smb::smbc_open(fname.as_ptr(), O_RDONLY, 0);
            if retval < 0 {
                println!("Couldn't accessed to a SMB file (code {})", retval);
            } else {
                println!("Accessed to specified SMB file");

                // Read file to buffer
                let read_val: i64 = smb::smbc_read(retval, file_contents.as_mut_ptr(), dstlen);
                if read_val > 0 {
                    // File successfully read, print contents to stdout

                    let c_str: &CStr = CStr::from_ptr(file_contents.as_mut_ptr() as *const i8);
                    let content_bytes: &[u8] = c_str.to_bytes();
                    let str_slice: &str = str::from_utf8(content_bytes).unwrap();
                    let str_buf: String = str_slice.to_owned();

                    println!("{0}", str_buf);
                } else {
                    // Panic \o/ if you couldn't read
                    panic!("Couldn't read file over SMB share");
                }

                // Close it
                smb::smbc_close(read_val as i32);
            }
        }
    }
}


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
