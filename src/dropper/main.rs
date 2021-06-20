use targeter::targeter;
//use std::{net::TcpStream, io::{Read,Write}};


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
///     Potentially smaller footprint --> https://github.com/returnvar/wce
/// 





fn main() {
    let mut tgtr = targeter::Targeter::new(); 

    // check if we are in a VM
    let rc = match tgtr.determine_targets(){
        Ok(i) => i,
        Err(e) => panic!("Caught error: {}", e)
    };

    println!("Return code {}", rc);
}
