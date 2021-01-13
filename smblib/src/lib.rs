

extern crate smbclient_sys as smb;
extern crate libc;

// sources to look into structure
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962



#[cfg(test)]
pub mod smblib {
    use std::str;
    use std::ffi::{CStr, CString};
    use libc::{c_char, c_int, strncpy, O_RDONLY};

    extern "C" fn auth_data(srv: *const c_char,
                shr: *const c_char,
                wg: *mut c_char,
                wglen: c_int,
                un: *mut c_char,
                unlen: c_int,
                pw: *mut c_char,
                pwlen: c_int) {

        unsafe {
            // dummy login info. wont need this once we have a working exploit
            strncpy(un, CString::new("W. Churchill").unwrap().as_ptr(), 13);
            strncpy(pw, CString::new("Password123").unwrap().as_ptr(), 12);
        }
    }

    pub static mut authCallback: smb::smbc_get_auth_data_fn = Some(auth_data);

    fn connect() {
        println!("Launch...");
        unsafe {
            // test server. eventually we want to make the device discoverable on its own
            let fname = CString::new("smb://192.168.97.132/Documents/test.txt").unwrap();

            // Buffer for contents
            let dstlen = 300;
            let mut file_contents = Vec::with_capacity(dstlen as usize);

            smb::smbc_init(authCallback, 0);
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
