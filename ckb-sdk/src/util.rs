use std::{ptr, sync::atomic};

pub fn zeroize_privkey(key: &mut secp256k1::SecretKey) {
    let key_ptr = key.as_mut_ptr();
    for i in 0..key.len() as isize {
        unsafe { ptr::write_volatile(key_ptr.offset(i), Default::default()) }
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

pub fn zeroize_slice(data: &mut [u8]) {
    for elem in data {
        unsafe { ptr::write_volatile(elem, Default::default()) }
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}
