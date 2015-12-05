//! # Bitmessage Proof-of-Work
//!
//! Calculating the Proof-of-Work function to send messages
//! from [Bitmessage](https://github.com/Bitmessage/PyBitmessage).
extern crate byteorder;
extern crate crypto;
extern crate num_cpus;

use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::thread;

use crypto::digest::Digest;
use crypto::sha2::Sha512;
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use std::io::Cursor;

/// A single thread of Proof-of-Work calculation
///
/// Returns the nonce that satisfies the target requirement.
/// Reference PoW in Python, the nonce is iterated from 0:
///
///     trialValue, = unpack('>Q',hashlib.sha512(hashlib.sha512(pack('>Q',nonce) + initialHash).digest()).digest()[0:8])
///
/// This value should be less than or equal to the target
fn bmpow(target: u64, hash: [u8; 64], starter: u64, stepsize: u64, chan_out: Sender<u64>) {
    let mut nonce: u64 = starter;
    let mut algoresult;

    loop {
        let mut wtr = vec![];
        let mut result: [u8; 64] = [0; 64];
        let mut hasher_inner = Sha512::new();
        let mut hasher_outer = Sha512::new();

        nonce += stepsize;
        match wtr.write_u64::<BigEndian>(nonce) {
            Ok(_) => {},
            Err(e) => { println!("error writing endian: {}", e) },
        }
        hasher_inner.input(&wtr);
        hasher_inner.input(&hash);

        hasher_inner.result(&mut result);
        hasher_outer.input(&result);

        let mut result_outer: [u8; 64] = [0; 64];
        hasher_outer.result(&mut result_outer);

        let mut r2 = vec![0; 64];
        hasher_outer.result(&mut r2);
        let mut rdr = Cursor::new(r2);
        // Converting from BigEndian to the endinannes of the system
        algoresult = rdr.read_u64::<BigEndian>().unwrap();
        if algoresult < target {
            chan_out.send(nonce).unwrap();
            return;
        }
    }
}

/// The exported Proof-of-Work task
///
/// In the reference PyBitmessage client copy or link `libbmpow.so` to
/// the `src/` director, then add to `src/proofofwork.py` something like this:
///
///     def _doRustPow(target, initialHash):
///         from ctypes import cdll, c_ulonglong,  c_void_p, create_string_buffer, byref
///         import os.path
///         me = os.path.abspath(os.path.dirname(__file__))
///         lib = cdll.LoadLibrary(os.path.join(me, "libbmpow.so"))
///         p = create_string_buffer(initialHash, 64)
///         lib.runpow.argtypes = [c_ulonglong, c_void_p];
///         lib.runpow.rettype = c_ulonglong;
///         nonce = lib.runpow(target, byref(p))
///         trialValue, = unpack('>Q',hashlib.sha512(hashlib.sha512(pack('>Q',nonce) + initialHash).digest()).digest()[0:8])
///         return [trialValue, nonce]
///
/// and in run() call:
///
///    return _doRustPow(target, initialHash)
///
#[no_mangle]
pub extern fn runpow(target: u64, hash: &[u8; 64]) -> u64 {

    // Set up signaling to receive the result
    let (tx, rx): (Sender<u64>, Receiver<u64>) = mpsc::channel();

    let threads = num_cpus::get() as u64;

    // Copy them input
    let mut h: [u8; 64] = [0; 64];
    for (i, b) in hash.iter().enumerate() {
        h[i] = *b;
    }

    // Start computation
    for i in 0..threads {
        let tx = tx.clone();
        thread::spawn(move || {
            bmpow(target, h, i, threads, tx);
        });
    }

    // Wait until one of the threads tumbles on a good nonce
    let value = rx.recv().unwrap();
    value
}
