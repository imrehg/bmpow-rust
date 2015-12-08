//! # Bitmessage Proof-of-Work
//!
//! Calculating the Proof-of-Work function to send messages
//! from [Bitmessage](https://github.com/Bitmessage/PyBitmessage).

extern crate crypto;
extern crate num_cpus;

use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::mem;

use crypto::digest::Digest;
use crypto::sha2::Sha512;

/// A single thread of Proof-of-Work calculation
///
/// Returns the nonce that satisfies the target requirement.
/// Reference PoW in Python, the nonce is iterated from 0:
///
///     trialValue, = unpack('>Q',hashlib.sha512(hashlib.sha512(pack('>Q',nonce) + initialHash).digest()).digest()[0:8])
///
/// This value should be less than or equal to the target
fn bmpow(target: u64, hash: &[u8; 64], starter: u64, stepsize: u64, cancelled: &AtomicBool) -> u64 {
    for i in 0.. {
        if cancelled.load(Relaxed) {
            return 0;
        }
        let nonce = starter + i * stepsize;
        if hash_nonce(nonce, &hash) < target {
            return nonce;
        }
    }
    unreachable!();
}

fn hash_nonce(nonce: u64, hash: &[u8; 64]) -> u64 {
    let nonce_bytes: [u8; 8] = unsafe {mem::transmute(nonce.to_be())};
    let mut hasher = Sha512::new();
    let mut hash_result = [0u8; 64];
    // hash (nonce + hash)
    hasher.input(&nonce_bytes);
    hasher.input(hash);
    hasher.result(&mut hash_result);
    hasher.reset();
    // hash result
    hasher.input(&hash_result);
    hasher.result(&mut hash_result);
    let result: &u64 = unsafe {mem::transmute(&hash_result)};
    u64::from_be(*result)
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

    let hash = *hash;
    // allow threads to be cancelled, so they don't continue computation 
    let cancelled = Arc::new(AtomicBool::new(false));

    // Start computation
    for i in 0..threads {
        let tx = tx.clone();
        let cancelled = cancelled.clone();
        thread::spawn(move || {
            let result = bmpow(target, &hash, i, threads, &cancelled);
            // If the channel is closed, don't panic
            let _ = tx.send(result);
        });
    }

    // Wait until one of the threads tumbles on a good nonce
    let value = rx.recv().unwrap();
    cancelled.store(true, Relaxed);
    value
}
