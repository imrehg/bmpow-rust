# Bitmessage Proof-of-Work

An alternative Proof-of-Work (PoW) worker library for [Bitmessage][bitmessage],
written in Rust. It's part of my learning experience with Rust ([see my blog][blog])

Build the dynamic library file `libbmpow.so` with:

    cargo build --release
	
To use it with the [PyBitmessage reference client][pybitmessage]
Then copy or symlink the resulting `target/release/libbmpow.so` to the
`src/` directory, and update `src/proofofwork.py` to add an extra function
to call this library, for example something like this:

    def _doRustPow(target, initialHash):
        from ctypes import cdll, c_ulonglong,  c_void_p, create_string_buffer, byref
        import os.path
        me = os.path.abspath(os.path.dirname(__file__))
        lib = cdll.LoadLibrary(os.path.join(me, "libbmpow.so"))
        p = create_string_buffer(initialHash, 64)
        lib.runpow.argtypes = [c_ulonglong, c_void_p];
        lib.runpow.rettype = c_ulonglong;
        nonce = lib.runpow(target, byref(p))
        trialValue, = unpack('>Q',hashlib.sha512(hashlib.sha512(pack('>Q',nonce) + initialHash).digest()).digest()[0:8])
        return [trialValue, nonce]

    def run(target, initialHash):
        target = int(target)
        return _doRustPow(target, initialHash)

[blog]: https://gergely.imreh.net/blog/2015/11/language-of-the-month-rust/ "Language of the Month: Rust"
[bitmessage]: https://bitmessage.org/wiki/Main_Page "Bitmessage Wiki"
[pybitmessage]: https://github.com/Bitmessage/PyBitmessage

## Benchmarks

The speed of this PoW calculation was tested on a Lenovo X201, very unscientifically.

The Python reference `_doFastPow` function (multicore) clocks in about 440,000 hash/s.

This library (multicore) clocks in 890,000 - 1,800,000 hash/s (variable), or (single core) 
about 870,000 hash/s.

Another PoW worker I have, written in OpenCL, clocks in (single core) 1,150,000 hash/s,
for reference.

## License

Released under the [MIT license](https://opensource.org/licenses/MIT)

Copyright (c) 2015 Gergely Imreh <imrehg@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
