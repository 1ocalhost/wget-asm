# wget-asm.py

A simple implementation of wget using Python and assembly language
that supports the 32-bit architectures of x86, MIPS, and ARM.

```
>>> ./wget-asm.py httpbin.org/get --mini --exe demo
>>> file demo
demo: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
statically linked, no section header
>>> wc -c demo
467 demo
>>> ./demo
{
  "args": {},
  "headers": {
    "Host": "httpbin.org",
  },
  "url": "http://httpbin.org/get"
}
```
