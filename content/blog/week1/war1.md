---
title: Hi Pwntools, Goodbye Shell Scripts
date: "2020-06-16 21:04:31.582772"
description: "A first look at pwntools"
categories: ["code"]
---
## Intro

---

**Tl;dr: use pwntools. Interact with the process using pwntools and use rabin2 -z to get the strings from the file. Profit.**

In this challenge we have an unknown file 'intro' which would give us a hint to the flag. Time to get into it.

1. Run the file command to find out what files I'm dealing with (prettified)
   ```
   intro: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV),
   dynamically linked,
   interpreter /lib/ld-linux.so.2,
   for GNU/Linux 3.2.0, BuildID[sha1]=177bf7376a9ca94f15c6557a9301244afc7c00f4,
   with debug_info, not stripped
   ```
   So its an Elf binary => An executable program (assuming C)
2. Since it is executable, and because I expect it to be safe enough, I run it.

   ```
   Yay you connected!
   If you connected WITHOUT using pwntools, please exit and do that first!
   Lets see if you can strip out this address: {0x1337}
   Now send it back to me in decimal form!
   ```

   Ah, interacting with another process.  
   I remember when I would write programs for the same and it would never work, resorting to shell loops was also hopeless.  
   Well pwntools is here to solve all problems.

3. I used (pwnlib.tubes.process)[https://docs.pwntools.com/en/stable/tubes/processes.html] to run and interact with the process. Spawn a new process using the `process` function, then using the `readuntil(<str>)` function you can very literally read until the passed string is found in the input. Then use `sendline(<str>)` to write data back to the process.
   1. `process()` has a flag: `shell` which would interpret the argument as a shell command instead of a file to run
   2. `readuntil()` has a flag: `drop` which would drop the delimiter you passed in
   3. `sendline(<str>)` function will write a newline after the string is printed
4. The binary throws a couple of challenges my way: converting hex to decimal, basic maath operations, reading and writing bytes etc. Here are the list of functions (from pwntools) I used to solve them:
   1. (p32)[https://docs.pwntools.com/en/stable/util/packing.html#pwnlib.util.packing.p32]: convert (pack) integer into raw byte form
   2. (u32)[https://docs.pwntools.com/en/stable/util/packing.html#pwnlib.util.packing.u32]: Unpack raw bytes into integer form
5. Finally, the binary asks for a secret hidden in the file. Easily found by running `strings` on the file. But if you ever downloaded radare2, I recommend using

   ```
   rabin2 -z intro
   ```

   to get the strings. The command gets only the strings in the data section of memory so you don't have to peer through the long list.

   The string **password** which was not seen used before, so assuming that that was the one, you test it, and it works.

6. The final step is to use the `interactive()` function from `pwnlib.tubes` to interact with the shell that the process spawns on finishing all the challenges. Run `cat flag` to get the flag in the directory.


This makes the final script to run the following.

```
from pwn import *

p = process('nc plsdonthaq.me 1025', shell=True)    # remote
#p = process('./intro')                             # local usage

p.readuntil('{')                                    # read until the first '{'
raw_n = p.readuntil('}', drop=True).decode()        # --> Expected: {0x1337} => 0x1337
n1 = int(raw_n, 16)                                 # convert to decimal
p.sendline(str(n1))                                 # send data

p.readuntil('MINUS ')                               # Read until 'MINUS '
n2 = p.readuntil('!', drop=True)                    # ---> Expected: 0x103! => 0x103
p.sendline(str(hex(int(n1)-int(n2, 16))))           # subtract and send

p.sendline(p32(n1))                                 # convert to bytes, little endian by default

p.readuntil('next line)\n')                         # Read
addr = p.readuntil('\n', drop=True)                 # Expected: xV4\x12
parsed = u32(addr)                                  # Expected: 305419896
p.sendline(str(parsed))

p.sendline(str(hex(parsed)))                        # Expected: 0x12345678

p.readuntil('What is ')                             # Read
a = int(p.readuntil(' + ', drop=True).decode())     # read first number, Expected: 12345
b = int(p.readuntil('?', drop=True).decode())       # read second number, Expected: 12345
p.sendline(str(a + b))                              # send sum

p.sendline('password')                              # password that we got earlier

p.interactive()                                     # Interactivity!
```

### Tip

1. One thing that helped me in my endeavors is the `DEBUG` flag. On running the script with the flag, it prints all debug output like what data was received from the spawned process, which is amazing for debugging.


## Too-Slow

---

**Tl;dr: Pwntools is pretty cool. You can pass multiple delimiters to `readuntil()`!**


We come across a strange file named 'too-slow'. Time to analyze it.

1. Similar to the previous one, start by running the file command.

   ```
   too-slow: ELF 32-bit LSB shared object,
   Intel 80386,
   version 1 (SYSV),
   dynamically linked,
   interpreter /lib/ld-linux.so.2,
   for GNU/Linux 3.2.0,
   BuildID[sha1]=fc21f7e613d118404b5c0e038868a6e938b8766e,
   with debug_info, not stripped
   ```

   ELF-binary. Yay

2. Running it, we see it wants you to solve math problems. Fast. Now, unless you're a human calculator with godlike typing speeds, it's best to leave this one to pwntools. Same as the last one, use pwntools to read and write to the process. Now, you would realize that you have to do this in a loop to solve all the problems.
3. When you do that however, the program gets stuck after a while. Using the DEBUG flag, we see that we have solved all the math problems and the program has opened up a shell. Pwntools is trying to read from the process, but no data is sent across. So it's not interactive, and you cannot talk to the shell it just spawned.
4. Now, you have two ways to fix this. Either brute force it, finding the number of problems the program asks you to solve or use the `readuntil()` function better. Using the DEBUG flag to understand the format of the inut, you see that there are essentially 3 types of lines. _Correct Answer\n_, _number + number =_, _Well done\n_. On looking at the pwntools documentation, you see that `readuntil()` accepts a list of delimiters. Using this information you can parse the input better to solve the problem.
5. Lastly, you need the `interactive` method again to talk to the shell that was spawned.


So the final script was

```
from pwn import *

# p = process('./too-slow')                                    # Local
p = process('nc plsdonthaq.me 1026', shell=True)               # Remote

def run(done):
	op = p.readline()                                           # read until newline
	numline = p.readuntil((' =', '\n'), drop=True).decode()     # read until newline or ' ='
	if (done in numline):                                       # check if we're done
		return False
	a, b = numline.split(' + ')                                 # Grab the two numbers
	p.sendline(str(int(a) + int(b)))                            # Return the sum
	return True                                                 # Not done yet

while (run('Well done!')):                                     # While there is work to do... do work
	pass

p.interactive()                                                # Talking to the shell
```


## Conclusion

---

Pwntools truly is amazing. I look forward to using the other features too.
