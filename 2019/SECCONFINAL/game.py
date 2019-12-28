from pwn import *
import sys
from defenseparse import *
from ctypes import CDLL

#./gameserv.bin 10
#nc 10.2.1.1  20000
context.log_level = "DEBUG"

if sys.argv[1] == "1" : 
	MyIP = "10.0.0.2"
	SERVERIP = MyIP
else : 
	MyIP = "192.168.8.4"
	SERVERIP = "10.2.1.1"

BASEPORT = (((u32(binary_ip(MyIP)[::-1]) >> 8) % 50) * 1000 + 10000)


print BASEPORT

while True:

	flag = getflag()
	token = flag

	print "FLAG : " + flag

	p = remote(SERVERIP,BASEPORT)
	#p.interactive()
	#p = remote("10.2.1.1",20000)

	p.sendafter(":",token)

	get = p.recv(1000,timeout=0.01)
	port = int(get.split("is ")[1][:5])
	print port

	for i in range(10) : 
		print "[STAGE %d] udp port : %d"%(i,port)
		r = remote(SERVERIP,port,typ="udp")
		
		if i == 9 :
			for i in range (100) : 
				try : 
					r.sendline(flag)
					get = r.recv(100,timeout=0.01)
					if get != ''  :
						break
#sleep(0.1)
				except : 
					pass
			break

		try : 
			for _ in range(40) : 
				r.sendline(token[:-2])
				get = r.recv(100,timeout=0.01)

				print hexdump(get.split("is "))
				port = int(get.split("is ")[1][:5])
#sleep(0.1)
		except : 
			pass

	p.close()

	sleep(300)
#p.interactive()
