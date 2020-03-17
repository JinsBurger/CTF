import gdb
import string
import binascii

lastcnt = 10000
key1 = False
key2 = False

def zz(a,c) :
	z = ((0x10000 - c )& 0xffff)^a
	print(binascii.unhexlify(hex(z)[2:])[::-1])


#flag = "CODEGATE2020{ezpz_but_1t_1s_pr3t3xt}".ljust(36,"A")
flag = "CODEGATE2020".ljust(36,"A")

gdb.execute('file simple_machine', to_string=True)

class MyBreakpoint(gdb.Breakpoint):
    def stop (self):
    	global key1
    	global key2

    	if key1: 
    		key2 = int(gdb.execute('p/x *(unsigned short *)($rdi+0x34)', to_string=True).split("0x")[1].strip(),16)
    		print(hex(key2))
    		zz(key1,key2)

    	if gdb.execute('p/x $ax', to_string=True).split("0x")[1].strip() == "4141" : 
    		key1 = int(gdb.execute('p/x *(unsigned short *)($rdi+0x36)', to_string=True).split("0x")[1].strip(),16)

    	return False
    	#gdb.execute("c")

MyBreakpoint('*0x55555555588c')
MyBreakpoint('*0x555555555860')
gdb.execute('run target <<< "{flag}"'.format(flag=flag))
exit(-1)
