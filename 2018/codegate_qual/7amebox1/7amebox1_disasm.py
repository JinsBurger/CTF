'''
Reference : https://lyoungjoo.github.io/2018/04/09/Codegate-2018-prequals-7amebox1-write-up/
'''

firm_file = []

TYPE_R = 0
TYPE_I = 1
register_list = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7','r8', 'r9', 'r10', 'bp', 'sp', 'pc', 'eflags', 'zero']
op_hander_table = ['op_x0', 'op_x1', 'op_x2', 'op_x3', 'op_x4', 'op_x5', 'op_x6', 'op_x7', 'op_x8', 'op_x9', 'op_x10', 'op_x11', 'op_x12', 'op_x13', 'op_x14', 'op_x15', 'op_x16', 'op_x17', 'op_x18', 'op_x19', 'op_x20', 'op_x21', 'op_x22', 'op_x23', 'op_x24', 'op_x25', 'op_x26', 'op_x27', 'op_x28', 'op_x29', 'op_x30']
ret_chk = True

def jmp_int_str_(src,op_size,pc):
    try:
        src = int(src)
        if(src > 0x100000):
            return hex(pc + op_size - (0x200000 - src))
        else:
            return hex(pc + op_size + src)
    except:
        return src

def asm(op,arg1,arg2,arg1_in_chk,arg2_in_chk):
    result = op +" "
    if(arg1_in_chk == True):
        result += "["+arg1+"]"
    else:
        result += arg1 + ""
    if(arg2 == ''):
        result += " "
    elif(not arg1 == ''):
        result += " , "
    if(arg2_in_chk == True):
        result += "["+arg2+"]"
    else:
        result += arg2 + ""
    return result


def disasm(op, op_type, opers, op_size,pc):
    global ret_chk
    ret_chk = False
    '''
    [src]
    src = self.register.get_register(opers[1])
    data = self.read_memory_tri(src, 1)[0]

    mov
    self.register.set_register(dst, data)
    '''
    dst = register_list[opers[0]]
    if(op_type == TYPE_R):
        src = register_list[opers[1]]
    elif(op_type == TYPE_I):
        src = opers[1]
    else:
        print("fuck!")
        exit(1)
    src = str(src)
    if(op == 0):
        return asm("mov",dst,src,False,True)
    elif(op == 1):
        return asm("movb7",dst,src,False,True)
    elif(op == 2):
        '''
        opers 0  , 1 changed
        src = self.register.get_register(opers[0]) 
        dst = self.register.get_register(opers[1])
        '''
        return asm("mov",src,dst,True,False)
    elif(op == 3):
        return asm("movb7",src,dst,True,False)
    elif(op == 4):
        return asm("mov",dst,src,False,False)
    elif(op == 5):
        return asm("xchg",dst,src,False,False)
    elif(op == 6):
        return asm("push",dst,'',False,False)
    elif(op == 7):
        if(dst != 'pc'):
            return asm("pop",dst,'',False,False)
        else:
            ret_chk = True
            return asm("ret",'','',False,False)
    elif(op == 8):
        return asm("syscall",'','',False,False)
    elif(op == 9):
        return asm("add",dst,src,False,False)
    elif(op == 10):
        return asm("add2",dst,src,False,False)
    elif(op == 11):
        return asm("sub",dst,src,False,False)
    elif(op == 12):
        return asm("sub2",dst,src,False,False)
    elif(op == 13):
        return asm("shr",dst,src,False,False)
    elif(op == 14):
        return asm("shl",dst,src,False,False)
    elif(op == 15):
        return asm("mul",dst,src,False,False)
    elif(op == 16):
        return asm("div",dst,src,False,False)
    elif(op == 17):
        return asm("inc",dst,src,False,False)
    elif(op == 18):
        return asm("dec",dst,src,False,False)
    elif(op == 19):
        return asm("and",dst,src,False,False)
    elif(op == 20):
        return asm("or",dst,src,False,False)
    elif(op == 21):
        return asm("xor",dst,src,False,False)
    elif(op == 22):
        return asm("mod",dst,src,False,False)
    elif(op == 23):
        return asm("cmp",dst,src,False,False)
    elif(op == 24):
        return asm("cmpb7",dst,src,False,False)
    elif(op == 25):
        return asm("jmp(!NF!ZF)",'',jmp_int_str_(src,op_size,pc),False,False)
    elif(op == 26):
        return asm("jmp(NF!ZF)",'',jmp_int_str_(src,op_size,pc),False,False)
    elif(op == 27):
        return asm("jmp(ZF)",'',jmp_int_str_(src,op_size,pc),False,False)
    elif(op == 28):
        return asm("jmp(!ZF)",'',jmp_int_str_(src,op_size,pc),False,False)
    elif(op == 29):
        return asm("jmp",'',jmp_int_str_(src,op_size,pc),False,False)
    elif(op == 30):
        return asm("call",'',jmp_int_str_(src,op_size,pc),False,False)
    print("FUCK")


def load_firm(filename):
    global firm_file
    with open(filename, 'rb') as f:
        firm_file = [ord(i) for i in (open(filename).read())]

def bit_concat(bit_list):
    res = 0
    for bit in bit_list:
        res <<= 7
        res += bit & 0b1111111
    return res


def read_memory_tri(addr, count):
    res = []
    for i in range(count):
        tri = 0
        tri |= firm_file[addr + i*3]
        tri |= firm_file[addr + i*3 + 1]  << 14
        tri |= firm_file[addr + i*3 + 2]  << 7
        res.append(tri)
    return res

def read_memory(addr, length):
    return firm_file[addr:addr+length]


def dispatch(addr):
    opcode = bit_concat(read_memory(addr, 2))
    op      = (opcode & 0b11111000000000) >> 9
    if op >= len(op_hander_table):
        print("[VM] Invalid instruction")

    op_type = (opcode & 0b00000100000000) >> 8
    opers   = []
    if  op_type == TYPE_R:
        opers.append((opcode & 0b00000011110000) >> 4)
        opers.append((opcode & 0b00000000001111))
        op_size = 2

    elif op_type == TYPE_I:
        opers.append((opcode & 0b00000011110000) >> 4)
        opers.append(read_memory_tri(addr+2, 1)[0])
        op_size = 5

    else:
        print("[VM] Invalid instruction")
        exit(1)

    return op, op_type, opers, op_size

load_firm('firm_chk')

pc = 0

while True:
    if(ret_chk or pc == 9):
        print("\nfunc_{0} : ".format(hex(pc)))
    op, op_type, opers, op_size =  dispatch(pc)
    print("\t"+hex(pc) + " : " + str(disasm(op, op_type, opers, op_size,pc)))
    pc+=op_size
    if(len(firm_file) <= pc):
        break
