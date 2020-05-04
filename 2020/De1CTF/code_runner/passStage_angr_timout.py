from angr import *
from z3 import *
from pwn import hexdump
import subprocess

FILENAME = None
passcode = []
stage = len(passcode) / 4


def getcalcfunctions() :
    p = Project(FILENAME, load_options={'auto_load_libs': False})
    cfg = p.analyses.CFGFast()
    startidx = -1
    endidx = -1
    result = []
    for idx,i in enumerate(p.kb.functions.items()) :
        if i[1].name == '_init' : 
            startidx = idx + 13
        if i[1].name == 'main' : 
            endidx = idx - 6
    
    for i in range(startidx,endidx+1) :
        result.append(p.kb.functions.items()[i])
    
    return result


def getfunctiondisassembly(startaddress) : 
    get = subprocess.check_output("mips-linux-gnu-objdump -d ./{0} --start-address={1}".format(FILENAME,hex(startaddress)),shell=True)
    get = map(str.strip,get.split("\n"))
    for i in range(len(get)) : 
        if "jr\tra" in get[i] : 
            return get[6:i]
    

def parse_idx_condition(func) : 
    blocks = func[1].blocks #arrange

    disasmfunc = getfunctiondisassembly(func[0])
    
    startchk = False
    breakchk = False
    result = []
    conditions = []
    cond_idx = 0

    lwchk = False
    slt = False

    for line in disasmfunc :
        if len(line.split("\t")) < 2 : continue

        inst = line.split("\t")[2]

        if len(line.split("\t")) > 3 : 
            inst2 = line.split("\t")[3]
            parts = map(str.strip,inst2.split(","))

        
        if inst[0] == 'b' : 
            if cond_idx == 2 or cond_idx == 5 : 
                cond = ""
                if "beq" in inst : cond = "LT"
                elif "bne" in  inst : cond = "LE"
                if cond == "" :
                    print line
                    exit(1)
                conditions.append(cond)
            cond_idx += 1

        if inst == "lw" and len(result) < 8: 
            lwchk = True
            continue

        if inst == "addiu" and lwchk :
            #print pars
            try : 
                num = int(parts[2])
                if num >= 4 :
                    continue
                result += [num]
            except : 
                continue

        elif inst == "lbu" and lwchk:
            result += [0]
        
        lwchk = False 

        if len(result) == 8 and len(conditions) == 2 : # [0,0,1,1] rest [2,2,0,0]
            breakchk = True
            break

    final = []

    for i in result : 
        if i not in final :
            final.append(i)
        
    return final ,conditions


def idxsolver(idxs,conditions) : 
    pbParm1 = []
    pbParm1.append(BitVec("a1",32))
    pbParm1.append(BitVec("a2",32))
    pbParm1.append(BitVec("a3",32))
    pbParm1.append(BitVec("a4",32))

    s = Solver()

    for pb in pbParm1 : 
        s.add(pb <= 0xff)
        s.add(pb >= 0)

    iVar1 = pbParm1[idxs[0]] * pbParm1[idxs[0]] - pbParm1[idxs[1]] * pbParm1[idxs[1]]
    iVar1 = If(iVar1 < 0 , -iVar1 , iVar1)

    iVar2 = pbParm1[idxs[2]] * pbParm1[idxs[2]] - pbParm1[idxs[3]] * pbParm1[idxs[3]]
    iVar2 = If(iVar2 < 0 , -iVar2 , iVar2)

    if conditions[0] == "LT" :
        s.add(iVar1 < iVar2)
    elif conditions[0] == "LE" :
        s.add(iVar2 <= iVar1)

    iVar3 = pbParm1[idxs[2]] * pbParm1[idxs[2]] - pbParm1[idxs[0]] * pbParm1[idxs[0]];
    iVar3 = If(iVar3 < 0 , -iVar3 , iVar3)

    iVar4 = pbParm1[idxs[3]] * pbParm1[idxs[3]] - pbParm1[idxs[1]] * pbParm1[idxs[1]];
    iVar4 = If(iVar4 < 0 , -iVar4 , iVar4)

    if conditions[1] == "LT" :
        s.add(iVar3 < iVar4)
    elif conditions[1] == "LE" :
        s.add(iVar4 <= iVar3)

    #s.add(iVar4 <= iVar3)

    s.check()

    m = s.model()
    result = []

    for i in range(4) : 
        result.append(int(str(m.evaluate(pbParm1[i]))))
    
    return result
    


def hook(s) : 
    global passcode
    for i,c in enumerate(passcode) :
        if c != None : 
            s.mem[s.regs.v0+i].byte = chr(c)

def run(functions) :
    global passcode
    global stage
    
    for func in functions[stage+1:] : 
        print("[*] %s -> %s "%(hex(functions[stage][0]),hex(func[0])))
        print "current passcode : " + str(passcode)

        if(functions[stage][1].size > 600) : 
            idxs,condition = parse_idx_condition(functions[stage])
            print("[*] idx : " + str(idxs))
            passcode += idxsolver(idxs,condition)
            stage += 1
            continue

        p = Project(FILENAME, load_options={'auto_load_libs': False})

        p.hook(functions[0][0],hook)

        state = p.factory.blank_state()
        simgr = p.factory.simgr(state)
        simgr.one_active.options.add(options.LAZY_SOLVES)
        simgr.explore(find=func[0])

        get = simgr.found[0].state.posix.dumps(0)

        for i in range(4) : 
            if(stage*4+i >= len(passcode)) :
                passcode.append(None)

            if(passcode[stage*4+i] == None) : 
                passcode[stage*4+i] = ord(get[stage*4+i])

        stage += 1

def getpasscode(filename) : 
    global FILENAME
    FILENAME = filename
    stages = getcalcfunctions()[::-1]
    run(stages)
    return passcode
