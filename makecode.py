from pwn import *
from capstone import *
from keystone import *
from collections import namedtuple,defaultdict
import random
import copy
import ctypes
import lief
sys.setrecursionlimit(10**6)

md = Cs(CS_ARCH_X86, CS_MODE_32)
newblock = namedtuple("block", ["pred", "succ","bytecodelist","addr","succInst"])
instList = []
asmCodeChall = open("asm","rb").read()
OFF_TEXT = 0x00060
IMAGEBASE = 0x8048060
for i in md.disasm(asmCodeChall[OFF_TEXT:], IMAGEBASE):
    # print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    instList.append(i)
    if  i.mnemonic == "nop":
        break
blks = []
blk = newblock([],[],[],[],[])
i = 0
while i < len(instList):
    inst = instList[i]
    blk.bytecodelist.append(bytes(inst.bytes))
    blk.addr.append(inst.address)
    if inst.mnemonic == "jmp" or inst.mnemonic == "jne" or inst.mnemonic == "je":
        blk.succInst.append(inst)
        instnext = instList[i+1]
        if instnext.mnemonic == "jne" or instnext.mnemonic == "je" or instnext.mnemonic == "jmp":
            blk.succInst.append(instnext)
            blk.bytecodelist.append(bytes(instnext.bytes))
            blk.addr.append(instnext.address)
            i+=1

        blks.append(blk)
        blk = newblock([],[],[],[],[])
    i+=1
    if i == len(instList):
        blks.append(blk)


def populateBCode(l):
    tmp = b"" 
    for i in l:
        tmp+=i
    return tmp

for i in range(len(blks)): # populate address 
    blk = blks[i]
    blks[i] = newblock(blk.pred,blk.succ, populateBCode(blk.bytecodelist),blk.addr[0],blk.succInst)
def findBlkidxByAddress(address):
    for i  in range(len(blks)):
        bl = blks[i]
        if bl.addr == address:
            return i
VisitedBlk = []
def findSucc(blk):
    if len(blk.succInst) == 0:
        return blk
    if blk in VisitedBlk:
        return blk
    for i in blk.succInst:
        opst = int(i.op_str,16)
        indx = findBlkidxByAddress(opst)
        branch = findSucc(blks[indx])
        if branch != None:
            blk.succ.append(branch)
    VisitedBlk.append(blk)
    return blk
findSucc(blks[0])

def findpred(blk):
    if len(blk.succ) == 0:
        return blk
    for b in blk.succ:
        findpred(b)
        b.pred.append(blk)

findpred(blks[0])
        

        

## START FLATTEN ##
#pattern 1: pattern start->decrypt->jump

ks = Ks(KS_ARCH_X86, KS_MODE_32)

def pattern_joke(location_joke,addr_start_encrypted,addr_end_encrypted,key): 
    a,b = ks.asm(f"""
push edx
mov edx, {addr_end_encrypted - 1}

decrypt_addr:
xor BYTE PTR [edx],{key}
dec edx
cmp edx, {addr_start_encrypted}
jae decrypt_addr

pop edx
jmp {addr_start_encrypted}
""",addr=location_joke) #relocation
    return a
LEN_PATTERN_JOKE = 0x15

MAX_TEXT_SECTION = 0x4ade7 - 0x10
READONLY_MAX_TEXT_SECTION = MAX_TEXT_SECTION
BASE = lambda off: IMAGEBASE + off
OFF = lambda base: base - IMAGEBASE
encrypt = lambda code,key: (bytes([i^key for i in code]),key)

#("block", ["pred", "succ","bytecodelist","addr","succInst"])
##### STAGE ENCRYPT #####
newEncryptBlock = namedtuple("encryptBlock", ["NewBlk", "OrigBlk"])
pincodeKey = []
pincodeValue = []
PinnedRange = []
def allocInTextSection(size):
    global MAX_TEXT_SECTION
    base = size
    alignment = 3
    remainder = base % alignment
    padding = alignment - remainder

    ret = BASE(MAX_TEXT_SECTION - (base + padding))

    MAX_TEXT_SECTION -= (base + padding)
    if MAX_TEXT_SECTION <= 0:
        error("MAX TEXT SECTION")
    return ret
def patchEngine(blk,locationCurrentblk,EncrytedBlk,nSucc,):
    locationEncBlk = EncrytedBlk.NewBlk.addr
    asmCodeToPatch = ""
    for i in md.disasm(blk.bytecodelist, blk.addr):
        if i.mnemonic in [memonicstr.mnemonic for memonicstr in blk.succInst]:
            ifSuccGoto = int(i.op_str,16)
            if EncrytedBlk.OrigBlk.addr == ifSuccGoto:
                print(hex(locationEncBlk),hex(locationEncBlk),hex(locationEncBlk))
                asmCodeToPatch += f"{i.mnemonic} {locationEncBlk}\n"
                continue
        asmCodeToPatch += f"{i.mnemonic} {i.op_str}\n"
    
    return newblock(pred=blk.pred,succ=blk.succ,bytecodelist=bytes(ks.asm(asmCodeToPatch,addr=locationCurrentblk)[0]),addr=locationCurrentblk,succInst=blk.succInst)
def Decomp(blkkkk):
    print(blkkkk.bytecodelist)
    for i in md.disasm(blkkkk.bytecodelist, blkkkk.addr):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    
def MakeJokeFlow(currentBlk):  
    if currentBlk in pincodeKey:
        for i in range(len(pincodeKey)):
            if pincodeKey[i] == currentBlk:
                return pincodeValue[i]
    prepareBlk = currentBlk
    locationCurrentBlk = allocInTextSection(len(currentBlk.bytecodelist) + 16)
    newbranch = []
    for i in range(len(currentBlk.succ)):
        encryptedBlock = MakeJokeFlow(currentBlk.succ[i])
        print("not patch:")
        Decomp(prepareBlk)
        prepareBlk = patchEngine(prepareBlk,locationCurrentBlk,encryptedBlock,len(currentBlk.succ))
        print("patched:")
        Decomp(prepareBlk)
        newbranch.append(encryptedBlock.NewBlk)
    
    enc,key = encrypt(prepareBlk.bytecodelist,random.randrange(20,255))

    locationJoke = allocInTextSection(LEN_PATTERN_JOKE)
    
    decJokeBytecode = pattern_joke(locationJoke,locationCurrentBlk,locationCurrentBlk + len(enc),key)

    blkenc = newblock(pred=[],succ=newbranch,bytecodelist=enc,addr=locationCurrentBlk,succInst=[])
    blkdec = newblock(pred=[],succ=[blkenc],bytecodelist=decJokeBytecode,addr=locationJoke,succInst=[])
    
    for _ in range(random.randrange(100,127)):
        enc,key = encrypt(blkdec.bytecodelist,random.randrange(20,255))

        locationJoke = allocInTextSection(LEN_PATTERN_JOKE)
        locationCurrentBlk = blkdec.addr

        decJokeBytecode = pattern_joke(locationJoke,locationCurrentBlk,locationCurrentBlk + len(enc),key)
        
        blkenc = newblock(pred=[],succ=blkdec.succ,bytecodelist=enc,addr=locationCurrentBlk,succInst=[])
        blkdec = newblock(pred=[],succ=[blkenc],bytecodelist=decJokeBytecode,addr=locationJoke,succInst=[])

    retblk = newEncryptBlock(blkdec,currentBlk) # note is visited 
    pincodeKey.append(currentBlk)
    pincodeValue.append(retblk)
    # pincode[currentBlk] = retblk
    return retblk
    
newflow = MakeJokeFlow(blks[0])

#### DUMP CHALLENGE ####
asmCodeChall = [i for i in asmCodeChall]
for i in range(READONLY_MAX_TEXT_SECTION):
    asmCodeChall[OFF_TEXT + i] = 0x90
VisitedBlk = []
def DumpCode(blk):
    if blk in VisitedBlk:
        return 
    for i in range(len(blk.bytecodelist)):
        asmCodeChall[OFF_TEXT + OFF(blk.addr) + i] = blk.bytecodelist[i]
    VisitedBlk.append(blk)
    for b in blk.succ:
        DumpCode(b)
DumpCode(newflow.NewBlk)
a =open("FinalChall.bin","wb")
a.write(bytes(asmCodeChall))
a.close()

print(f"EntryPoint in {hex(newflow.NewBlk.addr)}")

p = lief.parse("./FinalChall.bin")
p.header.entrypoint = newflow.NewBlk.addr
p.write("Flatten.elf")