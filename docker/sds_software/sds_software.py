#!/usr/bin/python3
from pwn import *
import binascii
import random

context.log_level = 'error'

class SDSSoftware:

    def __init__(self):
        self.ecm_id = "7e0"
        self.bcm_id = "7c0"

        self.flag = "RITCTF{vr00m_g03s_th3_c4r!!_52376241}"

        self.did = [
            b"LOWBOB-RONDO", #Author
            b"RITSEC",   # Brand
            b"2024", #Year
            b"1RITSEC15926Q2025",#VIN
            b"ritsec{FAKE_FLAG_IN_BCM_TOO}"
        ]
        self.response_template = "can0 {} [8] {}"
        self.candump_log = ""
        self.ecm_proc = None
        self.multiframe_data = ""
        self.bcm_state = 0

    def handle_cansend(self,command):
        args = command.split(" ")
        if len(args)<2:
            print("bad command")
            return
        ecu_id,data = args[1].split("#")
        data=data.strip()
        data=data.ljust(16,"0")
        unhex_data = binascii.unhexlify(data)[:8]
        byte_string = self.to_byte_string(unhex_data)
        response = self.response_template.format(str(ecu_id).upper(),byte_string)
        self.send_to_can(response)
        if ecu_id.lower() == self.ecm_id:
            self.ecm_proc.send(unhex_data)
            while True:
                can_resp = self.ecm_proc.readn(8,timeout=0.5)
                if can_resp==b"":
                    break
                byte_string = self.to_byte_string(can_resp)
                response = self.response_template.format(hex(int(self.ecm_id,16)+8).upper()[2:],byte_string)
                self.send_to_can(response)
        if ecu_id.lower() == self.bcm_id:
            if data.startswith("300000"):
                if self.multiframe_data != "":
                    idx = 1
                    i = 0
                    while i<len(self.multiframe_data):
                        can_resp = p8(0x20+idx)
                        can_resp += self.multiframe_data[i:i+7]
                        can_resp = can_resp.ljust(8,b"\x00")
                        byte_string = self.to_byte_string(can_resp)
                        response = self.response_template.format(hex(int(self.ecm_id,16)+8).upper()[2:],byte_string)
                        self.send_to_can(response)
                        i+=7
                        if idx==0xf:
                            idx=1
                        else:
                            idx+=1
                    self.multiframe_data=""
            elif not data.startswith("0224"):
                can_resp = b"\x03\x7f"+bytes([unhex_data[1]])+b"\x11"
                can_resp = can_resp.ljust(8,b"\x00")
                byte_string = self.to_byte_string(can_resp)
                response = self.response_template.format(hex(int(self.bcm_id,16)+8).upper()[2:],byte_string)
                self.send_to_can(response)
            else:
                index = unhex_data[2]
                if index<0 or index>4:
                    can_resp = b"\x03\x7f"+bytes([unhex_data[1]])+b"\x14"
                    can_resp = can_resp.ljust(8,b"\x00")
                    byte_string = self.to_byte_string(can_resp)
                    response = self.response_template.format(hex(int(self.bcm_id,16)+8).upper()[2:],byte_string)
                    self.send_to_can(response)
                else:
                    result = self.did[index]
                    length = len(result)
                    if length>6:
                        can_resp = b"\x10"+bytes([length]) + result[:6]
                        byte_string = self.to_byte_string(can_resp)
                        response = self.response_template.format(hex(int(self.bcm_id,16)+8).upper()[2:],byte_string)
                        self.multiframe_data = result[6:]
                    else:
                        byte_string = self.to_byte_string(bytes([length+1])+b"\x64"+result.ljust(6,b"\x00"))
                        response = self.response_template.format(hex(int(self.bcm_id,16)+8).upper()[2:],byte_string)
                    self.send_to_can(response)

    def handle_candump(self,command):
        if command=="candump clear":
            self.candump_log=""
        else:
            print(self.candump_log)

    def to_byte_string(self,s):
        return binascii.hexlify(s," ",1).decode()

    def send_to_can(self,data):
        self.candump_log += data
        self.candump_log += "\n"

    def handle_start_engine(self):
        old_log = self.candump_log
        self.handle_cansend("cansend 7e0#022002")
        self.candump_log=""
        self.handle_cansend("cansend 7e0#022403")
        self.handle_cansend("cansend 7e0#30")
        d = self.candump_log.split("\n")[1:]
        ecm_vin = binascii.unhexlify(d[0].strip()[19:].replace(" ",""))
        for x in d[2:]:
            ecm_vin += binascii.unhexlify(x.strip()[16:].replace(" ",""))
        ecm_vin = ecm_vin.strip(b"\x00")
        if ecm_vin == self.did[3]:
            print("VINs Match. Engine starts properly.")
            print("Flag: ",self.flag)
        else:
            print("VIN Mismatch. Engine fails to start.")
        self.candump_log=old_log

    def boot_ecm(self):
        self.ecm_proc = remote("192.168.112.3",5000)
        self.ecm_proc.readuntil(b"Starting ECU")
        self.ecm_proc.readline()
        lcg_state = random.randint(0, (1 << 32) - 1)
        self.ecm_proc.send(p32(lcg_state,endian='big').ljust(8,b"\x00"))

    def main_loop(self):
        print("SimpleDiagnosticService Software v1.0")
        self.boot_ecm()
        while True:
            command = input("> ")
            command = command.strip()
            if command == "help":
                print("help:...")
            elif command.startswith("cansend "):
                self.handle_cansend(command)
            elif command.startswith("candump"):
                self.handle_candump(command)
            elif command == "start_engine":
                self.handle_start_engine()
            elif command == "reboot":
                self.ecm_proc.close()
                self.boot_ecm()
                self.candump_log = ""
            else:
                print("Invalid command")

sds = SDSSoftware()
sds.main_loop()