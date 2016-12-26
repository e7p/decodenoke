#!/usr/bin/env python3
"""Noke decoding script by e7p

Usage: python decodenoke.py <file.txt>

This script expects a textfile containing a data dump in something like the
following format (each line is one packet to or by the noke):

01bd41ef9564fdc79bafdea1da064742
d5298a7bb219f081c52522a9f96db16400
a4fd46f750c37b7bf55d3144e3f09193
c606d3f9f770b9857778f7e7dfccd02600

Be assured that the script does use only the first 16 hex-encoded bytes of
every single line

This program is free to use. The python Module python-crypto is required."""
from Crypto.Cipher import AES
from binascii import hexlify,unhexlify
import sys
import os.path

key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

types = {
	1: "SESSIONSTART",
	2: "SESSIONSTARTCONF",
	4: "REKEY",
	6: "UNLOCK",
	7: "UNLOCKREPLY",		# self named
	8: "GETBATTERY",
	9: "GETBATTERYREPLY",	# self named
	10: "SETQUICKCODE",
	12: "RESETLOCK",
	14: "FIRMWAREUPDATE",
	16: "ENABLEPAIRFOB",
	18: "PAIRFOB",
	20: "GETLOGS",
	23: "REMOVEFOB",
	25: "GETONETIMEQC",
	28: "TESTMODE",
	30: "FOBUNLOCK",
	32: "ENABLEFOBS",
	34: "ENABLEONETIMEQC",
	36: "ENABLEQUICKCLICK",
	38: "REMOVEFOBCODE",
	40: "SETFOBCODE",
	42: "GETLOCKSFROMFOB",
	45: "GETFOBCODES",
	48: "REMOVELOCKFROMFOB"
}

def main():
	aes = AES.new(key, AES.MODE_ECB)
	nonce1 = b'\x00\x00\x00\x00'
	nonce2 = b'\x00\x00\x00\x00'
	packetcnt = 1
	
	if len(sys.argv) != 2 or not os.path.isfile(sys.argv[1]):
		print(__doc__)
		sys.exit(1)
	with open(sys.argv[1], 'r') as f:
		for line in f:
			print("== packet " + str(packetcnt) + " ==")
			packetcnt = packetcnt + 1
			cipher = bytes(unhexlify(line[:32]))
			message = aes.decrypt(cipher)
			if message[0] != 0x7e:
				# try again with new start key...
				aes = AES.new(key, AES.MODE_ECB)
				message = aes.decrypt(cipher)
				if message[0] != 0x7e:
					raise Exception("message seems to be undecryptable by " +
						"this tool")
			print(str(hexlify(message)))

			length = message[1]
			if length > 16 or length < 4:
				raise Exception("length of the message is expected to be " +
					"less than 16 and at least 4 bytes in total")
			cksum = 0
			for i in range(0,length-1):
				cksum = (cksum + message[i]) % 256
			if message[length-1] != cksum:
				raise Exception("data has a wrong checksum...")
			type = message[2]
			data = message[3:length-1]
			print("type: " + types[type] + " (" + str(type) + ")\ndata: " +
				str(hexlify(data)))

			desc = "<<< unknown"
			if type == 1: #SESSIONSTART
				nonce1 = data
				nonce2 = b'\x00\x00\x00\x00'
				desc = "nonce1 set"
			elif type == 2: #SESSIONSTARTCONF
				nonce2 = data
				xornonce = bytes([a ^ b for a,b in zip(nonce1,nonce2)])
				newkey = bytes(key[0:5]) + bytes([(a + b) % 256 for a, b in
					zip(key[5:9], xornonce)]) + bytes(key[9:16])
				aes = AES.new(newkey, AES.MODE_ECB)
				desc = "nonce2 set and switch to new key"
			elif type == 6: #UNLOCK
				desc = "data contains lock key"
			elif type == 7: #UNLOCKREPLY
				desc = "no data expected"
			elif type == 8: #GETBATTERY
				desc = "no data expected"
			print("description: " + desc + "\n")

if __name__ == "__main__":
    main()