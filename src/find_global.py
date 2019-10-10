#!/usr/bin/python

## Open the file with read only permit
#f = open('auth.S')

## Read the first line 
#line = f.readline()

## If the file is not empty keep reading line one at a time
## till the file is empty


import sys
# regular expressions
import re
import os
import fileinput

#\s+ : all white spaces ' '|\f|\t|\n|\v|\r
#patternRET = re.compile("\s+"+"ret"+"[a-z\s+]?\n")
#patternMOV = re.compile("\s+"+"mov"+"[a-z\s+]?%*,*(e[bs]p)")

#mov movl movb movsbl
#patternMOV = re.compile("\s+"+"mov." + "eax")


#%eax,0x[a-z0-9A-Z]+
'''
for line in fileinput.input():
    print line
'''

'''
while line:
    print line
    line = f.readline()
f.close()
'''

dict = {}

def findMovToGlobals(file):
    
    with open(file, "r") as in_file:
        buf = in_file.readlines()

    new_buf = []

    with open(file+".global_write", "w") as out_file:
	mustinclude = ["mov", "eax", "0x"]
        for line in buf:
            if line.find("mov") > 0 and line.find("eax") > 0 and line.find("0x") > 0 and line.find("(") < 0 and line.find("$") < 0: 
		iaddr = line[1:8]
		gaddr = line.rsplit(',', 1)[1][2:9]		
                if len(gaddr) > 6:
                	print line
			dict[gaddr] = iaddr
			print gaddr + ":" + dict[gaddr]
                        new_buf.append(gaddr+" "+dict[gaddr] + '\n');			
	print "global_addr: instruction"

        out_file.write("global_addr inst_addr\n")
        for line in new_buf:
            out_file.write(line)



print "Enter the location of the files: "; 
directory = os.getcwd()

path = r"%s" % directory

for file in os.listdir(path):
    if file.endswith(".asm"):
        current_file = os.path.join(path, file)
        print current_file
        findMovToGlobals(file)

    else:
        continue



'''                
            elif patternMOV.match(line):
                print line
                candidate_reg = re.search('%(.+?),', line)
                if candidate_reg:
                    reg = candidate_reg.group(1)
                    print reg
                    new_buf.append('	not	%'+reg+'\n')
                    new_buf.append('	not	%'+reg+'\n');
                
            new_buf.append(line)
'''


