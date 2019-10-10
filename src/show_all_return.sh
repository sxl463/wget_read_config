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

def getLinesWithReturn(file):
    with open(file, "r") as file_in:
        all_lines = file_in.readlines()
    i = 0
    for line in all_lines:
        i += 1
        if line.find("return") > 0 and (line.find('(') > 0 or line.find(')') > 0):
            print "{}:{}".format(i,line)


'''
def matchGlobalsInReadELF(file):
    
    with open(file, "r") as in_file:
        global_addrs = in_file.readlines()

    global_names = []

    print sys.argv[1] + ".symtbl"
    print "\n" + "------------------------------------------"
    with open(sys.argv[1]+".symtbl", "r") as symbol_table:
	symbols = symbol_table.readlines()

	for symbol in symbols:
		for line in global_addrs:
			gaddr = line.split(' ', 1)[0]			
			if symbol.find(gaddr) > 0:
				gname = symbol.split(' ')[-1][:-1]
				global_names.append(gname);
				
	
    with open(file+".global_list", "w") as out_file:

        for name in global_names:
	    print name
	    out_file.write(name+'\n')

            if line.find("mov") > 0 and line.find("eax") > 0 and line.find("0x") > 0 and line.find("(") < 0 and line.find("$") < 0: 
		iaddr = line[1:8]
		gaddr = line.rsplit(',', 1)[1][2:9]		
                if len(gaddr) > 6:
                	print line
			dict[gaddr] = iaddr
			print gaddr + ":" + dict[gaddr]
                        new_buf.append(gaddr+" "+dict[gaddr] + '\n');			
	print "global_addr: instruction"

        for line in new_buf:
            out_file.write(line)
'''


print "Enter the location of the files: "; 
directory = os.getcwd()

path = r"%s" % directory


for file in os.listdir(path):
    
    if file.endswith(".c"):
        print file
        current_file = os.path.join(path, file)
        getLinesWithReturn(current_file)

    else:
        continue




