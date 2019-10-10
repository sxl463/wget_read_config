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

def countImplicitFlow(file):
    
    with open(file, "r") as implicit_file:
        lines = implicit_file.readlines()

	# key: global_addr value: inst_addr
	for line in lines:
		dict[line.split()[1][1:]] = 0


	for line in lines:
		dict[line.split()[1][1:]] += 1
	for key in dict:
		print key + " " + str(dict[key])

    with open("wget_read_config.g", "r") as flow_file:
	lines = flow_file.readlines()


    with open("implicit_flow.out", "w") as output:
	print "open implicit_flow.out for output"
	
	for key in dict:
		if key.startswith('4'):
			continue
		for line in lines:
			if line.find(key) > 0 and line.find(".c") > 0:
				newline = line[:-1] + " leak: " + str(dict[key]) + "\n"
				output.write(newline)
				break



#	print "==================="
#	for key in dict:
#		print key + " : " + dict[key]

#    new_buf = []

'''
    flow_lines = []
    with open("wget_sock_read.g", "r") as flow_file:
    	flow_lines = flow_file.readlines()

    	for line in flow_lines:
		for key in dict:
	#	    print "$:" + value
	    		if line.find(dict[key]) > 0:
				print dict[key]
				print line


    with open(file, "r") as out_file:
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
'''


print "Enter the location of the files: "; 
directory = os.getcwd()

path = r"%s" % directory


def main():
	print("In main:\n")
	countImplicitFlow("implicit.log")

if __name__ == '__main__':
	main()

'''
for file in os.listdir(path):
    if file.endswith(".global_write"):
        current_file = os.path.join(path, file)
        print current_file
        getFlowToGlobals(file)

    else:
        continue

'''


