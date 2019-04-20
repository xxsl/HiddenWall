#!/usr/bin/python3

#You nd yaml, pyyaml modules... 
from util import parser

print("HiddenWall- Linux kernel module generator for custom use with netfilter\n\t\tversion 0.1\n \t\tcoded by CoolerVoid\n\n")

template_content=""
template_content2=""
souce=""

# load rules of firewall at directory rules
v=parser.Get_config("rules/server.yaml")

# Load templates
with open("template/wall.c") as f:
 content = f.readlines()

for line in content:
 template_content+=line

with open("template/Makefile") as f:
 content = f.readlines()

for line in content:
 template_content2+=line

print ("\n Generate Kernel module \n")

# replace macros in templates
source=template_content
source=source.replace("PUBLIC_PORTS",v['public_ports'])
source=source.replace("IP_WHITELISTED",v['whitelist_code'])
source=source.replace("PORTS_COUNT",v['open_port_count'])

source2=template_content2
source2=source2.replace("FILE_NAME",v['module_name'])

# save output
name_file="output/"+v['module_name']+".c"

file = open(name_file,"w") 
file.write(source) 
file.close()

file = open("output/Makefile","w") 
file.write(source2) 
file.close()

print ("Python Script end, please look the liunux custom kernel module at directory output/\n")

