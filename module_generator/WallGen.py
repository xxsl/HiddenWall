#!/usr/bin/python3
# WallGen v0.1
#You nd yaml, pyyaml modules... 
from util import parser
from util import file_op

template_filename=""
rules_filename=""
template_content=""
template_content2=""
source=""

# Get argvs of user's input
template_filename,rules_filename = parser.arguments()

# load rules of firewall at directory rules
v=parser.Get_config(rules_filename)

# Load content of templates
template_content=file_op.File_to_string(template_filename)
template_content2=file_op.File_to_string("template/Makefile")

print ("\n Generate Kernel module \n")

# replace macros in C module template
source=template_content
source=source.replace("PUBLIC_PORTS",v['public_ports'])
source=source.replace("IP_WHITELISTED",v['whitelist_code'])
source=source.replace("PORTS_COUNT",v['open_port_count'])
source=source.replace("UNHIDE_KEY",v['unhide_key'])
source=source.replace("HIDE_KEY",v['hide_key'])
source=source.replace("DEVICE_NAME",v['fake_device_name'])

print("Liberate IN to OUT rule mode: "+str(v['liberate_in_2_out']))
if(v['liberate_in_2_out']== True):
 source=source.replace("LIBERATE_IN_2_OUT",v['rule_liberate_in'])
else: 
 source=source.replace("LIBERATE_IN_2_OUT"," ")

# replace macro in Makefile
source2=template_content2
source2=source2.replace("FILE_NAME",v['module_name'])

# save output
name_file="output/"+v['module_name']+".c"
file_op.WriteFile(name_file,source)
file_op.WriteFile("output/Makefile",source2)

print ("Python Script end, please look the output your custom kernel module at directory output/\n")

