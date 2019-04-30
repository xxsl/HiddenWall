import os
import yaml
import argparse

def banner():
 reset='\033[0m'
 yellow='\033[93m'
 cyan='\033[36m'
 orange='\033[33m'
 print("\n\t"+yellow+"...:::-> HiddenWall <-:::...\n"+cyan+" Linux kernel module generator for custom use with netfilter\n\t  version 0.1, coded by CoolerVoid\n")
 print("                    ,-,-")      
 print("                   / / |")      
 print(" ,-'             _/ / / ")      
 print("(-_          _,-' `Z_/  ")        
 print("   #:      ,-'_,-.   \  _ ")    
 print("   #'    _(_-'_()\    \" |               1")   
 print(" ,--_,--'                 |             101")
 print("/ ""                      L-'\          10001")
 print("\,-V--v-----._        /   \ \\         1000001") 
 print("  \_________________,-'       \\ 1    100000001") 
 print("                   \          \\0001 10000000001")  
 print("                    \         \\00001000000000011")        
 print(yellow+"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"+reset)                               
 print (reset+"\n---\nExample to use:\n")
 print ("\t"+orange+"python3 WallGen.py --template template/hiddenwall.c --rules rules/server.yaml\n"+reset)
 print ("\n Explain:\n Default template is \"wall.c\".\n The template file \"hiddenwall.c\" is a hidden module with netfilter.")
 print (cyan+"\n github.com/CoolerVoid/HiddenWall\n....\n"+reset)

def arguments():
 parser = argparse.ArgumentParser(description = banner())
 parser.add_argument('-t', '--template', action = 'store', dest = 'template_filename', default="template/wall.c",required = False, help = 'Source code template at directory template')
 parser.add_argument('-r', '--rules', action = 'store', dest = 'rules_filename', default="rules/server.yaml", required = True, help = 'Netfilter rules to create a kernel module, look directory rules')
 args = parser.parse_args()
 if args.template_filename:
  if os.path.isfile(args.template_filename):
   if os.path.isfile(args.rules_filename):
    return args.template_filename,args.rules_filename
   else:
    print ('File rules does not exist!')
  else:
   print ('File template does not exist!')
   exit(1)
 else:
  parser.print_help()

def Get_config(ConfigFile):
 d={}
 e={}
 d['whitelist_code']=""
 d['whitelist_var']=""
 document = open(ConfigFile, 'r')
 parsed = yaml.load(document, Loader=yaml.FullLoader)
 x=0
 print("Load external config "+ConfigFile)

# load external config at file "config.yaml"
 for key,value in parsed.items():
  if key == "module_name":
   d['module_name']=str(value)
  if key == "public_ports":
   d['public_ports']=str(value)
   list_ports_open=d['public_ports'].split(",")
   d['open_port_count']=str(len(list_ports_open))
  if key == "unhide_key":
   d['unhide_key']=str(value)
  if key == "hide_key":
   d['hide_key']=str(value)
  if key == "fake_device_name":
   d['fake_device_name']=str(value)
  if key == "liberate_in_2_out":
   d['liberate_in_2_out']=value
  if key == "whitelist":
   e=value
# construct code for liberate port for each whitelisted IP
 for v in e:
  code01=""
  x+=1
  print ("Construct code for addr: "+v['machine']['ip']+" for ports: "+ str(v['machine']['open_ports'])+"\n---\n" )
  varname="var0"+str(x)
  code_var="\n\t char *"+varname+" = \""+v['machine']['ip']+"\"; \n"
  code01+="\t\t if((strncasecmp(saddr,"+varname+",16)==0)||(strncasecmp(daddr,"+varname+",16)==0))\n"
  strport=str(v['machine']['open_ports'])
  list_ports=strport.split(",")
  code01+="\t\t\t if( "
  for port in list_ports:
   code01+="dest_port == "+port+" || src_port == "+port+" ||"
  code01=code01[:-3]
  code01+=" )\n"
  code01+="\t\t\t\t return NF_ACCEPT;\n"
  d['whitelist_code']+=code01
  d['whitelist_var']+=code_var
  d['rule_liberate_in']="\t\tif(ip_hdr->saddr == *(unsigned int*)ip_address)\n\t\t\treturn NF_ACCEPT; \n" 

  print (code01+"\n---") 

 return d
