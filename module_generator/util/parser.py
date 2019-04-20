import yaml

def Get_config(ConfigFile):
 d={}
 e={}
 d['whitelist_code']=""
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
  if key == "whitelist":
   e=value
# construct code for liberate port for each whitelisted IP
 for v in e:
  x+=1
  print ("Construct code for addr: "+v['machine']['ip']+" for ports: "+ str(v['machine']['open_ports'])+"\n---\n" )
  varname="var0"+str(x)
  code01="\n\t\t\t char *"+varname+" = \""+v['machine']['ip']+"\"; \n"
  code01+="\t\t\t\t if((strncasecmp(saddr,"+varname+",16)==0)||(strncasecmp(daddr,"+varname+",16)==0))\n"
  strport=str(v['machine']['open_ports'])
  list_ports=strport.split(",")
  code01+="\t\t\t\t\t if( "
  for port in list_ports:
   code01+="dest_port == "+port+" || src_port == "+port+" ||"
  code01=code01[:-3]
  code01+=" )\n"
  code01+="\t\t\t\t\t\t return NF_ACCEPT;\n"
  d['whitelist_code']+=code01
  print (code01+"\n---") 

 return d
