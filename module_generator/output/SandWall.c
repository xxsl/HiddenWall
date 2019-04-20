#define __KERNEL__
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
// at the future load ipv6 ? TODO
#include <linux/skbuff.h>

static struct nf_hook_ops netfilter_ops;
         
// Static IP localhost
static unsigned char *ip_address = "\x14\x00\x00\x03";

unsigned int main_hook( unsigned int hooknum, 
			struct sk_buff *skb, 
			const struct net_device *in, 
			const struct net_device *out, 
			int (*okfn)(struct sk_buff*))
{


	int whitelist[]={80,443,53};
	int i=0;

		if(!skb)
			return NF_ACCEPT; 

	struct iphdr *ip_hdr = (struct iphdr *)skb_network_header(skb);

		if(!(ip_hdr))  
			return NF_ACCEPT; 

		if(ip_hdr->protocol == IPPROTO_ICMP)
		{
			struct icmphdr *icmph;
			icmph = icmp_hdr(skb);

			if(!icmph) 
				return NF_ACCEPT; 

		  	if(ip_hdr->saddr == *(unsigned int*)ip_address) 
				return NF_ACCEPT; 

			if(icmph->type != ICMP_ECHOREPLY) 
				return NF_DROP; 
		}

		if(ip_hdr->protocol == IPPROTO_UDP)
		{
			struct udphdr *udph;
			udph = udp_hdr(skb);
			i=0;

				if(!udph)
					return NF_ACCEPT; 
		// 	if(ip_hdr->daddr == *(unsigned int*)ip_address) return NF_ACCEPT; 
				if(ip_hdr->saddr == *(unsigned int*)ip_address) 
					return NF_ACCEPT; 

			unsigned int dest_port = (unsigned int)ntohs(udph->dest);
			unsigned int src_port = (unsigned int)ntohs(udph->source);
			

				while(i!=3)
				{
					if(dest_port == whitelist[i] || src_port == whitelist[i])
						return NF_ACCEPT; 
					i++;
		
				}
		}

		if(ip_hdr->protocol == IPPROTO_TCP)
		{
		  	struct tcphdr *tcph;
		  	tcph = tcp_hdr(skb);
			i=0;

		  		if(!tcph)
					return NF_ACCEPT; 

			unsigned int dest_port = (unsigned int)ntohs(tcph->dest);
			unsigned int src_port = (unsigned int)ntohs(tcph->source);

		//	  	if(ip_hdr->daddr == *(unsigned int*)ip_address) return NF_ACCEPT; 
		  		if(ip_hdr->saddr == *(unsigned int*)ip_address)
					return NF_ACCEPT; 



			char saddr[16];
			snprintf(saddr,16,"%pI4",&ip_hdr->saddr);
			char daddr[16];
			snprintf(daddr,16,"%pI4",&ip_hdr->saddr);


 
			 char *var01 = "192.168.100.181"; 
				 if((strncasecmp(saddr,var01,16)==0)||(strncasecmp(daddr,var01,16)==0))
					 if( dest_port == 22 || src_port == 22 ||dest_port == 21 || src_port == 21 )
						 return NF_ACCEPT;

			 char *var02 = "192.168.100.22"; 
				 if((strncasecmp(saddr,var02,16)==0)||(strncasecmp(daddr,var02,16)==0))
					 if( dest_port == 22 || src_port == 22 )
						 return NF_ACCEPT;



				while(i != 3 )
				{
					if(dest_port == whitelist[i] || src_port == whitelist[i]) 
						return NF_ACCEPT; 

					i++;
		
				}

		}

	return NF_DROP;
}

int init_module()
{
        netfilter_ops.hook              =       main_hook;
        netfilter_ops.pf                =       PF_INET;
        netfilter_ops.hooknum           =       NF_INET_PRE_ROUTING;
        netfilter_ops.priority          =       NF_IP_PRI_FIRST;
        nf_register_hook(&netfilter_ops);
	return 0;
}
void cleanup_module() { nf_unregister_hook(&netfilter_ops); }
