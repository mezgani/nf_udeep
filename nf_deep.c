#include <linux/kernel.h>                                                                                                                                                                            
#include <linux/module.h>                                                                                                                                                                            
#include <linux/netfilter.h>                                                                                                                                                                         
#include <linux/netfilter_ipv4.h>                                                                                                                                                                    
#include <linux/device.h>                                                                                                                                                                            
#include <linux/skbuff.h>                                                                                                                                                                            
#include <linux/udp.h>                                                                                                                                                                               
#include <linux/ip.h>      



#define LICENSE "GPLv3"
#define AUTHOR  "MEZGANI Ali <mezgani@nativelabs.org>";
#define DESC    "netfilter hooks module, personnal tiny fw and sensor"

#define SUCCESS 0

#define IPPROTO_UDP 17
#define DEBUG 1 


static struct nf_hook_ops nfho;   //net filter hook option struct
struct sk_buff *sock_buff;
struct udphdr *udp_header;        //udp header struct (not used)
struct iphdr *ip_header;          //ip header struct
struct device *d;


//For any packet, get the ip header and check the protocol field
//if the protocol number equal to UDP (17), log in var/log/messages
//default action of module to let all packets through

static unsigned int hook_func(unsigned int hooknum, 
                              struct sk_buff *skb, 
                              const struct net_device *in, 
                              const struct net_device *out, 
                              int (*okfn)(struct sk_buff *))
{

  sock_buff = skb;
  ip_header = (struct iphdr *)skb_network_header(sock_buff);    //grab network header using accessor
  
  if(!sock_buff) { return NF_ACCEPT;}
  if (ip_header->protocol==IPPROTO_UDP) {
    udp_header = (struct udphdr *)skb_transport_header(sock_buff);  //grab transport header

#if DEBUG > 0

	       
    //s_port = ((udp_header->source & 0xFF00) >> 8 | (udp_header->source & 0x00FF));
    //d_port = ((udp_header->dest & 0xFF00) >> 8 | (udp_header->dest & 0x00FF));
    printk(KERN_INFO "[debug] IN:%s LEN:%d TTL:%d ID:%d SPORT:%d DPORT:%d SRC:%d.%d.%d.%d DST:%d.%d.%d.%d \n",
	   skb->dev->name,skb->len,ip_header->ttl,ip_header->id,
	   udp_header->source, udp_header->dest,
	   NIPQUAD(ip_header->saddr),
	   NIPQUAD(ip_header->daddr));     
    
    //log we’ve got udp packet to /var/log/messages

#endif
    
    //return NF_DROP;
    return NF_ACCEPT;
  }
  return NF_ACCEPT;
  
}
 
static int __init init_main(void)
{
  nfho.hook = hook_func;
  nfho.hooknum = 1;
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FIRST;
  nf_register_hook(&nfho);
  return 0;
}
 
static void __exit cleanup_main(void)
{
  nf_unregister_hook(&nfho);     
}

module_init(init_main);
module_exit(cleanup_main);
MODULE_LICENSE(LICENSE);
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESC);
MODULE_VERSION("0.1");
