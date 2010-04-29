#include <linux/kernel.h>                                                                                                                                                   
#include <linux/module.h>                                                                                                                                                  
#include <linux/netfilter.h>                                                                                                                                               
#include <linux/netfilter_ipv4.h>                                                                                                                                          
#include <linux/device.h>                                                                                                                                                  
#include <linux/skbuff.h>                                                                                                                                                  
#include <linux/udp.h>                                                                                                                                                     
#include <linux/ip.h>      
#include <linux/net.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/unistd.h>
#include <asm/uaccess.h>
#include <linux/file.h>


#define LICENSE "GPLv3"
#define AUTHOR  "MEZGANI Ali <mezgani@nativelabs.org>";
#define DESC    "netfilter hooks module, personnal tiny fw and sensor"

#define SUCCESS 0

#define IPPROTO_UDP 17
#define DEBUG 1 
#define TOLOG 0
#define MAX  1024
#define RCFPROTO    210

#define LOGFILE "/var/log/udeep.log"

#define  TYPE_CHK     "check"   
#define  TYPE_DELETE  "delete"
#define  TYPE_ADD     "add"
#define  TYPE_MODIFY  "modify"
#define  TYPE_DISPLAY "display"
#define  TYPE_SUPER   "super"
#define  TYPE_BLOCK   "block"
#define  TYPE_PERMIT  "permi"


/*******************************
 *Remote control firewall header
 *******************************/

struct rcfhdr{
  /*  __be16 version;
  __be16 port;
  __be32 id;*/
  unsigned short int version;
  unsigned short int port;
  unsigned short int id;
  char mode[16];
  char comm[16];
  char data[64];
};





static struct nf_hook_ops nfho;   //net filter hook option struct
struct sk_buff *sock_buff;
struct udphdr  *udp_header;        //udp header struct (not used)
struct iphdr   *ip_header;          //ip header struct
struct rcfhdr  *rcf_header;
struct device  *d;





char  *readfile(char *filename, int position)
{
  char		*buffer;
  mm_segment_t	oldfs;
  int		bytes;

  struct file *filp;

  buffer = kmalloc(MAX, GFP_KERNEL);
  if (buffer==NULL) 
    return NULL;
	
  filp = filp_open(filename,00,O_RDONLY);
  if (IS_ERR(filp)||(filp==NULL))
    return NULL;  /* Or do something else */

  if (filp->f_op->read==NULL)
    return NULL;  /* File(system) doesn't allow reads */

  /* Now read MAX bytes from postion "position" */
  filp->f_pos = position;
  oldfs = get_fs();
  set_fs(KERNEL_DS);
  bytes = filp->f_op->read(filp,buffer,MAX,&filp->f_pos);
  set_fs(oldfs);
  return buffer;        
  /* Close the file */
  fput(filp);

}


int writefile(char *filename, char *buf, int len, int position)
{
  int writelen;
  mm_segment_t oldfs;
  struct file *filp;

  filp = filp_open(filename,00,O_WRONLY);
  if (IS_ERR(filp)||(filp==NULL))
    return -1;  /* Or do something else */


  if (filp->f_op->write == NULL)
    return -1;

  filp->f_pos = position;
  oldfs = get_fs();
  set_fs(KERNEL_DS);
  writelen = filp->f_op->write(filp, buf, len, &filp->f_pos);
  set_fs(oldfs);
  /* Close the file */
  fput(filp);
  return writelen;
}


/*For any packet, get the ip header and check the protocol field
 *if the protocol number equal to UDP (17), log in var/log/messages
 *default action of module to let all packets through
 *This inspection routines may decrease speed =) 
 */

static unsigned int hook_func(unsigned int hooknum, 
                              struct sk_buff *skb, 
                              const struct net_device *in, 
                              const struct net_device *out, 
                              int (*okfn)(struct sk_buff *))
{

  sock_buff = skb;
  ip_header = (struct iphdr *)skb_network_header(sock_buff);    //grab network header using accessor
  udp_header = (struct udphdr *)skb_transport_header(sock_buff);
  rcf_header = (struct rcfhdr *)(skb_transport_header(sock_buff)+sizeof(struct iphdr));
  //rcf_header = (struct rcfhdr *)(skb_transport_header(sock_buff)+sizeof(struct udphdr)+sizeof(struct iphdr));

  __be16 sport;
  __be16 dport;

  // __be32 saddr, daddr;
  
  if(!sock_buff) { return NF_ACCEPT;}

  //Working on IPv4 only
  if(ip_header->version == 6) { return NF_DROP;}

  if (ip_header->protocol==IPPROTO_UDP)  {
    udp_header = (struct udphdr *)skb_transport_header(sock_buff);  //grab transport header

    sport = ntohs((unsigned int) udp_header->source);
    dport = ntohs((unsigned int) udp_header->dest);
    printk(KERN_INFO "[udeep] debug IN:%s LEN:%d TTL:%d ID:%d SPORT:%d DPORT:%d SRC:%d.%d.%d.%d DST:%d.%d.%d.%d \n",
	   skb->dev->name,
	   skb->len,
	   ip_header->ttl,
	   ip_header->id,
	   sport, dport,
	   NIPQUAD(ip_header->saddr),
	   NIPQUAD(ip_header->daddr));     

#if DEBUG > 0

    
    //s_port = ((udp_header->source & 0xFF00) >> 8 | (udp_header->source & 0x00FF));
    //d_port = ((udp_header->dest & 0xFF00) >> 8 | (udp_header->dest & 0x00FF));
    printk(KERN_INFO "network: 0x%p transport: 0x%p application: 0x%p\n",ip_header,udp_header,rcf_header);
    //printk(KERN_INFO "[udeep] debug: transport start: 0p%p\n", rcf_header);
    //printk(KERN_INFO "[udeep] debug: network   start: 0p%p\n", skb_network_header(sock_buff));
    printk(KERN_INFO "[udeep] debug: Length: rcf_header=%d | version=%d |  port=%d | comm=%d | data=%d\n",
	   sizeof(rcf_header), 
	   sizeof(rcf_header->version), 
	   sizeof(rcf_header->port), 
	   sizeof(rcf_header->comm),
	   sizeof(rcf_header->data));
    /*    printk(KERN_INFO "[udeep] debug: Length: rcf_header=%d | version=%d |  port=%d | comm=%s | data=%s\n",
	   sizeof(rcf_header), 
	   ntohs(rcf_header->version), 
	   ntohs(rcf_header->port), 
	   ntohs(rcf_header->comm),
	   ntohs(rcf_header->data));*/

    printk(KERN_INFO "[udeep] debug: Length: version=%d port=%d comm=%s mod=%s data=%s\n",
	   ntohs(rcf_header->version), ntohs(rcf_header->port), rcf_header->comm, rcf_header->mode, rcf_header->data);

    
#endif


    
#if TOLOG > 0
    int len=0, pos=0;
    //char *file="/var/log/udeep.log";
    char *file=LOGFILE;
    char *buffer, *log=NULL;
    
    buffer = kmalloc(MAX, GFP_KERNEL);

    sprintf(log, "network: 0x%p transport: 0x%p application: 0x%p\n",ip_header,udp_header,rcf_header);
    sprintf(log, "[udeep] debug: Length: rcf_header=%d | version=%d |  port=%d | comm=%d | data=%d\n",
	   sizeof(rcf_header), 
	   sizeof(rcf_header->version), 
	   sizeof(rcf_header->port), 
	   sizeof(rcf_header->comm),
	   sizeof(rcf_header->data));

    sprintf(log,"[udeep] debug: Length: version=%d port=%d comm=%s mod=%s data=%s\n",
	   ntohs(rcf_header->version), ntohs(rcf_header->port), rcf_header->comm, rcf_header->mode, rcf_header->data);
    
    buffer=readfile(file, 0);
    if (buffer > 0){
      pos=strlen(buffer);
      len=writefile(file, log, strlen(log), pos);
    }
#endif

    /**
    
    switch (ntohs(rcf_header->comm)) {
  case TYPE_CHK:
    break;
  case TYPE_DELETE:
    break;
  case TYPE_ADD:
    break;
  case TYPE_DISPLAY:
    break;
  case TYPE_SUPER:
    break;
  case TYPE_SBLOCK:
    break;

  default:
    printk(KERN_ALERT, "WARNING: encountered unexpected type %d\n",
	ntohs(ce->type));
  }
    **/

    
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
MODULE_PARM_DESC(key, "interior");
