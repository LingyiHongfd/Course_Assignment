#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net.h>
#include <net/ip.h>
#include <linux/if_ether.h>
#include <net/protocol.h>
#include <net/icmp.h>
#include <net/tcp.h>
#include <linux/if_vlan.h>
#include <linux/inet.h>
#include <linux/types.h>

/* This is the structure we shall use to register our function */
static struct nf_hook_ops nfho;
/* This is the hook function itself */
unsigned int hook_func(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state)
{
    /* This is where you can inspect the packet contained in
the structure pointed by skb, and decide whether to accept
or drop it. You can even modify the packet */
    // In this example, we simply drop all packets
    struct iphdr *ip;
    struct tcphdr *tcp;

    if (!skb)
        return NF_ACCEPT;

    ip = ip_hdr(skb);

    // telnet from A to B
    if (ip->daddr == in_aton("10.0.2.4") && ip->saddr == in_aton("10.0.2.5"))
    {
        tcp = (struct tcphdr *)(ip + 1);
        if (ntohs(tcp->source) != 23 || ntohs(tcp->dest) != 23) // drop telnet
            return NF_DROP;
    }
    if (ip->daddr == in_aton("10.0.2.4") && ip->saddr == in_aton("47.95.164.112"))
    {
        //tcp = (struct tcphdr *)(ip + 1);
        //if (ntohs(tcp->source) != 23 || ntohs(tcp->dest) != 23) // drop telnet
        return NF_DROP;
    }

    return NF_ACCEPT; /* Drop ALL packets */
}
/* Initialization routine */
int init_module()
{                                       /* Fill in our hook structure */
    nfho.hook = hook_func;              /* Handler function */
    nfho.hooknum = NF_INET_PRE_ROUTING; /* First hook for IPv4 */
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST; /* Make our function first */
    nf_register_hook(&nfho);
    return 0;
}
/* Cleanup routine */
void cleanup_module()
{
    nf_unregister_hook(&nfho);
}
