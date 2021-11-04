#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops telnetFilterHook;

const char *MACHINE_A_IP = "10.0.2.6";
const char *MACHINE_B_IP = "10.0.2.5";
const char *EXAMPLE_DOT_COM_IP = "93.184.216.34";

const int PORT_TELNET = 23;
const int PORT_HTTP = 80;
const int PORT_SSH = 22;

// Task 2.1 Prevent A telnet to B
unsigned int telnetFilter_Task21(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;

    if (iph->protocol == IPPROTO_TCP && IPPROTO_TCP &&
        tcph->dest == htons(PORT_TELNET) &&
        strcmp((unsigned char *)&iph->saddr, MACHINE_A_IP) &&
        strcmp((unsigned char *)&iph->daddr, MACHINE_B_IP))
    {
        printk(KERN_INFO "POLICY: Dropping telnet packet to %d.%d.%d.%d\n",
               ((unsigned char *)&iph->daddr)[0],
               ((unsigned char *)&iph->daddr)[1],
               ((unsigned char *)&iph->daddr)[2],
               ((unsigned char *)&iph->daddr)[3]);

        return NF_DROP;
    }
    else
    {
        return NF_ACCEPT;
    }
}

// Task 2.2 Prevent B telnet to A
unsigned int telnetFilter_Task22(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;

    if (iph->protocol == IPPROTO_TCP && IPPROTO_TCP &&
        tcph->dest == htons(PORT_TELNET) &&
        strcmp((unsigned char *)&iph->daddr, MACHINE_A_IP) &&
        strcmp((unsigned char *)&iph->saddr, MACHINE_B_IP))
    {
        printk(KERN_INFO "POLICY: Dropping telnet packet from %d.%d.%d.%d\n",
               ((unsigned char *)&iph->saddr)[0],
               ((unsigned char *)&iph->saddr)[1],
               ((unsigned char *)&iph->saddr)[2],
               ((unsigned char *)&iph->saddr)[3]);
        return NF_DROP;
    }
    else
    {
        return NF_ACCEPT;
    }
}

// Task 2.3 Prevent A visit www.example.com
unsigned int telnetFilter_Task23(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;

    else if (iph->protocol == IPPROTO_TCP && IPPROTO_TCP &&
             tcph->dest == htons(PORT_HTTP) &&
             strcmp((unsigned char *)&iph->saddr, MACHINE_A_IP) &&
             strcmp((unsigned char *)&iph->daddr, EXAMPLE_DOT_COM_IP))
    {
        printk(KERN_INFO "POLICY: Dropping http packet to %d.%d.%d.%d\n",
               ((unsigned char *)&iph->daddr)[0],
               ((unsigned char *)&iph->daddr)[1],
               ((unsigned char *)&iph->daddr)[2],
               ((unsigned char *)&iph->daddr)[3]);
        return NF_DROP;
    }
    else
    {
        return NF_ACCEPT;
    }
}

// Task 2.4 Prevent A telnet to www.example.com
unsigned int telnetFilter_Task24(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;

    if (iph->protocol == IPPROTO_TCP && IPPROTO_TCP &&
        tcph->dest == htons(PORT_TELNET) &&
        strcmp((unsigned char *)&iph->saddr, MACHINE_A_IP) &&
        strcmp((unsigned char *)&iph->daddr, EXAMPLE_DOT_COM_IP))
    {
        printk(KERN_INFO "POLICY: Dropping telnet packet to %d.%d.%d.%d\n",
               ((unsigned char *)&iph->daddr)[0],
               ((unsigned char *)&iph->daddr)[1],
               ((unsigned char *)&iph->daddr)[2],
               ((unsigned char *)&iph->daddr)[3]);
        return NF_DROP;
    }
    else
    {
        return NF_ACCEPT;
    }
}

// Task 2.5 Prevent A SSH to B
unsigned int telnetFilter_Task25(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;

    if (iph->protocol == IPPROTO_TCP && IPPROTO_TCP &&
        tcph->dest == htons(PORT_SSH) &&
        strcmp((unsigned char *)&iph->saddr, MACHINE_A_IP) &&
        strcmp((unsigned char *)&iph->daddr, MACHINE_B_IP)))
        {
            printk(KERN_INFO "POLICY: Dropping ssh packet to %d.%d.%d.%d\n",
                   ((unsigned char *)&iph->daddr)[0],
                   ((unsigned char *)&iph->daddr)[1],
                   ((unsigned char *)&iph->daddr)[2],
                   ((unsigned char *)&iph->daddr)[3]);
            return NF_DROP;
        }
    else
    {
        return NF_ACCEPT;
    }
}

unsigned int telnetFilter_Task31(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;

    // Task 2.2 Prevent B telnet to A
    if (iph->protocol == IPPROTO_TCP && IPPROTO_TCP && tcph->source == htons(23) && strcmp((unsigned char *)&iph->saddr, MACHINE_A_IP))
    {
        printk(KERN_INFO "POLICY: Dropping telnet packet from %d.%d.%d.%d\n",
               ((unsigned char *)&iph->saddr)[0],
               ((unsigned char *)&iph->saddr)[1],
               ((unsigned char *)&iph->saddr)[2],
               ((unsigned char *)&iph->saddr)[3]);
        return NF_DROP;
    }
    // Task 2.3 Prevent A telnet to www.example.com
    else if (iph->protocol == IPPROTO_TCP && IPPROTO_TCP && tcph->dest == htons(80) && strcmp((unsigned char *)&iph->daddr, EXAMPLE_DOT_COM_IP))
    {
        printk(KERN_INFO "POLICY: Dropping http (TCP) packet to %d.%d.%d.%d\n",
               ((unsigned char *)&iph->daddr)[0],
               ((unsigned char *)&iph->daddr)[1],
               ((unsigned char *)&iph->daddr)[2],
               ((unsigned char *)&iph->daddr)[3]);
        return NF_DROP;
    }
    // Task 2.4 iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    // else if (iph->protocol == IPPROTO_TCP && IPPROTO_TCP && tcph->source == htons(80) && strcmp((unsigned char *)&iph->saddr, MACHINE_B_IP))
    // {
    //     printk(KERN_INFO "POLICY: Dropping http (TCP) packet to %d.%d.%d.%d\n",
    //            ((unsigned char *)&iph->daddr)[0],
    //            ((unsigned char *)&iph->daddr)[1],
    //            ((unsigned char *)&iph->daddr)[2],
    //            ((unsigned char *)&iph->daddr)[3]);
    //     return NF_DROP;
    // }
    // Task 2.5 iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    else
    {
        return NF_ACCEPT;
    }
}

unsigned int telnetFilter_Task32(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

int setUpFilter(void)
{
    printk(KERN_INFO "Registering a Telnet filter.\n ");
    telnetFilterHook.hook = telnetFilter_Task21;
    // telnetFilterHook.hook = telnetFilter_Task22;
    // telnetFilterHook.hook = telnetFilter_Task23;
    // telnetFilterHook.hook = telnetFilter_Task24;
    // telnetFilterHook.hook = telnetFilter_Task25;
    telnetFilterHook.hooknum = NF_INET_POST_ROUTING;
    telnetFilterHook.pf = PF_INET;
    telnetFilterHook.priority = NF_IP_PRI_FIRST;

    // Register the hook.
    nf_register_hook(&telnetFilterHook);
    return 0;
}

void removeFilter(void)
{
    printk(KERN_INFO "Telnet filter is being removed.\n");
    nf_unregister_hook(&telnetFilterHook);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
