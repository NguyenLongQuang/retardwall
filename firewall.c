#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/string.h>
#include <linux/if_ether.h>
#include <linux/jiffies.h>

#define NETLINK_USER 31
#define MAX_BLOCKED_IPS 256
#define MSG_ADD_IP 1
#define MSG_GET_LIST 2
#define MSG_UNBLOCK_IP 3
#define MSG_SET_RATE 4

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Retardwall");
MODULE_DESCRIPTION("Simple Firewall with Rate Limiting");

static struct sock *nl_sock = NULL;
static struct nf_hook_ops nfho;

// Structure to hold IP and MAC information with rate limiting
struct ip_entry {
    struct list_head list;
    uint32_t ip;
    unsigned char mac[ETH_ALEN];
    bool is_blocked;
    unsigned long last_seen;
    
    // Rate limiting fields
    unsigned long rate_limit;     // bytes per second
    unsigned long bytes_consumed; // bytes consumed in current window
    unsigned long window_start;   // start of current window
};

// List head for our IP entries
static LIST_HEAD(ip_list);
static DEFINE_SPINLOCK(ip_list_lock);

static struct ip_entry *find_ip_entry(uint32_t ip)
{
    struct ip_entry *entry;
    
    list_for_each_entry(entry, &ip_list, list) {
        if (entry->ip == ip)
            return entry;
    }
    return NULL;
}

static void update_ip_entry(uint32_t ip, unsigned char *mac)
{
    struct ip_entry *entry;
    
    spin_lock(&ip_list_lock);
    entry = find_ip_entry(ip);
    
    if (!entry) {
        entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
        if (entry) {
            entry->ip = ip;
            entry->is_blocked = false;
            entry->rate_limit = 0;  // No rate limit by default
            entry->bytes_consumed = 0;
            entry->window_start = jiffies;
            memcpy(entry->mac, mac, ETH_ALEN);
            entry->last_seen = jiffies;
            list_add(&entry->list, &ip_list);
        }
    } else {
        memcpy(entry->mac, mac, ETH_ALEN);
        entry->last_seen = jiffies;
    }
    spin_unlock(&ip_list_lock);
}

// Check and update rate limit for an IP
static bool check_rate_limit(struct ip_entry *entry, size_t packet_size)
{
    unsigned long now = jiffies;
    unsigned long window_size = HZ; // 1 second window
    
    if (!entry->rate_limit)
        return true;  // No rate limit set
        
    // Reset window if needed
    if (time_after(now, entry->window_start + window_size)) {
        entry->bytes_consumed = 0;
        entry->window_start = now;
    }
    
    // Check if adding this packet would exceed the rate limit
    if (entry->bytes_consumed + packet_size > entry->rate_limit)
        return false;
        
    entry->bytes_consumed += packet_size;
    return true;
}

static unsigned int hfunc(void *priv, struct sk_buff *skb, 
                         const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct ip_entry *entry;
    struct ethhdr *eth;
    
    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    eth = eth_hdr(skb);
    if (!eth)
        return NF_ACCEPT;

    update_ip_entry(iph->saddr, eth->h_source);

    spin_lock(&ip_list_lock);
    entry = find_ip_entry(iph->saddr);
    if (entry) {
        if (entry->is_blocked) {
            spin_unlock(&ip_list_lock);
            return NF_DROP;
        }
        
        // Check rate limit
        if (!check_rate_limit(entry, skb->len)) {
            spin_unlock(&ip_list_lock);
            return NF_DROP;
        }
    }
    spin_unlock(&ip_list_lock);
    
    return NF_ACCEPT;
}

// Structure for rate limit message
struct rate_limit_msg {
    uint32_t ip;
    unsigned long rate;
};

static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct ip_entry *entry;
    uint32_t ip;
    int msg_type;
    
    nlh = (struct nlmsghdr *)skb->data;
    msg_type = nlh->nlmsg_type;
    
    switch (msg_type) {
        case MSG_ADD_IP:
            ip = *(uint32_t *)NLMSG_DATA(nlh);
            
            spin_lock(&ip_list_lock);
            entry = find_ip_entry(ip);
            if (entry) {
                entry->is_blocked = true;
            }
            spin_unlock(&ip_list_lock);
            break;

        case MSG_UNBLOCK_IP:
            ip = *(uint32_t *)NLMSG_DATA(nlh);
            
            spin_lock(&ip_list_lock);
            entry = find_ip_entry(ip);
            if (entry) {
                entry->is_blocked = false;
            }
            spin_unlock(&ip_list_lock);
            break;
            
        case MSG_SET_RATE:
            {
                struct rate_limit_msg *rate_msg = NLMSG_DATA(nlh);
                
                spin_lock(&ip_list_lock);
                entry = find_ip_entry(rate_msg->ip);
                if (entry) {
                    entry->rate_limit = rate_msg->rate;
                    entry->bytes_consumed = 0;
                    entry->window_start = jiffies;
                }
                spin_unlock(&ip_list_lock);
            }
            break;
            
        case MSG_GET_LIST:
            {
                struct sk_buff *reply_skb;
                struct nlmsghdr *reply_nlh;
                struct ip_entry *curr_entry;
                void *data;
                int size = 0;
                
                list_for_each_entry(curr_entry, &ip_list, list) {
                    size += sizeof(uint32_t) + ETH_ALEN + sizeof(bool) + 
                           sizeof(unsigned long) * 2; // Added rate_limit
                }
                
                reply_skb = nlmsg_new(size, GFP_KERNEL);
                if (!reply_skb)
                    return;
                
                reply_nlh = nlmsg_put(reply_skb, 0, 0, NLMSG_DONE, size, 0);
                data = nlmsg_data(reply_nlh);
                
                spin_lock(&ip_list_lock);
                list_for_each_entry(curr_entry, &ip_list, list) {
                    memcpy(data, &curr_entry->ip, sizeof(uint32_t));
                    data += sizeof(uint32_t);
                    memcpy(data, curr_entry->mac, ETH_ALEN);
                    data += ETH_ALEN;
                    memcpy(data, &curr_entry->is_blocked, sizeof(bool));
                    data += sizeof(bool);
                    memcpy(data, &curr_entry->last_seen, sizeof(unsigned long));
                    data += sizeof(unsigned long);
                    memcpy(data, &curr_entry->rate_limit, sizeof(unsigned long));
                    data += sizeof(unsigned long);
                }
                spin_unlock(&ip_list_lock);
                
                nlmsg_unicast(nl_sock, reply_skb, NETLINK_CB(skb).portid);
            }
            break;
    }
}

// Rest of the code (init and exit functions) remains the same
static int __init firewall_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = nl_recv_msg,
    };
    
    nl_sock = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sock) {
        printk(KERN_ALERT "Error creating netlink socket.\n");
        return -1;
    }
    
    nfho.hook = hfunc;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    
    nf_register_net_hook(&init_net, &nfho);
    
    printk(KERN_INFO "Firewall module loaded\n");
    return 0;
}

static void __exit firewall_exit(void)
{
    struct ip_entry *entry, *tmp;
    
    nf_unregister_net_hook(&init_net, &nfho);
    
    if (nl_sock)
        netlink_kernel_release(nl_sock);
    
    list_for_each_entry_safe(entry, tmp, &ip_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    
    printk(KERN_INFO "Firewall module unloaded\n");
}

module_init(firewall_init);
module_exit(firewall_exit);