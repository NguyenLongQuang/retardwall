#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <argp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <time.h>
#include <stdbool.h>
#include <asm/param.h>

#define NETLINK_USER 31
#define MAX_PAYLOAD 1024
#define MSG_ADD_IP 1
#define MSG_GET_LIST 2
#define MSG_UNBLOCK_IP 3
#define MSG_SET_RATE 4

const char *argp_program_version = "firewall-cli 1.0";
const char *argp_program_bug_address = "<quang.nglong@email.com>";

static char doc[] = "Firewall CLI -- A command line interface for the kernel firewall module";

static struct argp_option options[] = {
    {"block",   'b', "IP",  0, "Block an IP address", 0 },
    {"unblock", 'u', "IP",  0, "Unblock an IP address", 0 },
    {"list",    'l', 0,     0, "List all IPs and their status", 0 },
    {"monitor", 'm', 0,     0, "Monitor IP list continuously", 0 },
    {"rate",    'r', "IP:RATE", 0, "Set rate limit for IP (bytes/sec)", 0 },
    { 0 }
};

struct arguments {
    char *ip;
    char *rate_str;
    int block;
    int unblock;
    int list;
    int monitor;
    int set_rate;
};

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
struct msghdr msg;
int sock_fd;

struct rate_limit_msg {
    uint32_t ip;
    unsigned long rate;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    switch (key) {
        case 'b':
            arguments->block = 1;
            arguments->ip = arg;
            break;
        case 'u':
            arguments->unblock = 1;
            arguments->ip = arg;
            break;
        case 'l':
            arguments->list = 1;
            break;
        case 'm':
            arguments->monitor = 1;
            break;
        case 'r':
            arguments->set_rate = 1;
            arguments->rate_str = arg;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, 0, doc, 0, 0, 0 };

void init_netlink(void)
{
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
}

void handle_ip(const char *ip_str, int msg_type)
{
    struct in_addr addr;
    
    if (inet_aton(ip_str, &addr) == 0) {
        printf("Invalid IP address format\n");
        return;
    }

    nlh->nlmsg_type = msg_type;
    memcpy(NLMSG_DATA(nlh), &addr.s_addr, sizeof(addr.s_addr));
    
    printf("%s IP: %s\n", 
           msg_type == MSG_ADD_IP ? "Blocking" : "Unblocking", 
           ip_str);
    sendmsg(sock_fd, &msg, 0);
}

void handle_rate_limit(const char *rate_str)
{
    char ip_str[16];
    char *colon_pos;
    unsigned long rate;
    struct in_addr addr;
    struct rate_limit_msg msg_data;
    
    colon_pos = strchr(rate_str, ':');
    if (!colon_pos) {
        printf("Invalid format. Use IP:RATE (e.g., 192.168.1.1:1000000)\n");
        return;
    }
    
    strncpy(ip_str, rate_str, colon_pos - rate_str);
    ip_str[colon_pos - rate_str] = '\0';
    
    if (inet_aton(ip_str, &addr) == 0) {
        printf("Invalid IP address format\n");
        return;
    }
    
    rate = strtoul(colon_pos + 1, NULL, 10);
    if (rate == 0 && errno == EINVAL) {
        printf("Invalid rate value\n");
        return;
    }
    
    msg_data.ip = addr.s_addr;
    msg_data.rate = rate;
    
    nlh->nlmsg_type = MSG_SET_RATE;
    memcpy(NLMSG_DATA(nlh), &msg_data, sizeof(msg_data));
    
    printf("Setting rate limit of %lu bytes/sec for IP: %s\n", rate, ip_str);
    sendmsg(sock_fd, &msg, 0);
}

void print_mac(unsigned char *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

char *format_rate(unsigned long rate)
{
    static char buf[32];
    if (rate == 0)
        return "No limit";
    else if (rate >= 1000000)
        snprintf(buf, sizeof(buf), "%.2f MB/s", rate/1000000.0);
    else if (rate >= 1000)
        snprintf(buf, sizeof(buf), "%.2f KB/s", rate/1000.0);
    else
        snprintf(buf, sizeof(buf), "%lu B/s", rate);
    return buf;
}

void print_ip_list(void)
{
    struct in_addr addr;
    unsigned char mac[6];
    bool is_blocked;
    unsigned long last_seen, rate_limit;
    void *data;
    time_t current_time;
    char time_str[64];
    
    nlh->nlmsg_type = MSG_GET_LIST;
    sendmsg(sock_fd, &msg, 0);
    
    recvmsg(sock_fd, &msg, 0);
    data = NLMSG_DATA(nlh);
    
    printf("\nCurrent IP List:\n");
    printf("%-15s %-20s %-8s %-15s %-19s\n", 
           "IP Address", "MAC Address", "Status", "Rate Limit", "Last Seen");
    printf("-----------------------------------------------------------------------\n");
    
    current_time = time(NULL);
    
    while ((char *)data < (char *)NLMSG_DATA(nlh) + nlh->nlmsg_len - NLMSG_HDRLEN) {
        memcpy(&addr.s_addr, data, sizeof(uint32_t));
        data += sizeof(uint32_t);
        
        memcpy(mac, data, 6);
        data += 6;
        
        memcpy(&is_blocked, data, sizeof(bool));
        data += sizeof(bool);

        memcpy(&last_seen, data, sizeof(unsigned long));
        data += sizeof(unsigned long);
        
        memcpy(&rate_limit, data, sizeof(unsigned long));
        data += sizeof(unsigned long);
        
        time_t seconds_ago = (current_time - (last_seen));
        if (seconds_ago < 60) {
            snprintf(time_str, sizeof(time_str), "%ld seconds ago", seconds_ago);
        } else if (seconds_ago < 3600) {
            snprintf(time_str, sizeof(time_str), "%ld minutes ago", seconds_ago / 60);
        } else {
            snprintf(time_str, sizeof(time_str), "%ld hours ago", seconds_ago / 3600);
        }
        
        printf("%-15s ", inet_ntoa(addr));
        print_mac(mac);
        printf(" %-8s %-15s %s\n", 
               is_blocked ? "Blocked" : "Active",
               format_rate(rate_limit),
               time_str);
    }
}

int main(int argc, char **argv)
{
    struct arguments arguments;

    memset(&arguments, 0, sizeof(arguments));

    argp_parse(&argp, argc, argv, 0, 0, &arguments);
    init_netlink();

    if (arguments.block && arguments.ip) {
        handle_ip(arguments.ip, MSG_ADD_IP);
    }
    else if (arguments.unblock && arguments.ip) {
        handle_ip(arguments.ip, MSG_UNBLOCK_IP);
    }
    else if (arguments.set_rate && arguments.rate_str) {
        handle_rate_limit(arguments.rate_str);
    }
    else if (arguments.list || arguments.monitor) {
        do {
            print_ip_list();
            if (arguments.monitor) {
                printf("\nMonitoring... (Press Ctrl+C to stop)\n");
                sleep(1);
            }
        } while (arguments.monitor);
    }
    else {
        argp_help(&argp, stdout, ARGP_HELP_STD_HELP, argv[0]);
    }

    close(sock_fd);
    free(nlh);
    return 0;
}