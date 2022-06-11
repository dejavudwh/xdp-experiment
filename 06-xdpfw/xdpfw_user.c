// SPDX-License-Identifier: GPL-2.0

#include "xdpfw_user.h"

/*
    This application uses the same logic for attaching/detaching XDP programs as the last section, its just
    been moved into the common/headers/xdp_prog_helpers.h file in the root of this repo.
*/

/*
    update_map处理从给定的BPF MAP中插入或删除一个给定的键。这是通过利用libbpf的'bpf_map_update_elem'和'bpf_map_delete_elem'
    和上一节的处理是几乎相同的
*/
static int update_map(const char *map, void *key, bool insert)
{
    /*
        在我们可以更新/删除黑名单中的元素之前
        我们需要抓取有关BPF MAP的文件描述符
    */
    int map_fd = open_bpf_map(map);
    if (map_fd < 0)
    {
        return EXIT_FAIL_XDP_MAP_OPEN;
    }

    if (insert)
    {
        /*
            就像上一节一样，我们传入map的文件描述符，然后传入key
            在本例中是解析后提供的key和0，
            在这里我们不关心值，只关心它是否存在于map中
        */
        __u8 value = 0;
        if (bpf_map_update_elem(map_fd, key, &value, BPF_NOEXIST) != 0)
        {
            return EXIT_FAIL_XDP_MAP_UPDATE;
        }
    }
    else
    {
        /*
            使用libbpf提供的bpf_map_delete_elem进行删除
        */
        if (bpf_map_delete_elem(map_fd, key) != 0)
        {
            return EXIT_FAIL_XDP_MAP_UPDATE;
        }
    }

    return EXIT_OK;
}

/*
    handle_mac处理从mac_blacklist中添加或删除一个给定的MAC地址
*/
static int handle_mac(char *mac_addr, bool insert)
{
    /*
        首先，由于我们传入的是一个MAC地址的字符串表示，形式为'00:00:00:00:00'，我们需要将其转换为适当的形式
    */
    unsigned char mac[6];
    if (6 != sscanf(mac_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]))
    {
        printf("ERR: Invalid MAC address specifed must be in the form '00:00:00:00:00:00', got '%s",
               mac_addr);
        return EXIT_FAIL_OPTIONS;
    }

    /*
        打印日志
    */
    printf("%s source MAC address '%s'.\n", insert ? "Blacklisting" : "Whitelisting", mac_addr);

    /*
        然后我们调用update_map，处理打开指定的MAP并插入或删除给定的键
    */
    int ret = update_map(MAC_BLACKLIST_PATH, &mac, insert);
    if (ret != 0)
    {
        printf("ERR: Failed to %s specified MAC address '%s' err(%d): %s\n",
               insert ? "blacklist" : "whitelist", mac_addr, errno, strerror(errno));
    }
    return ret;
}

/*
    handle_prefix'处理从各自的'v4_blacklist'或'v6_blacklist'中添加或删除一个给定的IP地址
    无论是IPv4还是IPv6，它的方式与上面的'handle_mac'函数相同。
*/
static int handle_prefix(char *prefix, bool insert, bool v4)
{
    /*
        根据v4还是v6来创建key
    */
    struct bpf_lpm_trie_key *key = alloca(v4 ? sizeof(struct lpm_v4_key) : sizeof(struct lpm_v6_key));

    /*
        由于我们传入的是IP地址前缀的字符串表示，形式为'0.0.0.0/0'或':/0'，我们需要将其转换为适当的形式
    */
    int addr_len = v4 ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
    char *addr = alloca(addr_len);
    if (2 != sscanf(prefix, "%[^/]%*c%d", addr, &key->prefixlen))
    {
        printf("ERR: Invalid IP address prefix specifed must be in the form '1.1.1.1/32' or '::1/128', got '%s'.\n",
               prefix);
        return EXIT_FAIL_OPTIONS;
    }

    /*
        inet_pton:将IP地址从字符串格式转换成网络地址格式
    */
    if (inet_pton(v4 ? AF_INET : AF_INET6, addr, key->data) != 1)
    {
        printf("ERR: Invalid IP address specified as part of the supplied prefix '%s'\n",
               prefix);
        return EXIT_FAIL_OPTIONS;
    }

    /*
        打印日志
    */
    printf("%s source IP%s prefix '%s'.\n", insert ? "Blacklisting" : "Whitelisting", v4 ? "v4" : "v6", prefix);

    /*
        同处理handle_mac
    */
    int ret = update_map(v4 ? V4_BLACKLIST_PATH : V6_BLACKLIST_PATH, key, insert);
    if (ret != 0)
    {
        printf("ERR: Failed to %s specified IP address prefix '%s' err(%d): %s\n",
               insert ? "blacklist" : "whitelist", prefix, errno, strerror(errno));
    }
    return ret;
}

/*
    handle_port'处理从'port_blacklist'BPF MAP中添加或删除一个指定的端口/协议/类型
    它的方式与上面的'handle_mac'和'handle_prefix'函数相同。
*/
static int handle_port(char *port, bool insert, bool udp, bool src)
{
    struct port_key *key = alloca(sizeof(struct port_key));

    key->type = src ? source_port : destination_port;
    key->proto = udp ? udp_port : tcp_port;
    key->port = atoi(port);

    printf("%s %s port '%s/%s'.\n", insert ? "Blacklisting" : "Whitelisting", src ? "source" : "dest", port, udp ? "udp" : "tcp");

    int ret = update_map(PORT_BLACKLIST_PATH, key, insert);
    if (ret != 0)
    {
        printf("ERR: Failed to %s specified %s port '%s/%s' err(%d): %s\n",
               insert ? "blacklist" : "whitelist", src ? "source" : "dest", port, udp ? "udp" : "tcp", errno, strerror(errno));
    }
    return ret;
}

int main(int argc, char **argv)
{
    int opt;
    int longindex = 0;

    char *prog_path = NULL;
    char *section = NULL;

    int if_index = -1;

    bool should_detach = false;
    bool should_attach = false;

    bool insert = true;

    char *mac_addr = NULL;
    char *prefix_v4 = NULL;
    char *prefix_v6 = NULL;

    bool is_udp = true;

    char *dest_port = NULL;
    char *src_port = NULL;

    int rlimit_ret = set_rlimit();
    if (rlimit_ret != EXIT_OK)
    {
        return rlimit_ret;
    }

    while ((opt = getopt_long(argc, argv, "hx::n::a:d:sirm:4:6:t:c:p:", long_options, &longindex)) != -1)
    {
        char *tmp_value = optarg;
        switch (opt)
        {
        case 'x':
            if (handle_optional_argument(argc, argv))
            {
                tmp_value = argv[optind++];
                prog_path = alloca(strlen(tmp_value));
                strcpy(prog_path, tmp_value);
            }
            break;
        case 'n':
            if (handle_optional_argument(argc, argv))
            {
                tmp_value = argv[optind++];
                section = alloca(strlen(tmp_value));
                strcpy(section, tmp_value);
            }
            break;
        case 'a':
            if (should_detach)
            {
                printf("ERR: Must not specify both '-a|--attach' and '-d|--detach' "
                       "during the same invocation.\n");
                return EXIT_FAIL_OPTIONS;
            }
            should_attach = true;
            if_index = get_ifindex(optarg);
            if (if_index < 0)
            {
                return EXIT_FAIL_OPTIONS;
            }
            break;
        case 'd':
            if (should_attach)
            {
                printf("ERR: Must not specify both '-a|--attach' and '-d|--detach' "
                       "during the same invocation.\n");
                return EXIT_FAIL_OPTIONS;
            }
            should_detach = true;
            if_index = get_ifindex(optarg);
            if (if_index < 0)
            {
                return EXIT_FAIL_OPTIONS;
            }
            break;
        case 's':
            return print_action_stats();
        case 'i':
            insert = true;
            break;
        case 'r':
            insert = false;
            break;
        case 'm':
            mac_addr = alloca(strlen(tmp_value));
            strcpy(mac_addr, tmp_value);
            break;
        case '4':
            prefix_v4 = alloca(strlen(optarg));
            strcpy(prefix_v4, optarg);
            break;
        case '6':
            prefix_v6 = alloca(strlen(optarg));
            strcpy(prefix_v6, optarg);
            break;
        case 't':
            dest_port = alloca(strlen(optarg));
            strcpy(dest_port, optarg);
            break;
        case 'c':
            src_port = alloca(strlen(optarg));
            strcpy(src_port, optarg);
            break;
        case 'p':
            if (strcmp("udp", optarg) == 0)
            {
                is_udp = true;
                break;
            }
            if (strcmp("tcp", optarg) == 0)
            {
                is_udp = false;
                break;
            }
            printf("ERR: Invalid protocol specified with '-p|--proto' must be either "
                   "'udp' or 'tcp', got '%s'.",
                   optarg);
            return EXIT_FAIL_OPTIONS;
        case 'h':
        default:
            usage(argv, doc, long_options, long_options_descriptions);
            return EXIT_FAIL_OPTIONS;
        }
    }

    if (should_detach)
    {
        return detach(if_index, prog_path == NULL ? default_prog_path : prog_path);
    }

    if (should_attach)
    {
        return attach(if_index, prog_path == NULL ? default_prog_path : prog_path, section == NULL ? default_section : section);
    }

    /*
        insert用来判断是插入还是删除对应的地址
    */
    if (mac_addr != NULL)
    {
        return handle_mac(mac_addr, insert);
    }

    if (prefix_v4 != NULL)
    {
        return handle_prefix(prefix_v4, insert, true);
    }
    if (prefix_v6 != NULL)
    {
        return handle_prefix(prefix_v6, insert, false);
    }

    if (dest_port != NULL)
    {
        return handle_port(dest_port, insert, is_udp, false);
    }
    if (src_port != NULL)
    {
        return handle_port(src_port, insert, is_udp, true);
    }

    return EXIT_OK;
}