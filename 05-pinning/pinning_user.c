// SPDX-License-Identifier: GPL-2.0

#include "pinning_user.h"

/*
    'xdp_flags'在这里被传递给处理将所提供的XDP程序附加到所提供的网络设备的函数。
    它控制程序的attach的方式和attach后的各种属性。
    XDP_FLAGS_UPDATE_IF_NOEXIST的意思就是如果当前要attach的设备上没有存在xdp程序，我们才进行操作
    这样可以避免不小心卸载了其它xdp程序

    $(LINUX v5.0)/include/uapi/linux/if_link.h

    #define XDP_FLAGS_UPDATE_IF_NOEXIST	(1U << 0)
    #define XDP_FLAGS_SKB_MODE		    (1U << 1)
    #define XDP_FLAGS_DRV_MODE		    (1U << 2)
    #define XDP_FLAGS_HW_MODE		    (1U << 3)
*/
static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

/*
    handle_action'是我们使用libbpf来更新来自用户空间的BPF MAP
    这样底层的XDP程序就可以根据我们更新的这些数据来改变它对数据包的响应方式
*/
static int handle_action(const char *str_action)
{
    /*
        由于我们从这个程序的调用中传入了一个字符串，我们需要找到相对应的XDP action
    */
    int action = str2action(str_action);
    if (action < 0)
    {
        printf("ERR: Failed to parse the suppled action '%s': must be one of "
               "['XDP_ABORTED', 'XDP_DROP', 'XDP_PASS', 'XDP_TX', 'XDP_REDIRECT'].\n",
               str_action);
        return EXIT_FAIL_OPTIONS;
    }

    /*
        在获得了我们想要进行的XDP action之后，
        我们就需要一个文件描述符，找到相应的BPF MAP，这与我们在上一节所做的非常相似。
        事实上，这个'open_bpf_map'函数和之前讲到的是同一个函数
        ACTION_MAP_PATH定义在constans.h中
        #define COUNTER_MAP_PATH "/sys/fs/bpf/action_counters"
    */
    int map_fd = open_bpf_map(ACTION_MAP_PATH);
    if (map_fd < 0)
    {
        return EXIT_FAIL_XDP_MAP_OPEN;
    }

    /*
        和之前讲的是类似的，具体可以参考上一节
    */
    __u32 action_idx = 0;

    /*
        我们调用'bpf_map_update_elem'，它从用户空间获取我们要更新的BPF MAP的文件描述符，
        一个指向我们要更新的键的指针，以及一个指向我们要设置键的值的指针
        内核态的程序会来读取这个程序以此来完成相应的操作
    */
    if (bpf_map_update_elem(map_fd, &action_idx, &action, 0) != 0)
    {
        printf("ERR: Failed to set specified action '%s' err(%d): %s\n",
               str_action, errno, strerror(errno));
        return EXIT_FAIL_XDP_MAP_UPDATE;
    }
    return EXIT_OK;
}

/*
    detach是使用 libbpf 从一个指定的网络接口上卸载一个 XDP 程序。

    这取代了我们上次用iproute2和rm来卸载程序并解除其BPF MAP的过程。
*/
static int detach(int if_index, char *prog_path)
{
    /*
        我们需要一些存储对象，用于生成的bpf对象文件和包含在对象中的程序的文件描述符。对象的文件描述符。
    */
    struct bpf_object *bpf_obj;
    int bpf_prog_fd = -1;
    int ret = 0;

    /*
        下面两个调用'bpf_prog_load'和'bpf_set_link_xdp_fd'相当于运行:
        'sudo ip link set dev ${device name} xdp off'
    */

    /*
        bpf_prog_load'处理根据作为第一个参数提供的文件路径从磁盘加载一个BPF程序
        它的第二个参数是期望的BPF程序的类型，在这个例子中我们加载一个XDP程序。
        最后两个参数是指向上述bpf对象存储和文件描述符的指针

        如果出错则返回一个bpf_prog_load的错误号
    */
    ret = bpf_prog_load(prog_path, BPF_PROG_TYPE_XDP, &bpf_obj, &bpf_prog_fd);
    if (ret != 0)
    {
        printf("ERR: Unable to load XDP program from file '%s' err(%d): %s\n",
               prog_path, -ret, strerror(-ret));
        return EXIT_FAIL_XDP_DETACH;
    }

    /*
        bpf_set_link_xdp_fd是真正卸载xdp程序的地方
        它接受提供的接口索引和-1作为第二个参数，向内核发出信号，表示在这个接口上卸载xdp程序       
    */
    ret = bpf_set_link_xdp_fd(if_index, -1, 0);
    if (ret != 0)
    {
        printf("WARN: Cannont detach XDP program from specified device at index '%d' err(%d): %s\n",
               if_index, -ret, strerror(-ret));
    }

    /*
        bpf_object__unpin_maps删除我们之前从'/sys/fs/bpf'文件系统加载的bpf对象中的BPF MAP，等于运行下列这条命令：
        'sudo rm -f /sys/fs/bpf/${map name}'

        MAP_DIR定义在constants.h
        #define MAP_DIR "/sys/fs/bpf"
    */
    ret = bpf_object__unpin_maps(bpf_obj, MAP_DIR);
    if (ret != 0)
    {
        printf("WARN: Unable to unpin the XDP program's '%s' maps from '%s' err(%d): %s\n",
               prog_path, MAP_DIR, -ret, strerror(-ret));
    }

    return EXIT_OK;
}

/*
    load_section'使用libbpf来处理一个已经加载的有效的'bpf_object'中找到所提供的section。
*/
static int load_section(struct bpf_object *bpf_obj, char *section)
{
    struct bpf_program *bpf_prog;

    /*
        bpf_object__find_program_by_title'处理从最后一次调用中搜索加载的'bpf_object'的给定的section。
        如果提供的section不存在或者不是bpf_object中的程序的section，那么它将返回NULL，
        否则它将返回一个'bpg_program'的指针，然后你可以使用'bpf_program__fd'来获取一个文件描述符。
    */
    bpf_prog = bpf_object__find_program_by_title(bpf_obj, section);
    if (bpf_prog == NULL)
    {
        return -EINVAL;
    }

    /*
        bpf_program__fd'处理返回正确的文件描述符，用于上次调用加载的有效'bpf_program'
        如果由于某种原因这个程序是无效的，这个调用将返回一个错误号
        否则，这个调用将返回给定的'bpf_program'的文件描述符
    */
    return bpf_program__fd(bpf_prog);
}

/*
    attach'是使用libbpf将XDP程序附加到一个给定的网络接口上。

    这取代了我们上次用iproute2和bpftool来附加程序和pinning BPF MAP的过程。
*/
static int attach(int if_index, char *prog_path, char *section)
{
    /*
        这里的作用和detach中的同样
    */
    struct bpf_object *bpf_obj;
    int bpf_prog_fd = -1;
    int ret = 0;

    /*
        以下三个调用'bpf_prog_load', 'load_section', 和'bpf_set_link_xdp_fd'相当于运行：
        'sudo ip link set dev ${device name} xdp obj ${object file} sec ${section name}'
    */

    /*
        同上面的detach
    */
    ret = bpf_prog_load(prog_path, BPF_PROG_TYPE_XDP, &bpf_obj, &bpf_prog_fd);
    if (ret != 0)
    {
        printf("ERR: Unable to load XDP program from file '%s' err(%d): %s\n",
               prog_path, -ret, strerror(-ret));
        return EXIT_FAIL_XDP_ATTACH;
    }

    /*
        load_section'是对libbpf提供的接口的一个封装
        它定位并加载给定的section，包含在给定的加载的'bpf_object'中。
        参数是一个'bpf_object'指针和代表你想从提供的'bpf_object'中加载的section的字符串。
        如果该部分不存在，这将返回错误号。
        否则它将返回代表给定section的文件描述符，然后我们可以在下面调用'bpf_set_link_xdp_fd'时使用它。
    */
    int section_fd = load_section(bpf_obj, section);
    if (section_fd < 0)
    {
        printf("WARN: Unable to load section '%s' from load bpf object file '%s' err(%d): %s.\n",
               section, prog_path, -section_fd, strerror(-section_fd));
        printf("WARN: Falling back to first program in loaded bpf object file '%s'.\n",
               prog_path);
    }
    else
    {
        bpf_prog_fd = section_fd;
    }

    /*
        bpf_set_link_xdp_fd是真正加载xdp程序的地方
        它接受提供的接口索引和bpf_prog_fd作为第二个参数，向内核发出信号，表示在这个接口上加载xdp程序    
    */
    ret = bpf_set_link_xdp_fd(if_index, bpf_prog_fd, 0);
    if (ret != 0)
    {
        printf("ERR: Unable to attach loaded XDP program to specified device index '%d' err(%d): %s\n",
               if_index, -ret, strerror(-ret));
        return EXIT_FAIL_XDP_ATTACH;
    }

    /*
        加载相应的BPF MAP

        等同于运行：
        'sudo bpftool map list'
        'sudo bpftool map pin id ${map id} /sys/fs/bpf/${map name}'
    */
    ret = bpf_object__pin_maps(bpf_obj, MAP_DIR);
    if (ret != 0)
    {
        printf("ERR: Unable to pin the loaded and attached XDP program's maps to '%s' err(%d): %s\n",
               MAP_DIR, -ret, strerror(-ret));
        return EXIT_FAIL_XDP_MAP_PIN;
    }

    return EXIT_OK;
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

    char *action = NULL;

    int rlimit_ret = set_rlimit();
    if (rlimit_ret != EXIT_OK)
    {
        return rlimit_ret;
    }

    /*
        int getopt_long(int argc, char * const argv[], const char *optstring, const struct option *longopts, int *longindex);  
        getopt_long是GNU C中提供的用来处理命令参数的函数
        形式如“a:b::cd:“，分别表示程序支持的命令行短选项有-a、-b、-c、-d，冒号含义如下：
        (1)只有一个字符，不带冒号——只表示选项， 如-c 
        (2)一个字符，后接一个冒号——表示选项后面带一个参数，如-a 100
        (3)一个字符，后接两个冒号——表示选项后面带一个可选参数，即参数可有可无，果带参数，则选项与参数之间不能有空格
    */
    while ((opt = getopt_long(argc, argv, "hx::n::a:d:se:", long_options, &longindex)) != -1)
    {
        /*
            对应的是long_options中的选项
            （1）optarg：表示当前选项对应的参数值。
            （2）optind：表示的是下一个将被处理到的参数在argv中的下标值。
            （3）opterr：如果opterr = 0，在getopt、getopt_long、getopt_long_only遇到错误将不会输出错误信息到标准输出流。opterr在非0时，向屏幕输出错误。
            （4）optopt：表示没有被未标识的选项。
        */
        char *tmp_value = optarg;
        switch (opt)
        {
        case 'x':   // 准备加载的xdp程序的文件路径
            if (handle_optional_argument(argc, argv))
            {
                tmp_value = argv[optind++];
                prog_path = alloca(strlen(tmp_value));
                strcpy(prog_path, tmp_value);
            }
            break;
        case 'n':   // 准备加载的xdp程序的Section名
            if (handle_optional_argument(argc, argv))
            {
                tmp_value = argv[optind++];
                section = alloca(strlen(tmp_value));
                strcpy(section, tmp_value);
            }
            break;
        case 'a': // 将指定的xdp程序附加到指定的网络设备上
            if (should_detach)
            {
                /*
                    如果已经设置了detach，则这是个错误  
                */
                printf("ERR: Must not specify both '-a|--attach' and '-d|--detach' "
                       "during the same invocation.\n");
                return EXIT_FAIL_OPTIONS;
            }
            should_attach = true;
            // 获得网络接口索引
            if_index = get_ifindex(optarg);
            if (if_index < 0)
            {
                return EXIT_FAIL_OPTIONS;
            }
            break;
        case 'd':   // 将指定的xdp程序从指定的网络设备中卸载
            if (should_attach)
            {
                printf("ERR: Must not specify both '-a|--attach' and '-d|--detach' "
                       "during the same invocation.\n");
                return EXIT_FAIL_OPTIONS;
            }
            should_detach = true;
            // 获得网络接口索引
            if_index = get_ifindex(optarg);
            if (if_index < 0)
            {
                return EXIT_FAIL_OPTIONS;
            }
            break;
        case 's':   // 打印已经加载的XDP程序的统计数据
            return print_action_stats();
        case 'e':   // 设置xdp程序的XDP action
            action = alloca(strlen(tmp_value));
            strcpy(action, tmp_value);
            break;
        case 'h':
        default:
            usage(argv, doc, long_options, long_options_descriptions);
            return EXIT_FAIL_OPTIONS;
        }
    }

    /*
        处理attach和detach
    */
    if (should_detach)
    {
        return detach(if_index, prog_path == NULL ? default_prog_path : prog_path);
    }

    if (should_attach)
    {
        return attach(if_index, prog_path == NULL ? default_prog_path : prog_path, section == NULL ? default_section : section);
    }

    /*
        处理其它xdp action
    */
    if (action != NULL)
    {
        return handle_action(action);
    }

    return EXIT_OK;
}
