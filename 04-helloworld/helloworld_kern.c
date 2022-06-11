#include <linux/bpf.h>

/*
    这个头文件其实也是由内核提供，但是在这里被单独拷贝出来了
*/
#include "kernel/bpf_helpers.h"

/*
    bpf_debug主要通过内核提供的bpf_trace_printk来讲日志输出到/sys/kernel/debug/tracing/trace_pipe
    long bpf_trace_printk(const char *fmt, __u32 fmt_size, ...);
    bpf_trace_printk是内核提供的BPF helper函数，虽然bpf_trace_printk是可变参的，但是规定最多只能接受5个参数（包括fmt和fmt_size）
*/
#define bpf_debug(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

/*
    SEC是一个宏用来在二进制文件(目标文件，.o文件)中生成一个新的section，具体可查看实验指导手册
    以下三个函数分别测试了XDP的三个ACTION
*/

SEC("xdp_abort")
int xdp_abort_fn(struct xdp_md *ctx)
{
    /*
        这个XDP ACTION将会递增一个特定的异常计数器，主要可以用来调试
    */

    bpf_debug("Aborting packet!\n");

    return XDP_ABORTED;
}

SEC("xdp_drop")
int xdp_drop_fn(struct xdp_md *ctx)
{
    /*
        这个XDP ACTION将丢弃当前的数据包，转到处理下一个数据包。
    */

    bpf_debug("Dropping packet!\n");

    return XDP_DROP;
}

SEC("xdp_pass")
int xdp_pass_fn(struct xdp_md *ctx)
{
    /*
        这个XDP ACTION将通知内核继续处理这个数据包，也就是判定允许通过。
    */

    bpf_debug("Passing packet to kernel!\n");

    return XDP_PASS;
}

/*
    XDP不止三个ACTION，还有像XDP_TX，和XDP_REDIRECT，它们一般用作在更高级的用途当中
    enum xdp_action {
        XDP_ABORTED = 0,
        XDP_DROP,
        XDP_PASS,
        XDP_TX,
        XDP_REDIRECT,
    };
*/

/*
    license声明，一般使用了bpf helper声明都必须使用GPL
*/
char _license[] SEC("license") = "GPL";
