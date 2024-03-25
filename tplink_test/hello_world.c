#include <stdio.h>
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
	(void *) BPF_FUNC_trace_printk;


int hello (struct xdp_md *ctx){
    char *str = "Hello Word!";
    BPF_trace_printk (str, sizeof(str));
    return XDP_PASS;
}