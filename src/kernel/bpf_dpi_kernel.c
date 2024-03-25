#include <stdint.h>
#include <stdlib.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <iproute2/bpf_elf.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "dpi.h"

#define DEBUG

struct bpf_elf_map SEC("maps") ipv4_provider = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof (uint32_t),
    .size_value = sizeof (int), 
    .max_elem = 1024,
    .pinning = 2,
};

struct bpf_elf_map SEC("maps") ipv6_provider = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof (struct in6_addr),
    .size_value = sizeof (int), 
    .max_elem = 1024,
    .pinning = 2,
};

struct bpf_elf_map SEC("maps") tracker = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof (__u32),
    .size_value = sizeof (struct stats),
    .max_elem = sizeof(__u8),
    .pinning = 2,
};

static __always_inline void update_cnt (void *provider, long long bytes){
    struct stats    *increment,
                    newstats = {0,0};

    // int key = (int)provider;

    increment = bpf_map_lookup_elem(&tracker, &provider);
    if (increment){
        increment->pkt_cnt++;
        increment->bytes_cnt += bytes;
    }
    else{
        newstats.pkt_cnt = 1;
        newstats.bytes_cnt = bytes;
        bpf_map_update_elem (&tracker, &provider, &newstats, BPF_NOEXIST);
    }
}

SEC("xdp_dpi")
int miniDPI(struct xdp_md *ctx){
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
    __u32 set;
    void *provider;
    struct ethhdr *eth = data;
    struct iphdr *ipv4_hdr;
    struct ipv6hdr *ipv6_hdr;
    int *ipv4_addr;

    bpf_printk("[DPI] hook XDP loaded!\n");
    set = sizeof (struct ethhdr);
	if (data + set + 1 > data_end){
        bpf_printk("ETHERNET!\n");
		return XDP_PASS;
    }

    if (eth->h_proto == bpf_htons(IPV4)){
        bpf_printk("[DPI][IPV4] packet loaded!\n");
        ipv4_hdr = data + set;

        set += sizeof(struct iphdr);
        
        if (data + set > data_end)
            return XDP_PASS;

        provider = bpf_map_lookup_elem(&ipv4_provider, &ipv4_hdr->saddr);

        if (!provider){
            bpf_printk("[DPI][IPV4] No IP in database PROVIDERS!\n");
            return XDP_PASS;
        }
        
    //     // TODO: lenght app or enlace
        bpf_printk("[DPI][IPV4][COUNTER] Updating packets data!\n");
        update_cnt(provider, data_end - data); 
    }
    else if (eth->h_proto == bpf_htons(IPV6)){
        bpf_printk("[DPI][IPV6] packet loaded!\n");
        ipv6_hdr = data + set;
        set += sizeof(struct ipv6hdr);

        if (data + set > data_end)
            return XDP_PASS;

        provider = bpf_map_lookup_elem(&ipv6_provider, &ipv6_hdr->saddr);

        if (!provider){
            bpf_printk("[DPI][IPV6] No IP in database PROVIDERS!\n");
            return XDP_PASS;
        }
        bpf_printk("[DPI][IPV6][COUNTER] Updating packets data!\n");
        update_cnt(provider, data_end - data);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
