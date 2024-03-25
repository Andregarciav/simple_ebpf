#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <linux/bpf.h>
#include <linux/if_link.h> 
#include <linux/if_xdp.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "dpi.h"
#include "bpf/libbpf.h"
// #include "bpf/bpf.h"

// static const char *xdp_filename = "dpi_xdp.o";
// static const char *xdp_sec = "xdp_dpi";
// static const char *tc_filename = "dpi_tc.o";
// static const char *tc_sec = "tc_dpi";

struct ipv4list {
    int provider;
    int ip;
    struct ipv4list *next;
};

static const struct _bpf_files {
    char* ipv4_table;
    char* ipv6_table;
    char* tracker;
} bpf_maps = {
    "/sys/fs/bpf/tc/globals/ipv4_provider"
    "/sys/fs/bpf/tc/globals/ipv6_provider"
    "/sys/fs/bpf/tc/globals/tracker"
};

struct ipv4list *node (int ip, int provider){
    struct ipv4list *aux = malloc (sizeof (struct ipv4list));
    aux->ip = ip;
    printf("Conteudo IP: %x\nConteudo aux-ip: %x\n", ip, aux->ip);
    aux->provider = provider;
    printf("Conteudo Povider: %x\nConteudo aux-prider: %d\n", provider, aux->provider);
    aux->next = NULL;
    return aux;
}

uint32_t convertip (char *buff){
    uint32_t ip = 0;
    uint8_t tmp[4];

    tmp[0] = atoi(strtok(buff, "."));
    tmp[1] = atoi(strtok('\0', "."));
    tmp[2] = atoi(strtok('\0', "."));
    tmp[3] = atoi(strtok('\0', "."));
    ip =    (tmp[0] << 24) |
            (tmp[1] << 16) |
            (tmp[2] << 8)  |
            (tmp[3]);
    return ip;
}

void get_ipv4_list(FILE *fp, struct ipv4list *list, int provider){
    char buff[20];
    int bytes;
    struct ipv4list *last;
    struct ipv4list *aux;
    struct ipv4list *innerlist;
    

    if(!fp)
        return;
    
    if (feof(fp))
        return;

    
    bytes = fscanf(fp, "%s", buff);
    innerlist = node(convertip(buff), provider);
    innerlist->next = NULL;
    list= innerlist;

    while(!feof(fp)){
        bytes = fscanf(fp, "%s", buff);
        aux = node(convertip(buff), provider);
        innerlist->next = aux;
        innerlist = aux;
    }
}

int main (){
    int ipv4_provider,
        ipv6_provider,
        tracker;
    struct ipv4list *list = NULL;
    FILE *fp;

    fp = fopen("netflix.dpi", "r");

    get_ipv4_list(fp, list, 1);

    ipv4_provider = bpf_obj_get(bpf_maps.ipv4_table);
    ipv6_provider = bpf_obj_get(bpf_maps.ipv6_table);
    tracker = bpf_obj_get(bpf_maps.tracker);

    
    return 0;
}