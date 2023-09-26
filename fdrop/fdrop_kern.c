#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "../common/parsing_helpers.h"


#define FDROP_MAX_ENTRY 4096



struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, FDROP_MAX_ENTRY);
} fdrop_map_v1 SEC(".maps");

SEC("xdp")
int  fdrop_simple(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
	struct iphdr *iphdr;
	__u32 action = XDP_PASS;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
        __u64 *value;
        int rtn;
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_type < 0) {
            action = XDP_PASS;
            goto out;
        }
        value = bpf_map_lookup_elem(&fdrop_map_v1, &iphdr->saddr);
        if (value != NULL) {
            action = XDP_DROP;
            *value = (*value) + 1;
            rtn = bpf_map_update_elem(&fdrop_map_v1, &iphdr->saddr, value, BPF_EXIST);
            if (rtn < 0)
                action = XDP_ABORTED;
        }
    }
out:
    return action;

}

char _license[] SEC("license") = "freebsd";