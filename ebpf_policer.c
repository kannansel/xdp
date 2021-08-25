/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

#define VLAN_MAX_DEPTH 2
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88a8
#define ETH_P_IP     0x0800
#define ETH_P_IPV6 0x86dd

#define NANO_SEC 1000000000000LL
#define INTERVAL 1

#define bpf_printk(fmt, ...)                                    \
({                                                              \
        char ____fmt[] = fmt;                                   \
        bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})
struct ethhdr {
        unsigned char h_dest[6];
        unsigned char h_source[6];
        unsigned short h_proto;
};

struct vlan_hdr {
        unsigned short  h_vlan_TCI;
        unsigned short  h_vlan_encapsulated_proto; /* NOTICE: unsigned type */
};

struct policer_info {
       int rate;
       int count;
       int drop_count;
       __u64 timestamp;
};


struct bpf_map_def SEC("maps") proto_policer = {
       .type       = BPF_MAP_TYPE_PERCPU_ARRAY,//BPF_MAP_TYPE_DEVMAP,
       .key_size   = sizeof(int),
       .value_size = sizeof(struct policer_info),
       .max_entries= 16,
};

static __always_inline int proto_is_vlan (unsigned short h_proto) {
    return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
              h_proto == bpf_htons(ETH_P_8021AD));
}

static  __always_inline int parse_ethhdr (void *data,
                  void *data_end,
                  struct ethhdr **ethhdr) {
    int hdrsize = sizeof(struct ethhdr);
    struct ethhdr *eth = data;
    int i = 0;
    unsigned short h_proto;
    struct  vlan_hdr *vlh;

    if (data+hdrsize > data_end)  {
        return -1;
    }

    h_proto = eth->h_proto;
    vlh = data + hdrsize;
    for (i=0; i < VLAN_MAX_DEPTH; i++) {
         if (!proto_is_vlan(h_proto)) {
             break;
         }

         if (vlh + 1 > data_end) {
             break;
         }

         h_proto = vlh->h_vlan_encapsulated_proto;
         vlh ++;
    }

    *ethhdr = eth;
    return h_proto;
}

/* Solution to police ip v4 and v6 reaching CPU
 */
SEC("ebpf_policer")
int  ebpf_control_plane_policer(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
        struct policer_info *elem;
        struct policer_info entry = {0};
        int key = 1;

        __u64 now;
	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	int nh_type;

	struct ethhdr *eth;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(data, data_end, &eth);

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
            key = 1;
	} else if (nh_type == bpf_htons(ETH_P_IP)) {
            key = 2;
	}
            now = bpf_ktime_get_ns ();
        elem= bpf_map_lookup_elem (&proto_policer, &key);
        if (!elem) {
            entry.rate = 1;
            entry.count= 0;
            entry.timestamp = bpf_ktime_get_ns();
            bpf_map_update_elem (&proto_policer, &key, &entry, BPF_ANY);
        } else {
            now = bpf_ktime_get_ns ();
            if (elem->rate == 0) {
                if (now - elem->timestamp > (NANO_SEC * INTERVAL)) {
                    elem->rate = 1;
                    elem->timestamp = now;
                } else {
                    elem->drop_count ++;
                    bpf_printk("Drop IP typenow %lld\n",now);
                    action = XDP_DROP;
                }
            }
            if (elem->rate > 0) {
                elem->rate --;
                elem->count ++;
            }
        }
        return action;     
}

char _license[] SEC("license") = "GPL";

