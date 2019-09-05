#!/usr/bin/python
#
# xdp_drop_count.py Drop incoming packets on XDP layer and count for which
#                   protocol type
#
# Copyright (c) 2016 PLUMgrid
# Copyright (c) 2016 Jan Ruth
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from bcc.utils import printb
import time
import sys
import csv
import socket
import struct

flags = 0
def usage():
    print("Usage: {0} <ifdev> <filename>".format(sys.argv[0]))
    print("e.g.: {0} eth0 policy.csv\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) < 3:
    usage()

device = sys.argv[1]
filename = sys.argv[2]

pToV = {'tcp':6, 'udp':17}

def dottedQuadToNum(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('>L',socket.inet_aton(ip))[0]

def ipToN(ip):
    h = dottedQuadToNum(ip)
    return socket.htonl(h)

def parse_policy_file(file_name):
    input_file = csv.DictReader(open(file_name))
    policy_arr = []
    for row in input_file:
        if (row['proto'] == None or row['proto'] == ''):
            continue
        rtop = {'proto':row['proto']}
        for key in row:
            val = row[key]
            if (val != None and val != ''):
                rtop[key] = val
        policy_arr.append(rtop)
    return policy_arr

def create_filter_cond_for_policy(policy, index):
    filter_str = "if ("

    if (pToV[policy['proto']] == 6):
        filter_str = filter_str + " is_tcp "
    elif (pToV[policy['proto']] == 17):
        filter_str = filter_str + " is_udp "
    else:
        return ""
    if (policy.get('sip') != None):
        filter_str = filter_str + " && src_ip == %d " % ipToN(policy.get('sip'))
    
    if (policy.get('dip') != None):
        filter_str = filter_str + " && dest_ip == %d " % ipToN(policy.get('dip'))
    
    if (policy.get('sp') != None):
        filter_str = filter_str + " && src_port == %d " % socket.htons(int(policy.get('sp')))
    
    if (policy.get('dp') != None):
        filter_str = filter_str + " && dest_port == %d " % socket.htons(int(policy.get('dp')))

    filter_str = filter_str + " ) { \n bpf_trace_printk(\"Policy %d passed \\n\"); goto pass;\n}" % index
    return filter_str

def create_filter_conditions(policies):
    filter_cond = ""
    count = 1
    for policy in policies:
        temp_cond = create_filter_cond_for_policy(policy, count)
        count = count + 1
        filter_cond = filter_cond + "\n" + temp_cond
    return filter_cond



policies = parse_policy_file(filename)
filters = ""
filters += create_filter_conditions(policies)

print filters

mode = BPF.XDP
#mode = BPF.SCHED_CLS

ret = "XDP_DROP"
ctxtype = "xdp_md"

prog_text = """
#define KBUILD_MODNAME "myfilter"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

BPF_TABLE("percpu_array", uint32_t, long, dropcnt, 256);

int xdp_prog1(struct xdp_md *ctx) {

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;

    // drop packets
    int rc = XDP_DROP; // let pass XDP_PASS or redirect to tx via XDP_TX
    long *value;
    uint16_t h_proto;
    uint64_t nh_off = 0;
    uint32_t index;

    nh_off = sizeof(*eth);

    if (data + nh_off  > data_end)
        return rc;

    h_proto = eth->h_proto;

    // parse double vlans
    #pragma unroll
    for (int i=0; i<2; i++) {
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
            struct vlan_hdr *vhdr;

            vhdr = data + nh_off;
            nh_off += sizeof(struct vlan_hdr);
            if (data + nh_off > data_end)
                return rc;
                h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

    if (h_proto != htons(ETH_P_IP))
        goto drop;
    
    struct iphdr *iph = data + nh_off;
    if (iph+1 > data_end) {
        goto drop;
    }
    int iphdrsz = (iph->ihl & 0xf) * 4;

    if (((void *)iph) + iphdrsz > data_end) {
        goto drop;
    }

    int proto = iph->protocol;

    int is_tcp, is_udp;
    u32 src_ip, dest_ip;
    u16 src_port, dest_port;

    is_tcp = (proto == IPPROTO_TCP);
    is_udp = (proto == IPPROTO_UDP);
    src_ip = iph->saddr;
    dest_ip = iph->daddr;

    if (!is_tcp && !is_udp) {
        goto drop;
    }

    if (is_tcp) {
        struct tcphdr *tp = ((void *)iph) + iphdrsz;
        if (tp +1 > data_end) {
            goto drop;
        }
        src_port = tp->source;
        dest_port = tp->dest;
        bpf_trace_printk("Processing tcp\\n");

    }

    if (is_udp) {
        struct udphdr *up = ((void *)iph) + iphdrsz;
        if (up + 1 > data_end) {
            goto drop;
        } 
        src_port = up->source;
        dest_port = up->dest;
        bpf_trace_printk("Processing UDP\\n");
    }

    FILTER_COND
 
drop:
    rc = XDP_DROP;
    goto done;

pass:
    bpf_trace_printk("proto:%d,sip:%d,sp:%d\\n", proto, src_ip, src_port);
    bpf_trace_printk("dip:%d,dp:%d\\n", dest_ip, dest_port); 
    rc = XDP_PASS;

done:
    return rc;
}
"""

prog_text = prog_text.replace("FILTER_COND", filters)

print prog_text

# exit()

# load BPF program
b = BPF(text =prog_text , cflags=["-w"])

fn = b.load_func("xdp_prog1", mode)

b.attach_xdp(device, fn, flags)

print("Printing drops per IP protocol-number, hit CTRL+C to stop")
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        printb(b"%-18s: %s" % (ts, msg))
    except KeyboardInterrupt:
        print("Removing filter from device")
        break;

b.remove_xdp(device, 0)

