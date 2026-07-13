// Package datapath loads and drives the minuteman XDP/eBPF datapath
// (bpf/datapath.bpf.c). It is the only package that talks to cilium/ebpf or
// knows about BPF map layouts; callers configure and attach the datapath
// through the exported Loader API without touching BPF details directly.
package datapath

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -cflags "-O2 -g -Wall -Wno-compare-distinct-pointer-types" -type b4_config -type next_hop -type lan_config -type fanout_config -type ipv6_rss_config bpf ../../bpf/datapath.bpf.c -- -I../../bpf
