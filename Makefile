ebpf_policer:
	clang -D __BPF_TRACING__ -g -Wall -Wno-compare-distinct-pointer-types -target bpf -O2 -emit-llvm -c ebpf_policer.c -o ebpf_policer.ll -I/root/ebpf/xdp-tutorial/libbpf/src -I/root/ebpf/xdp-tutorial/headers
	llc -march=bpf -filetype=obj -o  ebpf_policer.o ebpf_policer.ll

clean:
	rm ebpf_policer.ll
	rm ebpf_policer.o
