CLANG ?= clang
BPFTOOL ?= bpftool
CC ?= gcc
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf 2>/dev/null)

all: vmlinux.h monitor.bpf.o monitor.skel.h loader

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

monitor.bpf.o: monitor.bpf.c vmlinux.h
	$(CLANG) -target bpf -D__TARGET_ARCH_x86 -O2 -g -c monitor.bpf.c -o monitor.bpf.o

monitor.skel.h: monitor.bpf.o
	$(BPFTOOL) gen skeleton monitor.bpf.o > monitor.skel.h

loader: loader.c monitor.skel.h
	$(CC) -O2 -g loader.c -o loader $(LIBBPF_CFLAGS) $(LIBBPF_LIBS) -lelf -lz

clean:
	rm -f vmlinux.h monitor.bpf.o monitor.skel.h loader
