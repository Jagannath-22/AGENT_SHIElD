#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "monitor.skel.h"

static volatile sig_atomic_t exiting = 0;

struct net_event_t {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u32 ppid;
    __u32 event_type;
    __u32 ip_version;
    __u32 dst_ip4;
    __u8 dst_ip6[16];
    __u16 dst_port;
    __u32 size;
    char comm[16];
};

static void sig_handler(int signo)
{
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct net_event_t *event = data;
    char ip_buffer[INET6_ADDRSTRLEN] = "0.0.0.0";
    if (event->ip_version == AF_INET) {
        struct in_addr addr = {.s_addr = event->dst_ip4};
        inet_ntop(AF_INET, &addr, ip_buffer, sizeof(ip_buffer));
    } else if (event->ip_version == AF_INET6) {
        inet_ntop(AF_INET6, event->dst_ip6, ip_buffer, sizeof(ip_buffer));
    }
    printf("{\"timestamp_ns\":%llu,\"pid\":%u,\"uid\":%u,\"ppid\":%u,\"event_type\":%u,\"process_name\":\"%s\",\"destination_ip\":\"%s\",\"destination_port\":%u,\"size\":%u,\"ip_version\":%u,\"source\":\"core-ebpf\"}\n",
           event->timestamp_ns, event->pid, event->uid, event->ppid, event->event_type, event->comm, ip_buffer, event->dst_port, event->size, event->ip_version);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct monitor_bpf *skel;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load skeleton\n");
        return 1;
    }
    err = monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach skeleton: %d\n", err);
        monitor_bpf__destroy(skel);
        return 1;
    }
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        monitor_bpf__destroy(skel);
        return 1;
    }
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "ring buffer poll failed: %d\n", err);
            break;
        }
    }
    ring_buffer__free(rb);
    monitor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
