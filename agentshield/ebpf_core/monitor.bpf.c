#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define AF_INET_VALUE 2
#define AF_INET6_VALUE 10

enum event_type
{
    EVENT_EXECVE = 1,
    EVENT_CONNECT = 2,
    EVENT_SENDTO = 3,
    EVENT_RECVFROM = 4,
};

struct net_event_t
{
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
    char comm[TASK_COMM_LEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_stats SEC(".maps");

static __always_inline int submit_event(__u32 event_type, __u32 size, __u32 dst_ip4, const __u8 *dst_ip6, __u16 dst_port, __u32 ip_version)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct net_event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
    {
        __u32 key = 0;
        __u64 *drop_counter = bpf_map_lookup_elem(&drop_stats, &key);
        if (drop_counter)
        {
            __sync_fetch_and_add(drop_counter, 1);
        }
        return 0;
    }
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = (__u32)bpf_get_current_uid_gid();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    event->event_type = event_type;
    event->ip_version = ip_version;
    event->dst_ip4 = dst_ip4;
    event->dst_port = dst_port;
    event->size = size;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    if (dst_ip6)
    {
        __builtin_memcpy(event->dst_ip6, dst_ip6, sizeof(event->dst_ip6));
    }
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(void *ctx)
{
    return submit_event(EVENT_EXECVE, 0, 0, 0, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr *uservaddr = (struct sockaddr *)ctx->args[1];
    sa_family_t family = 0;
    if (!uservaddr)
    {
        return 0;
    }
    bpf_probe_read_user(&family, sizeof(family), &uservaddr->sa_family);
    if (family == AF_INET_VALUE)
    {
        struct sockaddr_in sa = {};
        bpf_probe_read_user(&sa, sizeof(sa), uservaddr);
        return submit_event(EVENT_CONNECT, 0, sa.sin_addr.s_addr, 0, bpf_ntohs(sa.sin_port), AF_INET_VALUE);
    }
    if (family == AF_INET6_VALUE)
    {
        struct sockaddr_in6 sa6 = {};
        bpf_probe_read_user(&sa6, sizeof(sa6), uservaddr);
        return submit_event(EVENT_CONNECT, 0, 0, sa6.sin6_addr.in6_u.u6_addr8, bpf_ntohs(sa6.sin6_port), AF_INET6_VALUE);
    }
    return 0;
}
