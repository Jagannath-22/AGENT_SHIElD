#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <linux/sched.h>
#include <net/sock.h>

#define MAX_COMM 16
#define AF_INET_VALUE 2
#define AF_INET6_VALUE 10

enum event_type {
    EVENT_EXECVE = 1,
    EVENT_CONNECT = 2,
    EVENT_SENDTO = 3,
    EVENT_RECVFROM = 4,
};

struct net_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 uid;
    u32 event_type;
    u32 ip_version;
    u32 dst_ip4;
    unsigned __int128 dst_ip6;
    u16 dst_port;
    u32 size;
    char comm[MAX_COMM];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(active_recv_sizes, u32, u64);

static __always_inline int submit_event(struct pt_regs *ctx, u32 event_type, u32 size, u32 dst_ip4,
                                        unsigned __int128 dst_ip6, u16 dst_port, u32 ip_version) {
    struct net_event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = pid_tgid >> 32;
    event.uid = (u32)uid_gid;
    event.event_type = event_type;
    event.ip_version = ip_version;
    event.dst_ip4 = dst_ip4;
    event.dst_ip6 = dst_ip6;
    event.dst_port = dst_port;
    event.size = size;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int trace_execve(struct pt_regs *ctx) {
    return submit_event(ctx, EVENT_EXECVE, 0, 0, 0, 0, 0);
}

int trace_connect(struct pt_regs *ctx, int fd, struct sockaddr *uservaddr, int addrlen) {
    if (!uservaddr) {
        return 0;
    }

    sa_family_t family = 0;
    bpf_probe_read_user(&family, sizeof(family), &uservaddr->sa_family);

    if (family == AF_INET_VALUE) {
        struct sockaddr_in sa = {};
        bpf_probe_read_user(&sa, sizeof(sa), uservaddr);
        return submit_event(ctx, EVENT_CONNECT, 0, sa.sin_addr.s_addr, 0, ntohs(sa.sin_port), AF_INET_VALUE);
    }

    if (family == AF_INET6_VALUE) {
        struct sockaddr_in6 sa6 = {};
        unsigned __int128 ip6 = 0;
        bpf_probe_read_user(&sa6, sizeof(sa6), uservaddr);
        bpf_probe_read_kernel(&ip6, sizeof(ip6), &sa6.sin6_addr.in6_u.u6_addr32);
        return submit_event(ctx, EVENT_CONNECT, 0, 0, ip6, ntohs(sa6.sin6_port), AF_INET6_VALUE);
    }

    return 0;
}

int trace_sendto(struct pt_regs *ctx, int fd, void *buff, size_t len, int flags, struct sockaddr *dest_addr, int addrlen) {
    u32 dst_ip4 = 0;
    unsigned __int128 dst_ip6 = 0;
    u16 dst_port = 0;
    u32 ip_version = 0;

    if (dest_addr) {
        sa_family_t family = 0;
        bpf_probe_read_user(&family, sizeof(family), &dest_addr->sa_family);

        if (family == AF_INET_VALUE) {
            struct sockaddr_in sa = {};
            bpf_probe_read_user(&sa, sizeof(sa), dest_addr);
            dst_ip4 = sa.sin_addr.s_addr;
            dst_port = ntohs(sa.sin_port);
            ip_version = AF_INET_VALUE;
        } else if (family == AF_INET6_VALUE) {
            struct sockaddr_in6 sa6 = {};
            bpf_probe_read_user(&sa6, sizeof(sa6), dest_addr);
            bpf_probe_read_kernel(&dst_ip6, sizeof(dst_ip6), &sa6.sin6_addr.in6_u.u6_addr32);
            dst_port = ntohs(sa6.sin6_port);
            ip_version = AF_INET6_VALUE;
        }
    }

    return submit_event(ctx, EVENT_SENDTO, (u32)len, dst_ip4, dst_ip6, dst_port, ip_version);
}

int trace_recvfrom(struct pt_regs *ctx, int fd, void *buff, size_t len, unsigned int flags, struct sockaddr *src_addr, int *addrlen) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 size = len;
    active_recv_sizes.update(&pid, &size);
    return 0;
}

int trace_recvfrom_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *size = active_recv_sizes.lookup(&pid);
    if (!size) {
        return 0;
    }

    int ret = PT_REGS_RC(ctx);
    if (ret > 0) {
        submit_event(ctx, EVENT_RECVFROM, ret, 0, 0, 0, 0);
    }

    active_recv_sizes.delete(&pid);
    return 0;
}
