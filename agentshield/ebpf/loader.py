"""eBPF loader for AgentShield."""

from __future__ import annotations

import ctypes as ct
import ipaddress
import logging
from pathlib import Path
from typing import Callable, Optional

LOGGER = logging.getLogger(__name__)

try:
    from bcc import BPF
except ImportError:  # pragma: no cover - handled via runtime fallback
    BPF = None

EVENT_TYPES = {
    1: "execve",
    2: "connect",
    3: "sendto",
    4: "recvfrom",
}


class NetEvent(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("event_type", ct.c_uint),
        ("ip_version", ct.c_uint),
        ("dst_ip4", ct.c_uint),
        ("dst_ip6", ct.c_ubyte * 16),
        ("dst_port", ct.c_ushort),
        ("size", ct.c_uint),
        ("comm", ct.c_char * 16),
    ]


class EBPFLoader:
    def __init__(self, source_file: Optional[Path] = None) -> None:
        self.source_file = source_file or Path(__file__).with_name("monitor.c")
        self.bpf: Optional[BPF] = None
        self._callback: Optional[Callable[[dict], None]] = None

    @property
    def available(self) -> bool:
        return BPF is not None

    def load(self, callback: Callable[[dict], None]) -> bool:
        self._callback = callback
        if not self.available:
            LOGGER.warning("bcc is not available; falling back to synthetic event mode")
            return False

        LOGGER.info("Loading eBPF program from %s", self.source_file)
        self.bpf = BPF(src_file=str(self.source_file))
        self.bpf.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="trace_execve")
        self.bpf.attach_kprobe(event="__sys_connect", fn_name="trace_connect")
        self.bpf.attach_kprobe(event="__sys_sendto", fn_name="trace_sendto")
        self.bpf.attach_kprobe(event="__sys_recvfrom", fn_name="trace_recvfrom")
        self.bpf.attach_kretprobe(event="__sys_recvfrom", fn_name="trace_recvfrom_return")
        self.bpf["events"].open_perf_buffer(self._handle_event)
        return True

    def poll(self, timeout: int = 100) -> None:
        if self.bpf is None:
            raise RuntimeError("eBPF is not loaded")
        self.bpf.perf_buffer_poll(timeout=timeout)

    def cleanup(self) -> None:
        if self.bpf is not None:
            LOGGER.info("Cleaning up eBPF probes")
            self.bpf.cleanup()
            self.bpf = None

    def _handle_event(self, cpu: int, data: int, size: int) -> None:
        if self.bpf is None or self._callback is None:
            return
        event = ct.cast(data, ct.POINTER(NetEvent)).contents
        payload = {
            "timestamp_ns": int(event.timestamp_ns),
            "pid": int(event.pid),
            "uid": int(event.uid),
            "event_type": EVENT_TYPES.get(int(event.event_type), "unknown"),
            "process_name": event.comm.split(b"\x00", 1)[0].decode(errors="ignore"),
            "destination_ip": self._format_ip(event),
            "destination_port": int(event.dst_port),
            "size": int(event.size),
            "ip_version": int(event.ip_version),
            "source": "ebpf",
        }
        self._callback(payload)

    @staticmethod
    def _format_ip(event: NetEvent) -> str:
        if event.ip_version == 2 and event.dst_ip4:
            return str(ipaddress.IPv4Address(int(event.dst_ip4)))
        if event.ip_version == 10:
            raw = bytes(event.dst_ip6)
            if any(raw):
                return str(ipaddress.IPv6Address(raw))
        return "0.0.0.0"
