from __future__ import annotations

import bz2
import gzip
import json
import os
import re
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Generator, Optional


class LogFormat(Enum):
    """Supported log formats."""

    APACHE_ACCESS = "apache_access"
    APACHE_ERROR = "apache_error"
    NGINX = "nginx"
    WINDOWS_EVENT = "windows_event"
    SYSLOG = "syslog"
    SYSLOG_RFC5424 = "syslog_rfc5424"
    FIREWALL = "firewall"
    CEF = "cef"
    LEEF = "leef"
    JSON = "json"
    CSV = "csv"
    SSH_AUTH = "ssh_auth"
    LINUX_AUTH = "linux_auth"
    DNS = "dns"
    DHCP = "dhcp"
    ZEEK_HTTP = "zeek_http"
    ZEEK_CONN = "zeek_conn"
    SURICATA = "suricata"
    SNORT = "snort"
    PALO_ALTO = "palo_alto"
    FORTIGATE = "fortigate"
    CHECKPOINT = "checkpoint"
    CISCO_ASA = "cisco_asa"
    AWS_CLOUDTRAIL = "aws_cloudtrail"
    AWS_VPC_FLOW = "aws_vpc_flow"
    AZURE_AD = "azure_ad"
    UNKNOWN = "unknown"


@dataclass
class LogEntry:
    """Normalized single log line."""

    raw: str = ""
    timestamp: Optional[datetime] = None
    source_ip: str = ""
    dest_ip: str = ""
    source_port: int = 0
    dest_port: int = 0
    protocol: str = ""
    action: str = ""
    status_code: int = 0
    method: str = ""
    url: str = ""
    user_agent: str = ""
    username: str = ""
    hostname: str = ""
    process: str = ""
    pid: int = 0
    message: str = ""
    severity: str = ""
    event_id: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    duration: float = 0.0
    log_format: LogFormat = LogFormat.UNKNOWN
    extra: dict = field(default_factory=dict)
    threat_score: float = 0.0
    tags: list = field(default_factory=list)
    line_number: int = 0


TIME_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",
    "%b %d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S%z",
    "%d-%b-%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y%m%d%H%M%S",
]

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

LOG_PATTERNS = {
    LogFormat.APACHE_ACCESS: re.compile(
        r"(?P<ip>[\d\.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"
        r"\"(?P<method>\w+)\s+(?P<url>\S+)\s+HTTP/[\d\.]+\"\s+"
        r"(?P<status>\d+)\s+(?P<bytes>\S+)"
        r"(?:\s+\"(?P<referer>[^\"]+)\")?"
        r"(?:\s+\"(?P<ua>[^\"]+)\")?",
        re.IGNORECASE,
    ),
    LogFormat.NGINX: re.compile(
        r"(?P<ip>[\d\.a-f:]+)\s+-\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"
        r"\"(?P<method>\w+)\s+(?P<url>\S+)\s+HTTP/[\d\.]+\"\s+"
        r"(?P<status>\d+)\s+(?P<bytes>\d+)\s+"
        r"\"(?P<referer>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\"",
        re.IGNORECASE,
    ),
    LogFormat.SYSLOG: re.compile(
        r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?\s*:\s+"
        r"(?P<message>.+)",
        re.IGNORECASE,
    ),
    LogFormat.SYSLOG_RFC5424: re.compile(
        r"<(?P<priority>\d+)>(?P<version>\d+)\s+(?P<timestamp>\S+)\s+"
        r"(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<pid>\S+)\s+"
        r"(?P<msgid>\S+)\s+(?P<structured>[^\s]+)\s+(?P<message>.+)",
        re.IGNORECASE,
    ),
    LogFormat.SSH_AUTH: re.compile(
        r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.+)",
        re.IGNORECASE,
    ),
    LogFormat.CEF: re.compile(
        r"CEF:(?P<version>\d+)\|(?P<vendor>[^|]+)\|(?P<product>[^|]+)\|"
        r"(?P<dev_version>[^|]+)\|(?P<sig_id>[^|]+)\|(?P<name>[^|]+)\|"
        r"(?P<severity>[^|]+)\|(?P<extension>.+)",
        re.IGNORECASE,
    ),
    LogFormat.CISCO_ASA: re.compile(
        r"%ASA-(?P<severity>\d)-(?P<msgid>\d+):\s+(?P<message>.+)", re.IGNORECASE
    ),
    LogFormat.AWS_VPC_FLOW: re.compile(
        r"(?P<version>\d+)\s+(?P<account_id>\d+)\s+(?P<interface_id>\S+)\s+"
        r"(?P<srcaddr>\S+)\s+(?P<dstaddr>\S+)\s+(?P<srcport>\d+)\s+"
        r"(?P<dstport>\d+)\s+(?P<protocol>\d+)\s+(?P<packets>\d+)\s+"
        r"(?P<bytes>\d+)\s+(?P<start>\d+)\s+(?P<end>\d+)\s+"
        r"(?P<action>\w+)\s+(?P<status>\w+)",
        re.IGNORECASE,
    ),
}


def parse_timestamp(ts_str: str) -> Optional[datetime]:
    if not ts_str:
        return None
    ts_str = ts_str.strip()
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def parse_syslog_time(month: str, day: str, time_str: str) -> Optional[datetime]:
    try:
        month_num = MONTHS.get(month[:3].capitalize(), 1)
        now = datetime.now()
        return datetime(
            now.year,
            month_num,
            int(day),
            int(time_str[:2]),
            int(time_str[3:5]),
            int(time_str[6:8]),
        )
    except Exception:
        return None


class FormatDetector:
    SIGNATURES = {
        LogFormat.CEF: [r"^CEF:\d+\|"],
        LogFormat.LEEF: [r"^LEEF:\d+\|"],
        LogFormat.CISCO_ASA: [r"%ASA-\d-\d+:"],
        LogFormat.SURICATA: [r"\"event_type\":", r"\"alert\":"],
        LogFormat.AWS_VPC_FLOW: [r"^\d+ \d{12} eni-"],
        LogFormat.AWS_CLOUDTRAIL: [r"\"eventSource\":", r"\"eventName\":"],
        LogFormat.SNORT: [r"\[\d+:\d+:\d+\]"],
        LogFormat.APACHE_ACCESS: [r"(GET|POST|PUT|DELETE|HEAD).*HTTP/\d\.\d.*\d{3}"],
        LogFormat.SSH_AUTH: [r"sshd\[\d+\]", r"(Accepted|Failed).*password"],
        LogFormat.SYSLOG_RFC5424: [r"^<\d+>\d+ \d{4}-\d{2}-\d{2}T"],
        LogFormat.SYSLOG: [r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"],
        LogFormat.LINUX_AUTH: [r"(sudo|PAM|login)\["],
        LogFormat.FORTIGATE: [r"devname=.*logid=.*type="],
        LogFormat.CHECKPOINT: [r"action=.*src=.*dst=.*proto="],
        LogFormat.JSON: [r"^\s*\{"],
    }

    FILENAME_HINTS = {
        "access.log": LogFormat.APACHE_ACCESS,
        "error.log": LogFormat.APACHE_ERROR,
        "nginx": LogFormat.NGINX,
        "syslog": LogFormat.SYSLOG,
        "auth.log": LogFormat.LINUX_AUTH,
        "secure": LogFormat.LINUX_AUTH,
        "eve.json": LogFormat.SURICATA,
        "suricata": LogFormat.SURICATA,
        "zeek": LogFormat.ZEEK_HTTP,
        "cloudtrail": LogFormat.AWS_CLOUDTRAIL,
        "vpc-flow": LogFormat.AWS_VPC_FLOW,
    }

    @classmethod
    def detect(cls, sample_lines: list) -> LogFormat:
        sample = "\n".join(sample_lines[:20])
        for fmt, patterns in cls.SIGNATURES.items():
            if all(re.search(p, sample, re.IGNORECASE | re.MULTILINE) for p in patterns):
                return fmt
        return LogFormat.UNKNOWN

    @classmethod
    def from_filename(cls, filename: str) -> Optional[LogFormat]:
        fn = filename.lower()
        for key, fmt in cls.FILENAME_HINTS.items():
            if key in fn:
                return fmt
        return None


class LogFileReader:
    @staticmethod
    def open_file(filepath: str):
        fp = filepath.lower()
        if fp.endswith(".gz"):
            return gzip.open(filepath, "rt", encoding="utf-8", errors="replace")
        if fp.endswith(".bz2"):
            return bz2.open(filepath, "rt", encoding="utf-8", errors="replace")
        if fp.endswith(".zip"):
            zf = zipfile.ZipFile(filepath, "r")
            names = zf.namelist()
            if names:
                return zf.open(names[0])
        return open(filepath, "r", encoding="utf-8", errors="replace")

    @staticmethod
    def read_lines(filepath: str, max_lines: int = 0) -> Generator[str, None, None]:
        count = 0
        with LogFileReader.open_file(filepath) as f:
            for line in f:
                if isinstance(line, bytes):
                    line = line.decode("utf-8", errors="replace")
                line = line.rstrip("\n\r")
                if line.strip():
                    yield line
                    count += 1
                    if max_lines and count >= max_lines:
                        break


class BaseParser:
    def parse_line(self, line: str, line_num: int = 0) -> Optional[LogEntry]:
        raise NotImplementedError

    def parse_file(
        self, filepath: str, progress_cb=None, max_lines: int = 0
    ) -> Generator[LogEntry, None, None]:
        for i, line in enumerate(LogFileReader.read_lines(filepath, max_lines)):
            entry = self.parse_line(line, i + 1)
            if entry:
                yield entry
            if progress_cb and i % 1000 == 0:
                progress_cb(i, i)


class ApacheAccessParser(BaseParser):
    def parse_line(self, line: str, line_num: int = 0) -> Optional[LogEntry]:
        m = LOG_PATTERNS[LogFormat.APACHE_ACCESS].match(line)
        if not m:
            return None
        e = LogEntry(raw=line, log_format=LogFormat.APACHE_ACCESS, line_number=line_num)
        e.source_ip = m.group("ip")
        e.username = m.group("user") if m.group("user") != "-" else ""
        e.timestamp = parse_timestamp(m.group("time"))
        e.method = m.group("method")
        e.url = m.group("url")
        e.status_code = int(m.group("status"))
        bytes_val = m.group("bytes")
        e.bytes_sent = int(bytes_val) if bytes_val.isdigit() else 0
        try:
            e.user_agent = m.group("ua") or ""
        except IndexError:
            pass
        e.message = f"{e.method} {e.url} [{e.status_code}]"
        return e


class NginxParser(BaseParser):
    def parse_line(self, line: str, line_num: int = 0) -> Optional[LogEntry]:
        m = LOG_PATTERNS[LogFormat.NGINX].match(line)
        if not m:
            return None
        e = LogEntry(raw=line, log_format=LogFormat.NGINX, line_number=line_num)
        e.source_ip = m.group("ip")
        e.username = m.group("user") if m.group("user") != "-" else ""
        e.timestamp = parse_timestamp(m.group("time"))
        e.method = m.group("method")
        e.url = m.group("url")
        e.status_code = int(m.group("status"))
        e.bytes_sent = int(m.group("bytes") or 0)
        e.user_agent = m.group("ua") or ""
        e.message = f"{e.method} {e.url} [{e.status_code}]"
        return e


class SyslogParser(BaseParser):
    def parse_line(self, line: str, line_num: int = 0) -> Optional[LogEntry]:
        m = LOG_PATTERNS[LogFormat.SYSLOG_RFC5424].match(line)
        if m:
            e = LogEntry(raw=line, log_format=LogFormat.SYSLOG_RFC5424, line_number=line_num)
            e.timestamp = parse_timestamp(m.group("timestamp"))
            e.hostname = m.group("host")
            e.process = m.group("app")
            e.message = m.group("message")
            priority = int(m.group("priority"))
            sev_names = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
            e.severity = sev_names[priority % 8]
            return e

        m = LOG_PATTERNS[LogFormat.SYSLOG].match(line)
        if not m:
            return None
        e = LogEntry(raw=line, log_format=LogFormat.SYSLOG, line_number=line_num)
        e.timestamp = parse_syslog_time(m.group("month"), m.group("day"), m.group("time"))
        e.hostname = m.group("host")
        e.process = m.group("process")
        e.pid = int(m.group("pid")) if m.group("pid") else 0
        e.message = m.group("message")
        return e


class SSHAuthParser(BaseParser):
    ACCEPTED_RE = re.compile(
        r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>[\d\.]+) port (?P<port>\d+)"
    )
    FAILED_RE = re.compile(
        r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d\.]+) port (?P<port>\d+)"
    )
    INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d\.]+)")

    def parse_line(self, line: str, line_num: int = 0) -> Optional[LogEntry]:
        m = LOG_PATTERNS[LogFormat.SSH_AUTH].match(line)
        if not m:
            return None

        e = LogEntry(raw=line, log_format=LogFormat.SSH_AUTH, line_number=line_num)
        e.timestamp = parse_syslog_time(m.group("month"), m.group("day"), m.group("time"))
        e.hostname = m.group("host")
        e.pid = int(m.group("pid")) if m.group("pid") else 0
        e.message = m.group("message")
        e.process = "sshd"
        msg = m.group("message")

        am = self.ACCEPTED_RE.search(msg)
        if am:
            e.action = "ACCEPTED"
            e.username = am.group("user")
            e.source_ip = am.group("ip")
            e.source_port = int(am.group("port"))
            e.method = am.group("method")
            e.severity = "info"
            return e

        fm = self.FAILED_RE.search(msg)
        if fm:
            e.action = "FAILED"
            e.username = fm.group("user")
            e.source_ip = fm.group("ip")
            e.source_port = int(fm.group("port"))
            e.severity = "warning"
            e.threat_score = 30.0
            return e

        im = self.INVALID_RE.search(msg)
        if im:
            e.action = "INVALID_USER"
            e.username = im.group("user")
            e.source_ip = im.group("ip")
            e.severity = "warning"
            e.threat_score = 40.0
            return e

        return e


class CEFParser(BaseParser):
    def parse_line(self, line: str, line_num: int = 0) -> Optional[LogEntry]:
        m = LOG_PATTERNS[LogFormat.CEF].match(line)
        if not m:
            return None

        e = LogEntry(raw=line, log_format=LogFormat.CEF, line_number=line_num)
        e.severity = m.group("severity")
        e.message = m.group("name")

        ext = m.group("extension")
        kv_pattern = re.compile(
            r"(\w+)=((?:[^\\=\s]|\\.)+(?:\s(?!\w+=)(?:[^\\=\s]|\\.)+)*)"
        )
        for kv in kv_pattern.finditer(ext):
            key, val = kv.group(1), kv.group(2).strip()
            if key == "src":
                e.source_ip = val
            elif key == "dst":
                e.dest_ip = val
            elif key == "spt":
                e.source_port = int(val) if val.isdigit() else 0
            elif key == "dpt":
                e.dest_port = int(val) if val.isdigit() else 0
            elif key == "suser":
                e.username = val
            elif key == "act":
                e.action = val
            elif key == "proto":
                e.protocol = val
            elif key == "in":
                e.bytes_recv = int(val) if val.isdigit() else 0
            elif key == "out":
                e.bytes_sent = int(val) if val.isdigit() else 0
            elif key == "start":
                e.timestamp = parse_timestamp(val)
            else:
                e.extra[key] = val

        e.threat_score = float(m.group("severity")) * 10 if m.group("severity").isdigit() else 0
        return e


class JSONParser(BaseParser):
    def parse_line(self, line: str, line_num: int = 0) -> Optional[LogEntry]:
        line = line.strip()
        if not line or not line.startswith("{"):
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        e = LogEntry(raw=line, log_format=LogFormat.JSON, line_number=line_num)
        e.extra = data

        if "event_type" in data:
            e.log_format = LogFormat.SURICATA
            ts = data.get("timestamp", "")
            e.timestamp = parse_timestamp(ts) if ts else None
            e.source_ip = data.get("src_ip", "")
            e.dest_ip = data.get("dest_ip", "")
            e.source_port = data.get("src_port", 0)
            e.dest_port = data.get("dest_port", 0)
            e.protocol = data.get("proto", "")

            if data.get("event_type") == "alert":
                alert = data.get("alert", {})
                e.severity = str(alert.get("severity", ""))
                e.message = alert.get("signature", "")
                e.action = alert.get("action", "")
                sev_num = int(str(alert.get("severity", 4)))
                e.threat_score = (5 - min(sev_num, 4)) * 25.0
                e.tags.append("IDS_ALERT")
        else:
            for ts_key in ["timestamp", "time", "@timestamp", "date"]:
                if ts_key in data:
                    e.timestamp = parse_timestamp(str(data[ts_key]))
                    break
            e.source_ip = str(
                data.get(
                    "src_ip",
                    data.get("source_ip", data.get("clientip", data.get("remote_addr", ""))),
                )
            )
            e.dest_ip = str(data.get("dst_ip", data.get("dest_ip", "")))
            e.message = str(data.get("message", data.get("msg", "")))
            e.severity = str(data.get("severity", data.get("level", "")))
            e.username = str(data.get("user", data.get("username", "")))

        return e


class CiscoASAParser(BaseParser):
    CONN_RE = re.compile(
        r"(?:Built|Teardown)\s+(?P<proto>\w+)\s+connection\s+\d+\s+for\s+"
        r"(?P<outif>\S+):(?P<src>[\d\.]+)/(?P<sport>\d+).*?to\s+"
        r"(?P<inif>\S+):(?P<dst>[\d\.]+)/(?P<dport>\d+)"
    )

    def parse_line(self, line: str, line_num: int = 0) -> Optional[LogEntry]:
        m = LOG_PATTERNS[LogFormat.CISCO_ASA].search(line)
        if not m:
            return None
        e = LogEntry(raw=line, log_format=LogFormat.CISCO_ASA, line_number=line_num)
        e.event_id = int(m.group("msgid"))
        e.message = m.group("message")
        sev_map = {
            "1": "critical",
            "2": "critical",
            "3": "error",
            "4": "warning",
            "5": "notice",
            "6": "info",
            "7": "debug",
        }
        e.severity = sev_map.get(m.group("severity"), "info")

        cm = self.CONN_RE.search(m.group("message"))
        if cm:
            e.protocol = cm.group("proto")
            e.source_ip = cm.group("src")
            e.source_port = int(cm.group("sport"))
            e.dest_ip = cm.group("dst")
            e.dest_port = int(cm.group("dport"))
        if not e.source_ip:
            ips = IP_PATTERN.findall(e.message)
            if ips:
                e.source_ip = ips[0]
            if len(ips) > 1:
                e.dest_ip = ips[1]
        return e


class FortiGateParser(BaseParser):
    KV_RE = re.compile(r'(?P<k>[A-Za-z0-9_]+)=(?P<v>"[^"]*"|\S+)')

    def parse_line(self, line: str, line_num: int = 0) -> Optional[LogEntry]:
        items = self.KV_RE.findall(line)
        if len(items) < 4:
            return None

        data: dict[str, str] = {}
        for k, v in items:
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            data[k.lower()] = v

        if not any(k in data for k in ("devname", "devid", "logid")):
            return None

        e = LogEntry(raw=line, log_format=LogFormat.FORTIGATE, line_number=line_num)

        dt = (data.get("date", "") + " " + data.get("time", "")).strip()
        if dt:
            e.timestamp = parse_timestamp(dt)
            if not e.timestamp:
                try:
                    e.timestamp = datetime.strptime(dt, "%Y-%m-%d %H:%M:%S")
                except Exception:
                    pass

        e.source_ip = data.get("srcip", "")
        e.dest_ip = data.get("dstip", "")
        try:
            e.source_port = int(data.get("srcport", "0") or 0)
        except Exception:
            e.source_port = 0
        try:
            e.dest_port = int(data.get("dstport", "0") or 0)
        except Exception:
            e.dest_port = 0

        proto = data.get("proto", "")
        proto_map = {"1": "ICMP", "6": "TCP", "17": "UDP", "58": "ICMPv6"}
        e.protocol = proto_map.get(proto, proto)

        act = (data.get("action", "") or "").lower()
        if act in ("accept", "allow", "permit"):
            e.action = "ACCEPTED"
        elif act in ("deny", "block", "drop", "reject"):
            e.action = "BLOCKED"
        else:
            e.action = act.upper() if act else ""

        e.severity = (data.get("level", "") or data.get("severity", "") or "").lower()
        e.message = data.get("msg") or data.get("logdesc") or ""

        e.extra.update(
            {
                "type": data.get("type", ""),
                "subtype": data.get("subtype", ""),
                "devname": data.get("devname", ""),
                "devid": data.get("devid", ""),
                "vd": data.get("vd", ""),
                "policyid": data.get("policyid", ""),
                "service": data.get("service", ""),
                "app": data.get("app", ""),
                "srcintf": data.get("srcintf", ""),
                "dstintf": data.get("dstintf", ""),
                "srcintfrole": data.get("srcintfrole", ""),
                "dstintfrole": data.get("dstintfrole", ""),
            }
        )

        return e


class AWSVPCFlowParser(BaseParser):
    def parse_line(self, line: str, line_num: int = 0) -> Optional[LogEntry]:
        if line.startswith("version") or line.startswith("#"):
            return None

        m = LOG_PATTERNS[LogFormat.AWS_VPC_FLOW].match(line)
        if not m:
            return None

        e = LogEntry(raw=line, log_format=LogFormat.AWS_VPC_FLOW, line_number=line_num)
        e.source_ip = m.group("srcaddr")
        e.dest_ip = m.group("dstaddr")
        e.source_port = int(m.group("srcport"))
        e.dest_port = int(m.group("dstport"))

        proto_map = {"1": "ICMP", "6": "TCP", "17": "UDP", "58": "ICMPv6"}
        e.protocol = proto_map.get(m.group("protocol"), m.group("protocol"))

        e.bytes_sent = int(m.group("bytes"))
        e.action = m.group("action")
        try:
            e.timestamp = datetime.fromtimestamp(int(m.group("start")))
        except Exception:
            pass
        e.message = (
            f"{e.action} {e.protocol} {e.source_ip}:{e.source_port} → {e.dest_ip}:{e.dest_port}"
        )
        return e


class WindowsEventParser(BaseParser):
    CRITICAL_EVENTS = {
        1102: ("Güvenlik Logu Silindi", "critical", 95),
        4719: ("Denetim Politikası Değiştirildi", "critical", 85),
        7045: ("Yeni Servis Kuruldu", "high", 70),
        4698: ("Zamanlanmış Görev Oluşturuldu", "high", 70),
        4688: ("Process Başlatıldı", "info", 10),
        4720: ("Kullanıcı Hesabı Oluşturuldu", "medium", 50),
        4625: ("Başarısız Oturum Açma", "warning", 35),
        4624: ("Başarılı Oturum Açma", "info", 5),
        4648: ("Açık Kimlik Bilgisiyle Oturum", "medium", 55),
        4672: ("Özel Ayrıcalıklar Atandı", "medium", 45),
    }

    def parse_line(self, line: str, line_num: int = 0) -> Optional[LogEntry]:
        if "<Event>" in line or "<EventID>" in line:
            return self._parse_xml(line, line_num)
        parts = line.split(",")
        if len(parts) >= 5:
            return self._parse_csv(parts, line, line_num)
        return None

    def _parse_xml(self, line: str, line_num: int) -> Optional[LogEntry]:
        e = LogEntry(raw=line, log_format=LogFormat.WINDOWS_EVENT, line_number=line_num)
        eid = re.search(r"<EventID>(\d+)</EventID>", line)
        if eid:
            e.event_id = int(eid.group(1))
        tc = re.search(r"SystemTime='([^']+)'", line)
        if tc:
            e.timestamp = parse_timestamp(tc.group(1))
        comp = re.search(r"<Computer>([^<]+)</Computer>", line)
        if comp:
            e.hostname = comp.group(1)
        msg = re.search(r"<Message>([^<]+)</Message>", line, re.DOTALL)
        if msg:
            e.message = msg.group(1).strip()
        self._enrich_event(e)
        return e

    def _parse_csv(self, parts: list, raw: str, line_num: int) -> Optional[LogEntry]:
        e = LogEntry(raw=raw, log_format=LogFormat.WINDOWS_EVENT, line_number=line_num)
        try:
            e.timestamp = parse_timestamp(parts[0].strip('"'))
            if len(parts) > 2:
                eid_str = parts[2].strip('"')
                e.event_id = int(eid_str) if eid_str.isdigit() else 0
            if len(parts) > 3:
                e.hostname = parts[3].strip('"')
        except (IndexError, ValueError):
            pass
        self._enrich_event(e)
        return e

    def _enrich_event(self, e: LogEntry) -> None:
        if e.event_id in self.CRITICAL_EVENTS:
            desc, sev, score = self.CRITICAL_EVENTS[e.event_id]
            if not e.message:
                e.message = desc
            e.severity = sev
            e.threat_score = float(score)


PARSER_MAP = {
    LogFormat.APACHE_ACCESS: ApacheAccessParser,
    LogFormat.NGINX: NginxParser,
    LogFormat.SYSLOG: SyslogParser,
    LogFormat.SYSLOG_RFC5424: SyslogParser,
    LogFormat.SSH_AUTH: SSHAuthParser,
    LogFormat.LINUX_AUTH: SSHAuthParser,
    LogFormat.CEF: CEFParser,
    LogFormat.JSON: JSONParser,
    LogFormat.SURICATA: JSONParser,
    LogFormat.CISCO_ASA: CiscoASAParser,
    LogFormat.FORTIGATE: FortiGateParser,
    LogFormat.AWS_VPC_FLOW: AWSVPCFlowParser,
    LogFormat.WINDOWS_EVENT: WindowsEventParser,
}


def get_parser(fmt: LogFormat) -> BaseParser:
    return PARSER_MAP.get(fmt, SyslogParser)()


def auto_parse_file(filepath: str, progress_cb=None, max_lines: int = 0):
    sample = list(LogFileReader.read_lines(filepath, max_lines=50))
    fmt = FormatDetector.from_filename(os.path.basename(filepath))
    if not fmt:
        fmt = FormatDetector.detect(sample)
    parser = get_parser(fmt)
    entries = list(parser.parse_file(filepath, progress_cb, max_lines))
    return entries, fmt

