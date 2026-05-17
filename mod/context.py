"""
context.py
----------
Shared Context Object — يمر عبر كل المراحل ويتراكم فيه كل النتائج.
كل module يقرأ منه ويكتب فيه.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import uuid


@dataclass
class Host:
    host_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    ip_address: str = ""
    hostname: str = ""
    os_type: str = "UNKNOWN"        # WINDOWS | LINUX | UNKNOWN
    is_alive: bool = True
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    services: list = field(default_factory=list)   # list of Service dicts
    vulnerabilities: list = field(default_factory=list)
    exploit_attempts: list = field(default_factory=list)
    post_exploitation: dict = field(default_factory=dict)
    mitre_mappings: list = field(default_factory=list)


@dataclass
class ScanContext:
    """
    الـ Context الرئيسي — يُنشأ في main.py ويُمرَّر لكل module.
    """
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_scope: str = ""
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: Optional[str] = None
    status: str = "RUNNING"         # RUNNING | DONE | HALTED | ERROR

    # نتائج كل مرحلة
    hosts: list = field(default_factory=list)          # list of Host objects
    rule_log: list = field(default_factory=list)       # سجل كل قرار اتُّخذ
    errors: list = field(default_factory=list)
    report_path: Optional[str] = None

    def log_rule(self, rule_id: str, condition: str, action: str):
        """يسجل كل قرار Rule مع وقته — للـ Explainability."""
        entry = {
            "rule": rule_id,
            "condition": condition,
            "action": action,
            "timestamp": datetime.now().isoformat()
        }
        self.rule_log.append(entry)
        print(f"  [RULE {rule_id}] {condition} → {action}")

    def log_error(self, module: str, message: str):
        self.errors.append({
            "module": module,
            "message": message,
            "timestamp": datetime.now().isoformat()
        })
        print(f"  [ERROR][{module}] {message}")

    def get_host(self, ip: str) -> Optional[Host]:
        for h in self.hosts:
            if h.ip_address == ip:
                return h
        return None

    def add_host(self, ip: str) -> Host:
        existing = self.get_host(ip)
        if existing:
            return existing
        h = Host(ip_address=ip)
        self.hosts.append(h)
        return h

    def summary(self) -> dict:
        total_vulns = sum(len(h.vulnerabilities) for h in self.hosts)
        total_exploits = sum(len(h.exploit_attempts) for h in self.hosts)
        successful = sum(
            1 for h in self.hosts
            for e in h.exploit_attempts
            if e.get("result") == "SUCCESS"
        )
        return {
            "session_id": self.session_id,
            "target": self.target_scope,
            "hosts_found": len(self.hosts),
            "total_vulnerabilities": total_vulns,
            "exploit_attempts": total_exploits,
            "successful_exploits": successful,
            "rules_fired": len(self.rule_log),
            "errors": len(self.errors),
        }