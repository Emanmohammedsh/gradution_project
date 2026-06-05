"""
api/routes/vulnerabilities.py — Vulnerability Intelligence API
"""
from fastapi import APIRouter, HTTPException, Query
from modules.api.schemas import VulnOut, VulnListResponse

router = APIRouter(prefix="/api/vulnerabilities", tags=["Vulnerabilities"])

# Demo dataset (populated by scan pipeline in production)
DEMO_VULNS = [
    {"host":"192.168.1.100","port":21, "service":"ftp",  "cve":"CVE-2011-2523","severity":"critical","cvss":10.0,"risk_score":95,"exploit":"exploit/unix/ftp/vsftpd_234_backdoor","title":"vsftpd 2.3.4 Backdoor RCE","intel":{"epss":0.975,"kev":True}},
    {"host":"192.168.1.100","port":445,"service":"smb",  "cve":"CVE-2007-2447","severity":"critical","cvss":9.3, "risk_score":88,"exploit":"exploit/multi/samba/usermap_script",  "title":"Samba usermap_script RCE","intel":{"epss":0.970,"kev":True}},
    {"host":"192.168.1.100","port":80, "service":"http", "cve":"CVE-2017-7679","severity":"critical","cvss":9.8, "risk_score":84,"exploit":"exploit/multi/http/apache_mod_cgi",   "title":"Apache mod_mime overflow","intel":{"epss":0.820,"kev":False}},
    {"host":"192.168.1.100","port":6667,"service":"irc", "cve":"CVE-2010-2075","severity":"critical","cvss":9.8, "risk_score":79,"exploit":"exploit/unix/irc/unreal_ircd_3281_backdoor","title":"UnrealIRCd backdoor","intel":{"epss":0.965,"kev":True}},
    {"host":"192.168.1.100","port":22, "service":"ssh",  "cve":"CVE-2008-0166","severity":"high",    "cvss":7.8, "risk_score":52,"exploit":"hydra","title":"Debian OpenSSL weak key","intel":{"epss":0.720,"kev":False}},
    {"host":"192.168.1.100","port":3306,"service":"mysql","cve":"CVE-2009-2446","severity":"high",   "cvss":8.5, "risk_score":61,"exploit":"exploit/windows/mysql/mysql_mof",        "title":"MySQL COM_FIELD_LIST RCE","intel":{"epss":0.670,"kev":False}},
]


@router.get("/", response_model=VulnListResponse)
async def list_vulnerabilities(
    severity: str | None = Query(None, description="Filter: critical|high|medium|low"),
    min_cvss: float = Query(0.0, description="Minimum CVSS score"),
):
    filtered = [
        v for v in DEMO_VULNS
        if (severity is None or v["severity"] == severity)
        and v["cvss"] >= min_cvss
    ]
    return VulnListResponse(
        total          = len(filtered),
        critical_count = sum(1 for v in filtered if v["severity"] == "critical"),
        high_count     = sum(1 for v in filtered if v["severity"] == "high"),
        vulnerabilities= [VulnOut(**v) for v in filtered],
    )


@router.get("/critical", response_model=VulnListResponse)
async def critical_vulnerabilities():
    crits = [v for v in DEMO_VULNS if v["severity"] == "critical"]
    return VulnListResponse(
        total=len(crits), critical_count=len(crits), high_count=0,
        vulnerabilities=[VulnOut(**v) for v in crits],
    )


@router.get("/kev", response_model=VulnListResponse)
async def kev_vulnerabilities():
    kevs = [v for v in DEMO_VULNS if v.get("intel", {}).get("kev")]
    return VulnListResponse(
        total=len(kevs), critical_count=len(kevs), high_count=0,
        vulnerabilities=[VulnOut(**v) for v in kevs],
    )


@router.get("/{cve_id}", response_model=VulnOut)
async def get_by_cve(cve_id: str):
    for v in DEMO_VULNS:
        if v["cve"].lower() == cve_id.lower():
            return VulnOut(**v)
    raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found in current scan.")
