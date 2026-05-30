/* ══════════════════════════════════════════════
   data.js — All static demo data
   ══════════════════════════════════════════════ */

const SESSION = {
  id:      "SIM-A3F9",
  target:  "192.168.1.100",
  status:  "done",
  mode:    "dry-run",
  progress: 100,
};

const HOSTS = [
  {
    ip: "192.168.1.100",
    hostname: "metasploitable",
    os: "LINUX",
    services: [
      { port:21,   proto:"tcp", service:"ftp",          product:"vsftpd",  version:"vsftpd 2.3.4" },
      { port:22,   proto:"tcp", service:"ssh",          product:"OpenSSH", version:"openssh 4.7"  },
      { port:445,  proto:"tcp", service:"microsoft-ds", product:"Samba",   version:"samba 3.0"    },
      { port:80,   proto:"tcp", service:"http",         product:"Apache",  version:"apache 2.2"   },
      { port:3306, proto:"tcp", service:"mysql",        product:"MySQL",   version:"mysql 5.0"    },
    ],
  },
];

const VULNS = [
  { cve:"CVE-2011-2523", ip:"192.168.1.100", service:"ftp",   port:21,   cvss:10.0, risk:0.95, attack:"remote",        auth:false, msf:"exploit/unix/ftp/vsftpd_234_backdoor",           desc:"vsftpd 2.3.4 backdoor — remote code execution" },
  { cve:"CVE-2007-2447", ip:"192.168.1.100", service:"smb",   port:445,  cvss:9.3,  risk:0.88, attack:"remote",        auth:false, msf:"exploit/multi/samba/usermap_script",             desc:"Samba usermap_script RCE" },
  { cve:"CVE-2017-7679", ip:"192.168.1.100", service:"http",  port:80,   cvss:9.8,  risk:0.84, attack:"remote",        auth:false, msf:"exploit/multi/http/apache_mod_cgi_bash_env_exec", desc:"Apache mod_mime buffer overflow" },
  { cve:"CVE-2008-0166", ip:"192.168.1.100", service:"ssh",   port:22,   cvss:7.8,  risk:0.52, attack:"brute-force",   auth:true,  msf:null,                                              desc:"Debian OpenSSL weak key generation" },
  { cve:"CVE-2009-2446", ip:"192.168.1.100", service:"mysql", port:3306, cvss:8.5,  risk:0.61, attack:"authenticated", auth:true,  msf:"exploit/windows/mysql/mysql_mof",                desc:"MySQL COM_FIELD_LIST RCE" },
];

const EXPLOITS = [
  { id:"sim_001", ip:"192.168.1.100", cve:"CVE-2011-2523", tool:"metasploit", msf:"exploit/unix/ftp/vsftpd_234_backdoor",      port:21,  result:"SUCCESS" },
  { id:"sim_002", ip:"192.168.1.100", cve:"CVE-2007-2447", tool:"metasploit", msf:"exploit/multi/samba/usermap_script",         port:445, result:"FAIL"    },
];

const MITRE = {
  "Initial Access":       [{ id:"T1190", name:"Exploit Public-Facing Application",     detail:"CVE-2011-2523" }],
  "Privilege Escalation": [{ id:"T1068", name:"Exploitation for Privilege Escalation", detail:"getsystem"     }],
  "Credential Access":    [{ id:"T1003", name:"OS Credential Dumping",                 detail:"hashdump"      }],
  "Persistence":          [{ id:"T1547", name:"Boot/Logon Autostart Execution",        detail:"SSH key"       }],
  "Discovery":            [{ id:"T1082", name:"System Information Discovery",          detail:"sysinfo"       }],
  "Lateral Movement":     [{ id:"T1021", name:"Remote Services",                       detail:"arp sweep"     }],
  "Exfiltration":         [{ id:"T1041", name:"Exfiltration Over C2 Channel",          detail:""              }],
};

const TACTIC_COLOR = {
  "Initial Access":       "#ef4444",
  "Execution":            "#f97316",
  "Persistence":          "#eab308",
  "Privilege Escalation": "#a855f7",
  "Credential Access":    "#3b82f6",
  "Discovery":            "#22c55e",
  "Lateral Movement":     "#ec4899",
  "Exfiltration":         "#f43f5e",
  "Collection":           "#06b6d4",
};

const RULES = [
  { rule:"R0",  cond:"target is 192.168.1.100",                action:"run Nmap host discovery"                               },
  { rule:"R1",  cond:"1 live host found",                      action:"proceed to scanning & enumeration"                     },
  { rule:"R3",  cond:"3 open ports on 192.168.1.100",          action:"run service & OS fingerprinting"                       },
  { rule:"R4",  cond:"OS detected: LINUX on 192.168.1.100",    action:"run linux-specific enumeration scripts"                },
  { rule:"R5",  cond:"web ports found: {80} on 192.168.1.100", action:"run web directory discovery"                           },
  { rule:"R6",  cond:"ftp vsftpd 2.3.4 on 192.168.1.100",     action:"CVE-2011-2523 → MSF: exploit/unix/ftp/vsftpd_234_backdoor" },
  { rule:"R6",  cond:"smb samba 3.0 on 192.168.1.100",         action:"CVE-2007-2447 → MSF: exploit/multi/samba/usermap_script"  },
  { rule:"R7",  cond:"exploit available | risk=0.95",           action:"trigger safe exploitation via metasploit"              },
  { rule:"R9",  cond:"shell established on 192.168.1.100",     action:"proceed to post-exploitation"                          },
  { rule:"R10", cond:"all phases complete",                     action:"generate detailed report — PDF + JSON"                 },
];

const LOGS = [
  "███████████████████████████████████████████████████",
  "  Rule-Based Adaptive Red Teaming Orchestrator",
  "  UCAS University — Cyber Security Engineering 2026",
  "███████████████████████████████████████████████████",
  "  Session ID : SIM-A3F9",
  "  Target     : 192.168.1.100",
  "  Dry Run    : True",
  "",
  "=======================================================",
  "[MODULE 1] Reconnaissance — Host Discovery",
  "=======================================================",
  "  [*] Running: nmap -sn -PE -PS22,80,443,445 192.168.1.100",
  "  [+] Host UP: 192.168.1.100 (metasploitable)",
  "  ✓ Found 1 live host(s): ['192.168.1.100']",
  "",
  "=======================================================",
  "[MODULE 2] Scanning & Enumeration",
  "=======================================================",
  "  [*] Scanning host: 192.168.1.100",
  "  [*] Running: nmap -sV -O -sC --open -T4 192.168.1.100",
  "  [+] Services on 192.168.1.100 (OS: LINUX):",
  "      21/tcp   ftp          vsftpd 2.3.4",
  "      22/tcp   ssh          openssh 4.7",
  "      445/tcp  microsoft-ds samba 3.0",
  "      80/tcp   http         apache 2.2",
  "      3306/tcp mysql        mysql 5.0",
  "  [R5] Web ports detected: {80} — web discovery queued",
  "",
  "=======================================================",
  "[MODULE 3] Vulnerability Mapping + Risk Scoring",
  "=======================================================",
  "  [*] Mapping vulnerabilities for 192.168.1.100",
  "  [+] CVE-2011-2523 | CVSS: 10.0 | Risk: 0.95 | ftp:21",
  "  [+] CVE-2007-2447 | CVSS: 9.3  | Risk: 0.88 | smb:445",
  "  [+] CVE-2017-7679 | CVSS: 9.8  | Risk: 0.84 | http:80",
  "  [+] CVE-2009-2446 | CVSS: 8.5  | Risk: 0.61 | mysql:3306",
  "  [+] CVE-2008-0166 | CVSS: 7.8  | Risk: 0.52 | ssh:22",
  "",
  "=======================================================",
  "[MODULE 4] Exploitation",
  "=======================================================",
  "  [*] Targeting host: 192.168.1.100",
  "  [*] 5 vulnerability(ies) to try (sorted by risk)",
  "  [*] Metasploit: exploit/unix/ftp/vsftpd_234_backdoor → 192.168.1.100:21",
  "  ✓ EXPLOITATION SUCCESS — CVE-2011-2523 on 192.168.1.100",
  "",
  "=======================================================",
  "[MODULE 5] Post-Exploitation + MITRE ATT&CK Mapping",
  "=======================================================",
  "  [*] Post-exploitation on 192.168.1.100",
  "  [+] Privilege escalation: ROOT/SYSTEM obtained",
  "  [+] Found 2 password hash(es)",
  "  [+] Persistence established",
  "  [+] Pivot candidates: ['192.168.1.101']",
  "  ✓ Post-exploitation complete for 192.168.1.100",
  "",
  "=======================================================",
  "[MODULE 6] Reporting (R10)",
  "=======================================================",
  "  ✓ JSON report : reports/report_SIM-A3F9.json",
  "  ✓ Text report : reports/report_SIM-A3F9.txt",
  "  ✓ PDF report  : reports/report_SIM-A3F9.pdf",
];
