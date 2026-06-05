/* ══════════════════════════════════════════════
   data.js — Enhanced demo data v2
   ══════════════════════════════════════════════ */

const SESSION = { id:"SIM-A3F9", target:"192.168.1.100", status:"done", mode:"dry-run", progress:100 };

const HOSTS = [{
  ip:"192.168.1.100", hostname:"metasploitable", os:"LINUX",
  services:[
    {port:21,   proto:"tcp", service:"ftp",          product:"vsftpd",         version:"2.3.4"},
    {port:22,   proto:"tcp", service:"ssh",          product:"OpenSSH",        version:"4.7p1"},
    {port:80,   proto:"tcp", service:"http",         product:"Apache httpd",   version:"2.2.8"},
    {port:139,  proto:"tcp", service:"netbios-ssn",  product:"Samba",          version:"3.X"},
    {port:445,  proto:"tcp", service:"microsoft-ds", product:"Samba",          version:"3.0.20"},
    {port:1524, proto:"tcp", service:"bindshell",    product:"Metasploitable", version:"root"},
    {port:3306, proto:"tcp", service:"mysql",        product:"MySQL",          version:"5.0.51a"},
    {port:5432, proto:"tcp", service:"postgresql",   product:"PostgreSQL",     version:"8.3.0"},
    {port:6667, proto:"tcp", service:"irc",          product:"UnrealIRCd",     version:"3.2.8.1"},
    {port:8180, proto:"tcp", service:"http",         product:"Apache Tomcat",  version:"1.1"},
  ]
}];

const VULNS = [
  {cve:"CVE-2011-2523",ip:"192.168.1.100",service:"ftp",  port:21,  cvss:10.0,risk:0.95,attack:"remote",      auth:false,msf:"exploit/unix/ftp/vsftpd_234_backdoor",          desc:"vsftpd 2.3.4 backdoor RCE",severity:"critical"},
  {cve:"CVE-2007-2447",ip:"192.168.1.100",service:"smb",  port:445, cvss:9.3, risk:0.88,attack:"remote",      auth:false,msf:"exploit/multi/samba/usermap_script",             desc:"Samba usermap_script RCE",severity:"critical"},
  {cve:"CVE-2017-7679",ip:"192.168.1.100",service:"http", port:80,  cvss:9.8, risk:0.84,attack:"remote",      auth:false,msf:"exploit/multi/http/apache_mod_cgi_bash_env_exec",desc:"Apache mod_mime buffer overflow",severity:"critical"},
  {cve:"CVE-2010-2075",ip:"192.168.1.100",service:"irc",  port:6667,cvss:9.8, risk:0.79,attack:"remote",      auth:false,msf:"exploit/unix/irc/unreal_ircd_3281_backdoor",     desc:"UnrealIRCd 3.2.8.1 backdoor",severity:"critical"},
  {cve:"CVE-2008-0166",ip:"192.168.1.100",service:"ssh",  port:22,  cvss:7.8, risk:0.52,attack:"brute-force", auth:true, msf:null,                                              desc:"Debian OpenSSL weak key generation",severity:"high"},
  {cve:"CVE-2009-2446",ip:"192.168.1.100",service:"mysql",port:3306,cvss:8.5, risk:0.61,attack:"authenticated",auth:true,msf:"exploit/windows/mysql/mysql_mof",                 desc:"MySQL COM_FIELD_LIST RCE",severity:"high"},
];

const EXPLOITS = [
  {id:"sim_001",ip:"192.168.1.100",cve:"CVE-2011-2523",tool:"metasploit",msf:"exploit/unix/ftp/vsftpd_234_backdoor",    port:21,  result:"SUCCESS",duration:"4.2s"},
  {id:"sim_002",ip:"192.168.1.100",cve:"CVE-2007-2447",tool:"metasploit",msf:"exploit/multi/samba/usermap_script",       port:445, result:"FAIL",   duration:"12.1s"},
  {id:"sim_003",ip:"192.168.1.100",cve:"CVE-2010-2075",tool:"metasploit",msf:"exploit/unix/irc/unreal_ircd_3281_backdoor",port:6667,result:"FAIL",   duration:"8.7s"},
];

const MITRE = {
  "Initial Access":       [{id:"T1190",name:"Exploit Public-Facing Application",detail:"CVE-2011-2523",conf:0.95,src:"rule_exact"},{id:"T1566",name:"Phishing",detail:"SMTP relay",conf:0.70,src:"stix"}],
  "Execution":            [{id:"T1059.004",name:"Unix Shell",detail:"meterpreter",conf:0.90,src:"rule_exact"},{id:"T1059",name:"Command and Scripting Interpreter",detail:"bash",conf:0.85,src:"rule_exact"}],
  "Privilege Escalation": [{id:"T1068",name:"Exploitation for Privilege Escalation",detail:"getsystem",conf:0.93,src:"post_exploit"}],
  "Credential Access":    [{id:"T1003",name:"OS Credential Dumping",detail:"hashdump",conf:0.95,src:"post_exploit"},{id:"T1110",name:"Brute Force",detail:"ssh/ftp",conf:0.87,src:"rule_service"}],
  "Discovery":            [{id:"T1082",name:"System Information Discovery",detail:"sysinfo",conf:0.95,src:"post_exploit"},{id:"T1016",name:"System Network Config Discovery",detail:"arp/route",conf:0.93,src:"post_exploit"},{id:"T1057",name:"Process Discovery",detail:"ps",conf:0.93,src:"post_exploit"},{id:"T1033",name:"System Owner/User Discovery",detail:"getuid",conf:0.95,src:"post_exploit"}],
  "Lateral Movement":     [{id:"T1210",name:"Exploitation of Remote Services",detail:"samba smb",conf:0.88,src:"stix"},{id:"T1021",name:"Remote Services",detail:"ssh pivot",conf:0.75,src:"stix"}],
  "Persistence":          [{id:"T1547",name:"Boot/Logon Autostart Execution",detail:"SSH key added",conf:0.65,src:"ml"}],
  "Exfiltration":         [{id:"T1041",name:"Exfiltration Over C2 Channel",detail:"FTP C2",conf:0.60,src:"stix"}],
};

const ATTACK_CHAIN = [
  {phase:1,name:"Initial Access",      tactic:"initial-access",      color:"#f43f5e",techniques:[{id:"T1190",name:"Exploit Public-Facing App"},{id:"T1566",name:"Phishing"}],             conf:0.95,src:"rule_exact"},
  {phase:2,name:"Execution",           tactic:"execution",           color:"#fb923c",techniques:[{id:"T1059.004",name:"Unix Shell"},{id:"T1059",name:"Command Interpreter"}],             conf:0.90,src:"rule_exact"},
  {phase:3,name:"Privilege Escalation",tactic:"privilege-escalation",color:"#a78bfa",techniques:[{id:"T1068",name:"Exploit for Priv. Escalation"}],                                       conf:0.93,src:"post_exploit"},
  {phase:4,name:"Credential Access",   tactic:"credential-access",   color:"#60a5fa",techniques:[{id:"T1003",name:"OS Credential Dumping"},{id:"T1110",name:"Brute Force"}],             conf:0.91,src:"post_exploit"},
  {phase:5,name:"Discovery",           tactic:"discovery",           color:"#34d399",techniques:[{id:"T1082",name:"System Info Discovery"},{id:"T1016",name:"Network Config Discovery"},{id:"T1057",name:"Process Discovery"}],conf:0.94,src:"post_exploit"},
  {phase:6,name:"Lateral Movement",    tactic:"lateral-movement",    color:"#ec4899",techniques:[{id:"T1210",name:"Remote Services Exploitation"}],                                      conf:0.88,src:"stix"},
  {phase:7,name:"Exfiltration",        tactic:"exfiltration",        color:"#f43f5e",techniques:[{id:"T1041",name:"Exfiltration Over C2"}],                                               conf:0.60,src:"ml"},
];

const POST_EXPLOIT = {
  host:"192.168.1.100", os:"linux", privilege:"root",
  ai_action:"hashdump", ai_conf:0.92,
  commands:[
    {cmd:"sysinfo",   output:"Computer: metasploitable | OS: Linux 2.6.24 | Arch: x86",                                          tech:{id:"T1082",name:"System Information Discovery",    color:"#34d399"}},
    {cmd:"getuid",    output:"Server username: root",                                                                              tech:{id:"T1033",name:"System Owner/User Discovery",      color:"#34d399"}},
    {cmd:"hashdump",  output:"root:0:aad3b435b51404eeaad3b435b51404ee:8c110a32d4b86f64b99bcbe759dfb7e0:::\nmsfadmin:1000:...",   tech:{id:"T1003",name:"OS Credential Dumping",             color:"#60a5fa"}},
    {cmd:"arp",       output:"IP: 192.168.1.1  MAC: 00:50:56:c0:00:01\nIP: 192.168.1.254  MAC: 00:50:56:fb:a8:b2",               tech:{id:"T1016",name:"System Network Config Discovery",   color:"#34d399"}},
    {cmd:"ps",        output:"PID  NAME\n1    init\n1234 apache2\n1456 mysqld",                                                    tech:{id:"T1057",name:"Process Discovery",                 color:"#34d399"}},
    {cmd:"getsystem", output:"Got system via technique 1 (Named Pipe Impersonation)",                                             tech:{id:"T1068",name:"Exploitation for Privilege Escalation",color:"#a78bfa"}},
  ],
  credentials:[
    {type:"ntlm",user:"root",     ntlm:"8c110a32d4b86f64b99bcbe759dfb7e0"},
    {type:"ntlm",user:"msfadmin", ntlm:"b46f8a4dd2f4bc9b23f5..."},
  ],
  network:{ips:["192.168.1.1","192.168.1.254","192.168.1.100"],has_route:true},
};

const ML_RESULTS = [
  {exploit:"vsftpd_234_backdoor",  service:"ftp",  port:21,  tactic:"initial-access",       conf:0.95,layer:"rule_exact",top:[{t:"initial-access",c:0.95},{t:"execution",c:0.06}]},
  {exploit:"samba/usermap_script", service:"smb",  port:445, tactic:"lateral-movement",      conf:0.88,layer:"stix",      top:[{t:"lateral-movement",c:0.88},{t:"initial-access",c:0.08}]},
  {exploit:"unreal_ircd_backdoor", service:"irc",  port:6667,tactic:"initial-access",        conf:0.90,layer:"rule_exact",top:[{t:"initial-access",c:0.90},{t:"execution",c:0.10}]},
  {exploit:"ssh brute force",      service:"ssh",  port:22,  tactic:"credential-access",     conf:0.87,layer:"rule_service",top:[{t:"credential-access",c:0.87},{t:"initial-access",c:0.10}]},
  {exploit:"mysql brute force",    service:"mysql",port:3306,tactic:"credential-access",     conf:0.74,layer:"ml",         top:[{t:"credential-access",c:0.74},{t:"initial-access",c:0.20}]},
];

const TACTIC_COLOR = {
  "Initial Access":"#f43f5e","Execution":"#fb923c","Persistence":"#eab308",
  "Privilege Escalation":"#a855f7","Credential Access":"#3b82f6",
  "Discovery":"#22c55e","Lateral Movement":"#ec4899","Exfiltration":"#f43f5e",
  "Collection":"#06b6d4","Impact":"#dc2626",
};

const RULES = [
  {rule:"R0", cond:"target: 192.168.1.0/24",                    action:"nmap -sn host discovery"},
  {rule:"R1", cond:"1 live host: 192.168.1.100",                action:"proceed to service scan"},
  {rule:"R3", cond:"10 open ports discovered",                   action:"run -sV -sC fingerprinting"},
  {rule:"R4", cond:"OS: LINUX detected",                         action:"run linux NSE scripts"},
  {rule:"R5", cond:"web ports {80, 8180}",                       action:"run directory & vuln discovery"},
  {rule:"R6", cond:"vsftpd 2.3.4 on :21",                        action:"CVE-2011-2523 → vsftpd_234_backdoor"},
  {rule:"R6", cond:"Samba 3.0.20 on :445",                       action:"CVE-2007-2447 → usermap_script"},
  {rule:"R6", cond:"UnrealIRCd 3.2.8.1 on :6667",               action:"CVE-2010-2075 → unreal_ircd_backdoor"},
  {rule:"R7", cond:"risk_score ≥ 0.30 (CVE-2011-2523 = 0.95)",  action:"exploit via Metasploit"},
  {rule:"R8", cond:"SUCCESS on :21",                             action:"open Meterpreter → post-exploitation"},
  {rule:"R9", cond:"session on 192.168.1.100",                   action:"sysinfo / getuid / hashdump / arp / ps"},
  {rule:"R10",cond:"all phases complete",                         action:"generate ATT&CK layer + JSON + TXT"},
];

const LOGS = [
  "███████████████████████████████████████████████████████",
  "  Hybrid AI Red Team Framework — UCAS Cyber Sec 2026",
  "███████████████████████████████████████████████████████",
  "  Session: SIM-A3F9  |  Target: 192.168.1.100  |  Dry-Run",
  "","═══════════════════════════════════════════════════════",
  "[MODULE 1] Reconnaissance","═══════════════════════════════════════════════════════",
  "  [*] nmap -sn 192.168.1.0/24","  [+] Host UP: 192.168.1.100 (metasploitable)","  ✓ 1 live host",
  "","═══════════════════════════════════════════════════════",
  "[MODULE 2] Scanning","═══════════════════════════════════════════════════════",
  "  [+] 21/tcp   ftp     vsftpd 2.3.4","  [+] 22/tcp   ssh     OpenSSH 4.7p1",
  "  [+] 80/tcp   http    Apache 2.2.8","  [+] 445/tcp  smb     Samba 3.0.20",
  "  [+] 6667/tcp irc     UnrealIRCd 3.2.8.1","  [+] 3306/tcp mysql   MySQL 5.0.51a",
  "","═══════════════════════════════════════════════════════",
  "[MODULE 3] Vulnerability Mapping","═══════════════════════════════════════════════════════",
  "  [!] CRITICAL  21/ftp   CVE-2011-2523  CVSS=10.0  risk=0.95",
  "  [!] CRITICAL  445/smb  CVE-2007-2447  CVSS=9.3   risk=0.88",
  "  [!] CRITICAL  80/http  CVE-2017-7679  CVSS=9.8   risk=0.84",
  "  [!] CRITICAL  6667/irc CVE-2010-2075  CVSS=9.8   risk=0.79",
  "","═══════════════════════════════════════════════════════",
  "[MODULE 4] Exploitation","═══════════════════════════════════════════════════════",
  "  [*] exploit/unix/ftp/vsftpd_234_backdoor → 192.168.1.100:21",
  "  ✓ SUCCESS — Meterpreter session 1 opened  (root)",
  "","═══════════════════════════════════════════════════════",
  "[MODULE 5] Post-Exploitation (AI-guided)","═══════════════════════════════════════════════════════",
  "  [AI] OS=linux | priv=root | action=hashdump (conf=0.92)",
  "  [+] sysinfo  → T1082 System Information Discovery",
  "  [+] getuid   → T1033 System Owner/User Discovery (root)",
  "  [+] hashdump → T1003 OS Credential Dumping (2 hashes)",
  "  [+] arp      → T1016 System Network Config Discovery",
  "  [+] ps       → T1057 Process Discovery",
  "","═══════════════════════════════════════════════════════",
  "[MODULE 6] Hybrid MITRE ATT&CK Engine","═══════════════════════════════════════════════════════",
  "  [Layer1/rule] vsftpd → T1190 initial-access        conf=0.95",
  "  [Layer2/stix] samba  → T1210 lateral-movement      conf=0.70",
  "  [Layer3/ml  ] mysql  → T1110 credential-access     conf=0.74",
  "  [post_exploit] 6 techniques mapped from Meterpreter session",
  "  [+] ATT&CK heatmap → reports/attack_layer.json",
  "  [+] Attack chain   → reports/attack_chain.json",
  "","═══════════════════════════════════════════════════════",
  "[MODULE 7] Social Engineering","═══════════════════════════════════════════════════════",
  "  [SE] OSINT surface=8/10 | emails guessed: 5",
  "  [SE] Phishing templates: it_support, hr_notification",
  "  [SE] MITRE: T1566 Phishing, T1534 Internal Spearphishing",
  "","═══════════════════════════════════════════════════════",
  "[MODULE 8] Reporting","═══════════════════════════════════════════════════════",
  "  [+] reports/report_20260530.txt",
  "  [+] reports/attack_report_20260530.json",
  "  ✓ Pipeline complete",
];

/* ══ Threat Intelligence Data ══ */
const THREAT_INTEL = [
  {cve:"CVE-2011-2523",cvss:10.0,epss:0.975,kev:true, kev_ransomware:false,vendor:"vsftpd project",product:"vsftpd",       severity:"critical",score:97.4,tier:"patch_immediately"},
  {cve:"CVE-2007-2447",cvss:9.3, epss:0.970,kev:true, kev_ransomware:false,vendor:"samba",         product:"samba",        severity:"critical",score:96.0,tier:"patch_immediately"},
  {cve:"CVE-2017-0144",cvss:9.8, epss:0.975,kev:true, kev_ransomware:true, vendor:"microsoft",     product:"windows smb",  severity:"critical",score:100, tier:"patch_immediately"},
  {cve:"CVE-2010-2075",cvss:9.8, epss:0.965,kev:true, kev_ransomware:false,vendor:"unrealircd",    product:"unrealircd",   severity:"critical",score:98.1,tier:"patch_immediately"},
  {cve:"CVE-2008-0166",cvss:7.8, epss:0.720,kev:false,kev_ransomware:false,vendor:"debian",        product:"openssl",      severity:"high",    score:66.0,tier:"patch_within_week"},
  {cve:"CVE-2009-2446",cvss:8.5, epss:0.670,kev:false,kev_ransomware:false,vendor:"oracle",        product:"mysql server", severity:"high",    score:67.5,tier:"patch_within_week"},
];

/* ══ Adversary Profiles Data ══ */
const ADVERSARY_PROFILES = [
  {
    name:"APT29",alias:"Cozy Bear",nation:"Russia",motivation:"espionage",
    similarity:82,
    tactics:["initial-access","execution","persistence","credential-access","lateral-movement","collection","exfiltration"],
    techniques:["T1566","T1059","T1547","T1003","T1021","T1005","T1041"],
    matched:["T1190","T1003","T1082","T1041"],
    color:"#f43f5e",
    desc:"Russian SVR-linked group known for stealthy long-term espionage campaigns.",
  },
  {
    name:"APT28",alias:"Fancy Bear",nation:"Russia",motivation:"espionage/disruption",
    similarity:74,
    tactics:["initial-access","execution","credential-access","lateral-movement","exfiltration"],
    techniques:["T1566","T1059","T1110","T1021","T1041"],
    matched:["T1190","T1110","T1021","T1041"],
    color:"#fb923c",
    desc:"Russian GRU unit. Known for targeting government, military, and election infrastructure.",
  },
  {
    name:"Lazarus",alias:"Hidden Cobra",nation:"North Korea",motivation:"financial/espionage",
    similarity:61,
    tactics:["initial-access","execution","persistence","lateral-movement","impact"],
    techniques:["T1566","T1059","T1547","T1021","T1486"],
    matched:["T1190","T1059","T1021"],
    color:"#60a5fa",
    desc:"North Korean group behind WannaCry ransomware and major financial heists.",
  },
  {
    name:"FIN7",alias:"Carbanak",nation:"Ukraine (cybercrime)",motivation:"financial",
    similarity:44,
    tactics:["initial-access","execution","credential-access","collection"],
    techniques:["T1566","T1059","T1003","T1005"],
    matched:["T1003","T1059"],
    color:"#34d399",
    desc:"Financially motivated group targeting retail, restaurant, and hospitality sectors.",
  },
];

/* ══ Attack Graph Data ══ */
const GRAPH_DATA = {
  nodes:[
    {id:"ATTACKER",  type:"attacker", label:"Attacker",       x:50,  y:200, color:"#f43f5e"},
    {id:"192.168.1.100:21",  type:"service",  label:"FTP :21",       x:220, y:80,  color:"#fb923c", service:"ftp",  risk:95},
    {id:"192.168.1.100:445", type:"service",  label:"SMB :445",      x:220, y:200, color:"#fb923c", service:"smb",  risk:88},
    {id:"192.168.1.100:80",  type:"service",  label:"HTTP :80",      x:220, y:320, color:"#fbbf24", service:"http", risk:84},
    {id:"192.168.1.100",     type:"host",     label:"Metasploitable",x:400, y:200, color:"#a78bfa", risk:95},
    {id:"CREDS",             type:"data",     label:"Credentials",   x:570, y:120, color:"#60a5fa"},
    {id:"PIVOT",             type:"pivot",    label:"Pivot Point",   x:570, y:280, color:"#34d399"},
  ],
  edges:[
    {from:"ATTACKER",             to:"192.168.1.100:21",  label:"CVE-2011-2523",  tactic:"initial-access",    color:"#f43f5e"},
    {from:"ATTACKER",             to:"192.168.1.100:445", label:"CVE-2007-2447",  tactic:"lateral-movement",  color:"#fb923c"},
    {from:"ATTACKER",             to:"192.168.1.100:80",  label:"CVE-2017-7679",  tactic:"initial-access",    color:"#fbbf24"},
    {from:"192.168.1.100:21",     to:"192.168.1.100",     label:"T1059 Shell",    tactic:"execution",         color:"#a78bfa"},
    {from:"192.168.1.100:445",    to:"192.168.1.100",     label:"T1210 Exploit",  tactic:"lateral-movement",  color:"#fb923c"},
    {from:"192.168.1.100",        to:"CREDS",             label:"T1003 hashdump", tactic:"credential-access", color:"#60a5fa"},
    {from:"192.168.1.100",        to:"PIVOT",             label:"T1016 network",  tactic:"discovery",         color:"#34d399"},
  ],
};
