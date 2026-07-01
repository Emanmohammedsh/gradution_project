"""
train_mitre_model.py
--------------------
Trains the MITRE ATT&CK tactic classifier (TF-IDF + Random Forest).

v2: Builds training data automatically from the official STIX enterprise-attack.json
    (709 techniques -> 890+ samples) and merges with the original hand-crafted set.

Run once before starting the pipeline:
    python train_mitre_model.py

Outputs:
    models/mitre_classifier.pkl
    data/stix_training.csv
"""

import csv
import json
import os
import pickle
import re

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

STIX_PATH         = "data/enterprise-attack.json"
STIX_TRAINING_CSV = "data/stix_training.csv"
MODEL_PATH        = "models/mitre_classifier.pkl"

TACTIC_ALIASES = {
    "stealth":            "defense-evasion",
    "defense-impairment": "defense-evasion",
}

HANDCRAFTED_DATA = [
    ("vsftpd backdoor remote code execution ftp 21",           "initial-access"),
    ("samba usermap script smb 445 command injection",         "lateral-movement"),
    ("eternalblue ms17 smb 445 windows",                       "lateral-movement"),
    ("bluekeep rdp 3389 windows remote",                       "lateral-movement"),
    ("drupalgeddon web http 80 exploit",                       "initial-access"),
    ("struts ognl injection http 8080 java",                   "initial-access"),
    ("unreal ircd backdoor irc 6667",                          "initial-access"),
    ("distcc exec remote code linux 3632",                     "initial-access"),
    ("java rmi server lateral 1099",                           "lateral-movement"),
    ("ms08 netapi smb 445 windows buffer overflow",            "lateral-movement"),
    ("ssh brute force credential 22",                          "credential-access"),
    ("ftp brute force credential 21",                          "credential-access"),
    ("telnet brute force valid accounts 23",                   "credential-access"),
    ("rdp brute force credential 3389",                        "credential-access"),
    ("mysql brute force credential 3306",                      "credential-access"),
    ("hashdump credential dump ntlm windows",                  "credential-access"),
    ("ssh private key credential dump linux",                  "credential-access"),
    ("getsystem privilege escalation windows",                 "privilege-escalation"),
    ("sudo nopasswd privilege escalation linux",               "privilege-escalation"),
    ("local exploit suggester privilege linux windows",        "privilege-escalation"),
    ("sysinfo discovery system information",                   "discovery"),
    ("getuid user discovery system owner",                     "discovery"),
    ("arp route network discovery enum",                       "discovery"),
    ("ping sweep remote system discovery network",             "discovery"),
    ("process list discovery ps windows linux",                "discovery"),
    ("meterpreter command shell execution interpreter",        "execution"),
    ("bash shell command scripting interpreter linux",         "execution"),
    ("powershell command scripting windows execution",         "execution"),
    ("web application exploit public facing http",             "initial-access"),
    ("php cgi argument injection web 80",                      "initial-access"),
    ("wordpress admin shell upload http",                      "initial-access"),
    ("jenkins script console http 8080",                       "execution"),
    ("exfiltration ftp c2 channel data",                       "exfiltration"),
    ("phishing spearphishing email smtp link",                 "initial-access"),
    ("scheduled task persistence cron windows",                "persistence"),
    ("registry run key persistence windows",                   "persistence"),
    ("lateral movement psexec smb windows",                    "lateral-movement"),
    ("remote services ssh linux lateral",                      "lateral-movement"),
    ("collection files directory discovery",                   "collection"),
    ("impact ransomware encryption data",                      "impact"),
    ('archive via utility adversaries may use utilities to compress and or encrypt collected data prior to exfiltration many utilities include functionalities to compress, encrypt, or otherwise package data', 'collection'),
    ('vnc adversaries may use valid accounts to remotely control machines using virtual network computing vnc vnc is a platform independent desktop sharing system that uses the rfb “remote framebuffer” prot', 'lateral-movement'),
    ('screen capture adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation screen capturing functionality may be included as a feature of a rem', 'collection'),
    ('adversary in the middle adversaries may attempt to position themselves between two or more networked devices using an adversary in the middle aitm technique to support follow on behaviors such as netw', 'collection'),
    ('keylogging adversaries may log user keystrokes to intercept credentials as the user types them keylogging is likely to be used to acquire credentials for new access opportunities when os credential du', 'collection'),
    ('data from configuration repository adversaries may collect data related to managed devices from configuration repositories configuration repositories are used by management systems in order to configu', 'collection'),
    ('disk structure wipe adversaries may corrupt or wipe the disk data structures on a hard drive necessary to boot a system; targeting specific critical systems or in large numbers in a network to interru', 'impact'),
    ('direct network flood adversaries may attempt to cause a denial of service dos by directly sending a high volume of network traffic to a target this dos attack may also reduce the availability and func', 'impact'),
    ('sharepoint adversaries may leverage the sharepoint repository as a source to mine valuable information sharepoint will often contain useful information for an adversary to learn about the structure an', 'collection'),
    ('external defacement an adversary may deface systems external to an organization in an attempt to deliver messaging, intimidate, or otherwise mislead an organization or users external defacement may ul', 'impact'),
    ("os exhaustion flood adversaries may launch a denial of service dos attack targeting an endpoint's operating system os a system's os is responsible for managing the finite resources as well as preventi", 'impact'),
    ('lifecycle triggered deletion adversaries may modify the lifecycle policies of a cloud storage bucket to destroy all objects stored within cloud storage buckets often allow users to set lifecycle polic', 'impact'),
    ("audio capture an adversary can leverage a computer's peripheral devices e g , microphones and webcams or applications e g , voice and video call services to capture audio recordings for the purpose of", 'collection'),
    ('external remote services adversaries may leverage external facing remote services to initially access and or persist within a network remote services such as vpns, citrix, and other access mechanisms ', 'initial-access'),
    ('sms pumping adversaries may leverage messaging services for sms pumping, which may impact system and or hosted service availability citation: twilio sms pumping sms pumping is a type of telecommunicat', 'impact'),
    ('archive via custom method an adversary may compress or encrypt data that is collected prior to exfiltration using a custom method adversaries may choose to use custom archival methods, such as encrypt', 'collection'),
    ('email collection adversaries may target user email to collect sensitive information emails may contain sensitive data, including trade secrets or personal information, that can prove valuable to adver', 'collection'),
    ('application exhaustion flood adversaries may target resource intensive features of applications to cause a denial of service dos , denying availability to those applications for example, specific feat', 'impact'),
    ('compromise software dependencies and development tools adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system com', 'initial-access'),
    ('disk wipe adversaries may wipe or corrupt raw disk data on specific systems or in large numbers in a network to interrupt availability to system and network resources with direct write access to a dis', 'impact'),
    ('data from removable media adversaries may search connected removable media on computers they have compromised to find files of interest sensitive data can be collected from any removable media optical', 'collection'),
    ('local data staging adversaries may stage collected data in a central location or directory on the local system prior to exfiltration data may be kept in separate files or combined into one file throug', 'collection'),
    ('stored data manipulation adversaries may insert, delete, or manipulate data at rest in order to influence external outcomes or hide activity, thus threatening the integrity of the data citation: firee', 'impact'),
    ('local email collection adversaries may target user email on local systems to collect sensitive information files containing email data can be acquired from a user’s local system, such as outlook stora', 'collection'),
    ('service stop adversaries may stop or disable services on a system to render those services unavailable to legitimate users stopping critical services or processes can inhibit or stop response to an in', 'impact'),
    ('taint shared content adversaries may deliver payloads to remote systems by adding content to shared storage locations, such as network drives or internal code repositories content stored on network dr', 'lateral-movement'),
    ('databases adversaries may leverage databases to mine valuable information these databases may be hosted on premises or in the cloud both in platform as a service and software as a service environments', 'collection'),
    ('spearphishing link adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems spearphishing with a link is a specific variant of spearphishing it is', 'initial-access'),
    ('application or system exploitation adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users citation: sucuri bind9 august 2015 s', 'impact'),
    ('ssh adversaries may use valid accounts to log into remote machines using secure shell ssh the adversary may then perform actions as the logged on user ssh is a protocol that allows authorized users to', 'lateral-movement'),
    ('spearphishing attachment adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems spearphishing attachment is a specific variant of spearphi', 'initial-access'),
    ('automated collection once established within a system or network, an adversary may use automated techniques for collecting internal data methods for performing this technique could include use of a co', 'collection'),
    ('clipboard data adversaries may collect data stored in the clipboard from users copying information within or between applications for example, on windows adversaries can access clipboard data by using', 'collection'),
    ('data from cloud storage adversaries may access data from cloud storage many iaas providers offer solutions for online data object storage such as amazon s3, azure storage, and google cloud storage sim', 'collection'),
    ('runtime data manipulation adversaries may modify systems in order to manipulate the data as it is accessed and displayed to an end user, thus threatening the integrity of the data citation: fireeye ap', 'impact'),
    ('remote data staging adversaries may stage data collected from multiple systems in a central location or directory on one system prior to exfiltration data may be kept in separate files or combined int', 'collection'),
    ('reflection amplification adversaries may attempt to cause a denial of service dos by reflecting a high volume of network traffic to a target this type of network dos takes advantage of a third party s', 'impact'),
    ('service exhaustion flood adversaries may target the different network services provided by systems to conduct a denial of service dos adversaries often target the availability of dns and web services,', 'impact'),
    ('compromise hardware supply chain adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise by modifying hardware or f', 'initial-access'),
    ('replication through removable media adversaries may move onto systems, possibly those on disconnected or air gapped networks, by copying malware to removable media and taking advantage of autorun feat', 'lateral-movement'),
    ('replication through removable media adversaries may move onto systems, possibly those on disconnected or air gapped networks, by copying malware to removable media and taking advantage of autorun feat', 'initial-access'),
    ('data from local system adversaries may search local system sources, such as file systems, configuration files, local databases, virtual machine files, or process memory, to find files of interest and ', 'collection'),
    ('supply chain compromise adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise supply chain compromise can', 'initial-access'),
    ('exploit public facing application adversaries may attempt to exploit a weakness in an internet facing host or system to initially access a network the weakness in the system can be a software bug, a t', 'initial-access'),
    ('exfiltration over web service adversaries may use an existing, legitimate external web service to exfiltrate data rather than their primary command and control channel popular web services acting as a', 'exfiltration'),
    ('archive via library an adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party libraries many libraries exist that can archive data, including python rarfile cit', 'collection'),
    ('content injection adversaries may gain access and continuously communicate with victims by injecting malicious content into systems through online network traffic rather than luring victims to malicio', 'initial-access'),
    ('exfiltration over webhook adversaries may exfiltrate data to a webhook endpoint rather than over their primary command and control channel webhooks are simple mechanisms for allowing a server to push ', 'exfiltration'),
    ('direct cloud vm connections adversaries may leverage valid accounts to log directly into accessible cloud hosted compute infrastructure through cloud native methods many cloud providers offer interact', 'lateral-movement'),
    ('evil twin adversaries may host seemingly genuine wi fi access points to deceive users into connecting to malicious networks as a way of supporting follow on behaviors such as network sniffing transmit', 'collection'),
    ("ssh hijacking adversaries may hijack a legitimate user's ssh session to move laterally within an environment secure shell ssh is a standard means of remote access on linux and macos systems it allows ", 'lateral-movement'),
    ('scheduled transfer adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals this could be done to blend traffic patterns with normal activity or ', 'exfiltration'),
    ('smb windows admin shares adversaries may use valid accounts to interact with a remote network share using server message block smb the adversary may then perform actions as the logged on user smb is a', 'lateral-movement'),
    ('use alternate authentication material adversaries may use alternate authentication material, such as password hashes, kerberos tickets, and application access tokens, in order to move laterally within', 'lateral-movement'),
    ('exfiltration over other network medium adversaries may attempt to exfiltrate data over a different network medium than the command and control channel if the command and control network is a wired int', 'exfiltration'),
    ('network device configuration dump adversaries may access network configuration files to collect sensitive data about the device and the network the network configuration is a file containing parameter', 'collection'),
    ('archive collected data an adversary may compress and or encrypt data that is collected prior to exfiltration compressing the data can help to obfuscate the collected data and minimize the amount of da', 'collection'),
    ('browser session hijacking adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user behaviors, and intercept information ', 'collection'),
    ('remote services adversaries may use valid accounts to log into a service that accepts remote connections, such as telnet, ssh, and vnc the adversary may then perform actions as the logged on user in a', 'lateral-movement'),
    ('defacement adversaries may modify visual content available internally or externally to an enterprise network, thus affecting the integrity of the original content reasons for defacement include delive', 'impact'),
    ('dhcp spoofing adversaries may redirect network traffic to adversary owned systems by spoofing dynamic host configuration protocol dhcp traffic and acting as a malicious dhcp server on the victim netwo', 'collection'),
    ('remote service session hijacking adversaries may take control of preexisting sessions with remote services to move laterally in an environment users may use valid credentials to log into a service spe', 'lateral-movement'),
    ('windows remote management adversaries may use valid accounts to interact with remote systems using windows remote management winrm the adversary may then perform actions as the logged on user winrm is', 'lateral-movement'),
    ('exfiltration over bluetooth adversaries may attempt to exfiltrate data over bluetooth rather than the command and control channel if the command and control network is a wired internet connection, an ', 'exfiltration'),
    ('default accounts adversaries may obtain and abuse credentials of a default account as a means of gaining initial access, persistence, privilege escalation, or defense evasion default accounts are thos', 'initial-access'),
    ('name resolution poisoning and smb relay by responding to llmnr nbt ns mdns network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary c', 'collection'),
    ('distributed component object model adversaries may use valid accounts to interact with remote machines by taking advantage of distributed component object model dcom the adversary may then perform act', 'lateral-movement'),
    ('web portal capture adversaries may install code on externally facing portals, such as a vpn login page, to capture and transmit credentials of users who attempt to log into the service for example, a ', 'collection'),
    ("video capture an adversary can leverage a computer's peripheral devices e g , integrated cameras or webcams or applications e g , video call services to capture video recordings for the purpose of gat", 'collection'),
    ('bandwidth hijacking adversaries may leverage the network bandwidth resources of co opted systems to complete resource intensive tasks, which may impact system and or hosted service availability advers', 'impact'),
    ('automated exfiltration adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during collection citation: eset gamaredon june 2020 w', 'exfiltration'),
    ('exfiltration over symmetric encrypted non c2 protocol adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control ', 'exfiltration'),
    ('confluence adversaries may leverage confluence repositories to mine valuable information often found in development environments alongside atlassian jira, confluence is generally used to store develop', 'collection'),
    ('pass the ticket adversaries may “pass the ticket” using stolen kerberos tickets to move laterally within an environment, bypassing normal system access controls pass the ticket ptt is a method of auth', 'lateral-movement'),
    ('traffic duplication adversaries may leverage traffic mirroring in order to automate data exfiltration over compromised infrastructure traffic mirroring is a native feature for some devices, often used', 'exfiltration'),
    ('email forwarding rule adversaries may setup email forwarding rules to collect sensitive information adversaries may abuse email forwarding rules to monitor the activities of a victim, steal informatio', 'collection'),
    ('data staged adversaries may stage collected data in a central location or directory prior to exfiltration data may be kept in separate files or combined into one file through techniques such as archiv', 'collection'),
    ('financial theft adversaries may steal monetary resources from targets through extortion, social engineering, technical theft, or other methods aimed at their own financial gain at the expense of the a', 'impact'),
    ('exfiltration to code repository adversaries may exfiltrate data to a code repository rather than over their primary command and control channel code repositories are often accessible via an api ex: ac', 'exfiltration'),
    ('cloud services adversaries may log into accessible cloud services within a compromised environment using valid accounts that are synchronized with or federated to on premises user identities the adver', 'lateral-movement'),
    ('internal defacement an adversary may deface systems internal to an organization in an attempt to intimidate or mislead users, thus discrediting the integrity of the systems this may take the form of m', 'impact'),
    ('exfiltration over asymmetric encrypted non c2 protocol adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than that of the existing command and contr', 'exfiltration'),
    ('cloud service hijacking adversaries may leverage compromised software as a service saas applications to complete resource intensive tasks, which may impact hosted service availability for example, adv', 'impact'),
    ('software deployment tools adversaries may gain access to and use centralized software suites installed within an enterprise to execute commands and move laterally through the network configuration man', 'lateral-movement'),
    ('exfiltration over c2 channel adversaries may steal data by exfiltrating it over an existing command and control channel stolen data is encoded into the normal communications channel using the same pro', 'exfiltration'),
    ('exploitation of remote services adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network exploitation of a software vulnerability occurs when an', 'lateral-movement'),
    ('internal spearphishing after they already have access to accounts or systems within the environment, adversaries may use internal spearphishing to gain access to additional information or compromise o', 'lateral-movement'),
    ('trusted relationship adversaries may breach or otherwise leverage organizations who have access to intended victims access through trusted third party relationship abuses an existing connection that m', 'initial-access'),
    ('exfiltration over alternative protocol adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel the data may also be sent to an alt', 'exfiltration'),
    ('gui input capture adversaries may mimic common operating system gui components to prompt users for credentials with a seemingly legitimate prompt when programs are executed that need additional privil', 'collection'),
    ('exfiltration over usb adversaries may attempt to exfiltrate data over a usb connected physical device in certain circumstances, such as an air gapped network compromise, exfiltration could occur via a', 'exfiltration'),
    ('phishing adversaries may send phishing messages to gain access to victim systems all forms of phishing are electronically delivered social engineering phishing can be targeted, known as spearphishing ', 'initial-access'),
    ('compute hijacking adversaries may leverage the compute resources of co opted systems to complete resource intensive tasks, which may impact system and or hosted service availability one common purpose', 'impact'),
    ('data manipulation adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity, thus threatening the integrity of the data citation: sygnia elephant beet', 'impact'),
    ('data from network shared drive adversaries may search network shares on computers they have compromised to find files of interest sensitive data can be collected from remote systems via shared network', 'collection'),
    ('valid accounts adversaries may obtain and abuse credentials of existing accounts as a means of gaining initial access, persistence, privilege escalation, or defense evasion compromised credentials may', 'initial-access'),
    ('account access removal adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users accounts may be deleted, locked, or manipula', 'impact'),
    ("remote email collection adversaries may target an exchange server, office 365, or google workspace to collect sensitive information adversaries may leverage a user's credentials and interact directly ", 'collection'),
    ('data encrypted for impact adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources they can attempt to rende', 'impact'),
    ('exfiltration to text storage sites adversaries may exfiltrate data to text storage sites instead of their primary command and control channel text storage sites, such as <code>pastebin com< code>, are', 'exfiltration'),
    ('input capture adversaries may use methods of capturing user input to obtain credentials or collect information during normal system usage, users often provide credentials to various different location', 'collection'),
    ('spearphishing voice adversaries may use voice communications to ultimately gain access to victim systems spearphishing voice is a specific variant of spearphishing it is different from other forms of ', 'initial-access'),
    ('customer relationship management software adversaries may leverage customer relationship management crm software to mine valuable information crm software is used to assist organizations in tracking a', 'collection'),
    ('compromise software supply chain adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise supply chain compromise of software c', 'initial-access'),
    ('email bombing adversaries may flood targeted email addresses with an overwhelming volume of messages this may bury legitimate emails in a flood of spam and disrupt business operations citation: sophos', 'impact'),
    ('exfiltration to cloud storage adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel cloud storage services allow for the storage, edit, ', 'exfiltration'),
    ('lateral tool transfer adversaries may transfer tools or other files between systems in a compromised environment once brought into the victim environment i e , ingress tool transfer files may then be ', 'lateral-movement'),
    ('data transfer size limits an adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds this approach may be used to avoid triggering netw', 'exfiltration'),
    ('web session cookie adversaries can use stolen session cookies to authenticate to web applications and services this technique bypasses some multi factor authentication protocols since the session is a', 'lateral-movement'),
    ('domain accounts adversaries may obtain and abuse credentials of a domain account as a means of gaining initial access, persistence, privilege escalation, or defense evasion citation: technet credentia', 'initial-access'),
    ('endpoint denial of service adversaries may perform endpoint denial of service dos attacks to degrade or block the availability of services to users endpoint dos can be performed by exhausting the syst', 'impact'),
    ('arp cache poisoning adversaries may poison address resolution protocol arp caches to position themselves between the communication of two or more networked devices this activity may be used to enable ', 'collection'),
    ('resource hijacking adversaries may leverage the resources of co opted systems to complete resource intensive tasks, which may impact system and or hosted service availability resource hijacking may ta', 'impact'),
    ('code repositories adversaries may leverage code repositories to collect valuable information code repositories are tools services that store source code and automate software builds they may be hosted', 'collection'),
    ('transmitted data manipulation adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity, thus threatening the integrity of the data cita', 'impact'),
    ('data from information repositories adversaries may leverage information repositories to mine valuable information information repositories are tools that allow for storage of information, typically to', 'collection'),
    ('hardware additions adversaries may physically introduce computer accessories, networking hardware, or other computing devices into a system or network that can be used as a vector to gain access rathe', 'initial-access'),
    ('data destruction adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources data destruction is l', 'impact'),
    ('transfer data to cloud account adversaries may exfiltrate data by transferring the data, including through sharing syncing and creating backups of cloud environments, to another cloud account they con', 'exfiltration'),
    ('drive by compromise adversaries may gain access to a system through a user visiting a website over the normal course of browsing multiple ways of delivering exploit code to a browser exist i e , drive', 'initial-access'),
    ('network denial of service adversaries may perform network denial of service dos attacks to degrade or block the availability of targeted resources to users network dos can be performed by exhausting t', 'impact'),
    ('rdp hijacking adversaries may hijack a legitimate user’s remote desktop session to move laterally within an environment remote desktop is a common feature in operating systems it allows a user to log ', 'lateral-movement'),
    ('pass the hash adversaries may “pass the hash” using stolen password hashes to move laterally within an environment, bypassing normal system access controls pass the hash pth is a method of authenticat', 'lateral-movement'),
    ('exfiltration over physical medium adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive in certain circumstances, such as an air gapped network compromise, exfilt', 'exfiltration'),
    ('remote desktop protocol adversaries may use valid accounts to log into a computer using the remote desktop protocol rdp the adversary may then perform actions as the logged on user remote desktop is a', 'lateral-movement'),
    ('snmp mib dump adversaries may target the management information base mib to collect and or mine valuable information in a network managed using simple network management protocol snmp the mib is a con', 'collection'),
    ('application access token adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems th', 'lateral-movement'),
    ('cloud accounts valid accounts in cloud environments may allow adversaries to perform actions to achieve initial access, persistence, privilege escalation, or defense evasion cloud accounts are those c', 'initial-access'),
    ('credential api hooking adversaries may hook into windows application programming interface api functions and linux system functions to collect user credentials malicious hooking mechanisms may capture', 'collection'),
    ('firmware corruption adversaries may overwrite or corrupt the flash memory contents of system bios or other firmware in devices attached to a system in order to render them inoperable or unable to boot', 'impact'),
    ('inhibit system recovery adversaries may delete or remove built in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery citation: talos olympic destroyer', 'impact'),
    ('spearphishing via service adversaries may send spearphishing messages via third party services in an attempt to gain access to victim systems spearphishing via service is a specific variant of spearph', 'initial-access'),
    ('disk content wipe adversaries may erase the contents of storage devices on specific systems or in large numbers in a network to interrupt availability to system and network resources adversaries may p', 'impact'),
    ('messaging applications adversaries may leverage chat and messaging applications, such as microsoft teams, google chat, and slack, to mine valuable information the following is a brief list of example ', 'collection'),
    ('exfiltration over unencrypted non c2 protocol adversaries may steal data by exfiltrating it over an un encrypted network protocol other than that of the existing command and control channel the data m', 'exfiltration'),
    ('local accounts adversaries may obtain and abuse credentials of a local account as a means of gaining initial access, persistence, privilege escalation, or defense evasion local accounts are those conf', 'initial-access'),
    ('wi fi networks adversaries may gain initial access to target systems by connecting to wireless networks they may accomplish this by exploiting open wi fi networks used by target devices or by accessin', 'initial-access'),
    ('system shutdown reboot adversaries may shutdown reboot systems to interrupt access to, or aid in the destruction of, those systems operating systems may contain commands to initiate a shutdown reboot ', 'impact'),
]


def _clean(text):
    text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    text = re.sub(r"`[^`]+`", " ", text)
    text = re.sub(r"https?://\S+", " ", text)
    text = re.sub(r"[/_\-\.\(\)\[\]]", " ", text)
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text


def _tech_to_text(obj):
    name  = obj.get("name", "")
    desc  = obj.get("description", "")[:600]
    plats = " ".join(obj.get("x_mitre_platforms", []))
    return _clean(f"{name} {desc} {plats}")


def build_stix_samples(stix_path):
    if not os.path.exists(stix_path):
        print(f"  [!] STIX file not found: {stix_path}")
        return []

    print(f"  [*] Loading STIX data from {stix_path} ...")
    with open(stix_path, encoding="utf-8") as f:
        data = json.load(f)

    samples = []
    skipped = 0
    merged = 0

    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            skipped += 1
            continue

        text = _tech_to_text(obj)
        if not text:
            continue

        # Collect ALL tactics for this technique first (instead of adding
        # one sample per phase, which creates contradictory duplicate
        # training pairs when a technique legitimately belongs to more
        # than one tactic in the official MITRE taxonomy).
        tactics_for_tech = set()
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            tactic = phase.get("phase_name", "").strip()
            tactic = TACTIC_ALIASES.get(tactic, tactic)
            if tactic:
                tactics_for_tech.add(tactic)

        if not tactics_for_tech:
            continue

        if len(tactics_for_tech) == 1:
            samples.append((text, next(iter(tactics_for_tech))))
        else:
            # Known, deliberate dual-use overlap in the official MITRE
            # taxonomy (e.g. many techniques are legitimately both
            # persistence AND privilege-escalation). Instead of adding
            # the same text twice under two contradictory single labels,
            # emit ONE sample with a merged label, joined by "+" in a
            # fixed sorted order so it is deterministic.
            merged_label = "+".join(sorted(tactics_for_tech))
            samples.append((text, merged_label))
            merged += 1

    print(f"  [+] Extracted {len(samples)} samples ({skipped} skipped, {merged} merged dual-tactic).")
    return samples


def save_stix_csv(samples, path):
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "tactic"])
        writer.writerows(samples)
    print(f"  [+] Saved {len(samples)} samples -> {path}")


def normalize(text):
    return re.sub(r"[/_\-]", " ", text.lower())


def train():
    print("\n[MITRE Classifier Training - v2 STIX-augmented]\n")

    stix_samples = build_stix_samples(STIX_PATH)
    save_stix_csv(stix_samples, STIX_TRAINING_CSV)

    all_samples = stix_samples + HANDCRAFTED_DATA

    # Collapse any tactic label (merged or single) that ends up with
    # fewer than 2 samples — stratified train/test split requires at
    # least 2 members per class. Rare compound labels (e.g. a single
    # technique that is uniquely "initial-access+lateral-movement")
    # fall back to their most frequent individual component tactic,
    # so the sample is kept but folded into a class large enough to
    # split and evaluate meaningfully.
    from collections import Counter
    tactic_counts = Counter(t for _, t in all_samples)

    # Frequency of each *individual* component tactic, used to pick
    # the best fallback when a compound label is too rare.
    component_counts = Counter()
    for _, tactic in all_samples:
        for part in tactic.split("+"):
            component_counts[part] += 1

    cleaned_samples = []
    collapsed = 0
    for text, tactic in all_samples:
        if tactic_counts[tactic] < 2:
            parts = tactic.split("+")
            fallback = max(parts, key=lambda p: component_counts[p])
            cleaned_samples.append((text, fallback))
            collapsed += 1
        else:
            cleaned_samples.append((text, tactic))

    if collapsed:
        print(f"  [+] Collapsed {collapsed} sample(s) from rare compound "
              f"labels (<2 members) into their dominant component tactic.")

    all_samples = cleaned_samples
    texts   = [normalize(t[0]) for t in all_samples]
    tactics = [t[1] for t in all_samples]

    print(f"\n  Total training samples : {len(texts)}")

    from collections import Counter
    dist = Counter(tactics)
    print("  Tactic distribution:")
    for tactic, count in sorted(dist.items(), key=lambda x: -x[1]):
        bar = "=" * (count // 5)
        print(f"    {tactic:<30} {count:>4}  {bar}")

    le = LabelEncoder()
    y  = le.fit_transform(tactics)

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=5000,
        min_df=2,
        sublinear_tf=True,
    )
    X = vectorizer.fit_transform(texts)

    print(f"\n  Vocabulary size : {len(vectorizer.vocabulary_)}")
    print(f"  Feature matrix  : {X.shape[0]} x {X.shape[1]}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    print(f"  Train / Test    : {X_train.shape[0]} / {X_test.shape[0]}")

    print("\n  [*] Training Random Forest classifier ...")
    from sklearn.svm import SVC
    model = SVC(
        kernel="linear",
        C=1.0,
        class_weight="balanced",
        probability=True,
        random_state=42,
    )
    model.fit(X_train, y_train)

    y_pred   = model.predict(X_test)
    accuracy = (y_pred == y_test).mean()
    print(f"\n  Test Accuracy   : {accuracy:.1%}\n")
    print("  Classification Report:")
    present_labels = sorted(set(y_test) | set(y_pred))
    print(classification_report(
        y_test, y_pred,
        labels=present_labels,
        target_names=le.inverse_transform(present_labels),
        zero_division=0
    ))

    os.makedirs("models", exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump({
            "model":         model,
            "vectorizer":    vectorizer,
            "label_encoder": le,
            "version":       "2.0-stix",
            "n_train":       X_train.shape[0],
            "accuracy":      round(accuracy, 4),
        }, f)

    print(f"\n  [+] Model saved -> {MODEL_PATH}")
    print(f"  [+] Tactics covered ({len(le.classes_)}): {list(le.classes_)}")
    print(f"  [+] Training samples : {len(texts)} ({len(stix_samples)} STIX + {len(HANDCRAFTED_DATA)} hand-crafted)")


if __name__ == "__main__":
    train()
