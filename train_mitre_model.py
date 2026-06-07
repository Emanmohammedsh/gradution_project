"""
train_mitre_model.py
--------------------
Trains the MITRE ATT&CK tactic classifier (TF-IDF + Random Forest).
Run once before starting the pipeline:

    python train_mitre_model.py

Outputs: models/mitre_classifier.pkl
"""

import pickle
import os
import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder


TRAINING_DATA = [
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
]


def normalize(text: str) -> str:
    return re.sub(r'[/_\-]', ' ', text.lower())


def train():
    print("[*] Building MITRE tactic training set...")

    texts   = [normalize(t[0]) for t in TRAINING_DATA]
    tactics = [t[1] for t in TRAINING_DATA]

    le = LabelEncoder()
    y  = le.fit_transform(tactics)

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=500,
        min_df=1
    )
    X = vectorizer.fit_transform(texts)

    print("[*] Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        random_state=42,
        class_weight="balanced"
    )
    model.fit(X, y)

    os.makedirs("models", exist_ok=True)
    with open("models/mitre_classifier.pkl", "wb") as f:
        pickle.dump({
            "model":         model,
            "vectorizer":    vectorizer,
            "label_encoder": le
        }, f)

    print("[+] Model saved to models/mitre_classifier.pkl")
    print(f"[+] Tactics covered: {list(le.classes_)}")


if __name__ == "__main__":
    train()
