class MitreMapper:

    def __init__(self):
        self.mitre_db = {
            "exploit/unix/ftp/vsftpd_234_backdoor": {
                "techniques": [
                    {"id": "T1190", "name": "Exploit Public-Facing Application"},
                    {"id": "T1059", "name": "Command and Scripting Interpreter"},
                ],
                "tactic": "Initial Access"
            },
            "exploit/multi/samba/usermap_script": {
                "techniques": [
                    {"id": "T1210", "name": "Exploitation of Remote Services"},
                    {"id": "T1059", "name": "Command and Scripting Interpreter"},
                ],
                "tactic": "Lateral Movement"
            },
            "ssh": {
                "techniques": [
                    {"id": "T1110", "name": "Brute Force"},
                    {"id": "T1021", "name": "Remote Services"},
                ],
                "tactic": "Credential Access"
            },
            "ftp": {
                "techniques": [
                    {"id": "T1110", "name": "Brute Force"},
                    {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
                ],
                "tactic": "Credential Access"
            },
            "web": {
                "techniques": [
                    {"id": "T1190", "name": "Exploit Public-Facing Application"},
                    {"id": "T1083", "name": "File and Directory Discovery"},
                ],
                "tactic": "Initial Access"
            }
        }

    def map_techniques(self, exploit_results):
        print(f"\n[MITRE] Starting ATT&CK Mapping...")

        mapped = []

        for result in exploit_results:
            exploit = result.get("exploit", "")
            mitre_info = self.mitre_db.get(exploit, {
                "techniques": [{"id": "T1000", "name": "Unknown Technique"}],
                "tactic": "Unknown"
            })

            result["mitre"] = mitre_info
            mapped.append(result)

            print(f"  [+] {result['host']}:{result['port']}")
            print(f"      Tactic    : {mitre_info['tactic']}")
            for tech in mitre_info["techniques"]:
                print(f"      Technique : {tech['id']} - {tech['name']}")

        return mapped
