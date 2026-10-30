#!/usr/bin/env python3
"""
Qualcomm SDX65 / Quectel ODU52140 Deep Forensic Audit Collector
Connects via USB UART (/dev/ttyUSB0) and collects forensic evidence.
"""

import os
import sys
import time
import re
import serial
import base64
import json
from pathlib import Path

PORT = os.environ.get("UART_PORT", "/dev/ttyUSB0")
BAUD = int(os.environ.get("UART_BAUD", 115200))
BASE_DIR = Path("/home/dc/Documents/odu52140")
EVIDENCE_DIR = BASE_DIR / "evidence"

class SerialAuditor:
    def __init__(self, port=PORT, baud=BAUD):
        self.port = port
        self.baud = baud
        print(f"[*] Connecting to {self.port} at {self.baud} baud...")
        self.ser = serial.Serial(self.port, self.baud, timeout=0.2)
        self.sync_terminal()

    def sync_terminal(self):
        """Prepare shell for clean command execution."""
        # Send wake-up newlines
        self.ser.write(b"\r\n\r\n")
        time.sleep(0.3)
        self.drain()
        
        # Disable echo so our sent commands aren't echoed back in stdout
        self.ser.write(b"stty -echo 2>/dev/null; export TERM=dumb\n")
        time.sleep(0.3)
        self.drain()
        print("[+] UART console synced and terminal echo disabled.")

    def drain(self):
        while self.ser.in_waiting > 0:
            self.ser.read(self.ser.in_waiting)
            time.sleep(0.01)

    def exec(self, cmd, timeout=10):
        """Execute command and cleanly extract stdout and exit code."""
        self.drain()
        token = str(int(time.time() * 1000))[-7:]
        s_marker = f"__AUDIT_S_{token}__"
        e_marker = f"__AUDIT_E_{token}__"
        
        payload = f"echo '{s_marker}'; {cmd}; echo '{e_marker}:'$?\n"
        self.ser.write(payload.encode("utf-8"))
        
        out = ""
        start = time.time()
        while time.time() - start < timeout:
            if self.ser.in_waiting > 0:
                chunk = self.ser.read(self.ser.in_waiting).decode("utf-8", errors="replace")
                out += chunk
                if e_marker in out:
                    break
            time.sleep(0.03)
            
        if s_marker in out and e_marker in out:
            # Extract content between markers
            after_start = out.split(s_marker)[-1]
            body = after_start.split(e_marker)[0]
            # Strip trailing/leading carriage returns & newlines
            body = body.replace("\r\n", "\n").strip()
            
            # Find exit code
            code_match = re.search(rf"{e_marker}:(\d+)", out)
            exit_code = int(code_match.group(1)) if code_match else -1
            return body, exit_code
        else:
            # Fallback if markers timed out or got garbled
            cleaned = out.replace(s_marker, "").replace(e_marker, "").replace("\r\n", "\n").strip()
            return cleaned, -1

    def extract_file_base64(self, remote_path, local_path):
        """Extract a remote file via base64 encoding over UART."""
        print(f"[*] Extracting file: {remote_path} -> {local_path}...")
        body, code = self.exec(f"test -f '{remote_path}' && base64 '{remote_path}'", timeout=25)
        if code != 0 or not body:
            print(f"[-] Failed to extract {remote_path} (Exit: {code})")
            return False
            
        # Remove any non-base64 noise
        clean_lines = [l.strip() for l in body.splitlines() if re.match(r"^[A-Za-z0-9+/=]+$", l.strip())]
        b64_str = "".join(clean_lines)
        try:
            raw_bytes = base64.b64decode(b64_str)
            local_path.parent.mkdir(parents=True, exist_ok=True)
            with open(local_path, "wb") as f:
                f.write(raw_bytes)
            print(f"[+] Successfully extracted {remote_path} ({len(raw_bytes)} bytes)")
            return True
        except Exception as e:
            print(f"[!] Error decoding base64 for {remote_path}: {e}")
            return False

    def close(self):
        # Restore terminal echo
        try:
            self.ser.write(b"stty echo 2>/dev/null\n")
            time.sleep(0.1)
            self.ser.close()
        except Exception:
            pass


def run_audit():
    auditor = SerialAuditor()
    
    categories = {
        "system_info": [
            ("uname.txt", "uname -a"),
            ("os_release.txt", "cat /etc/os-release 2>/dev/null || cat /etc/issue"),
            ("version.txt", "cat /etc/version 2>/dev/null; cat /etc/*version* 2>/dev/null"),
            ("cmdline.txt", "cat /proc/cmdline"),
            ("cpuinfo.txt", "cat /proc/cpuinfo"),
            ("meminfo.txt", "cat /proc/meminfo"),
            ("devicetree_model.txt", "cat /sys/firmware/devicetree/base/model 2>/dev/null; echo; cat /sys/firmware/devicetree/base/compatible 2>/dev/null; echo"),
            ("uptime.txt", "uptime"),
            ("dmesg.txt", "dmesg"),
        ],
        "storage_partitions": [
            ("mtd.txt", "cat /proc/mtd"),
            ("partitions.txt", "cat /proc/partitions"),
            ("mounts.txt", "mount"),
            ("df_h.txt", "df -h"),
            ("ls_dev_block.txt", "ls -la /dev/block/bootdevice/by-name/ 2>/dev/null || ls -la /dev/block/"),
            ("ubinfo.txt", "ubinfo -a 2>/dev/null || cat /sys/class/ubi/*/dev 2>/dev/null"),
            ("fdisk_l.txt", "fdisk -l 2>/dev/null"),
        ],
        "network_config": [
            ("ip_addr.txt", "ip -d addr show"),
            ("ip_route.txt", "ip route show table all"),
            ("ip_rule.txt", "ip rule show"),
            ("ip_neigh.txt", "ip neigh show"),
            ("ifconfig.txt", "ifconfig -a"),
            ("netstat_tulpen.txt", "netstat -tulpen 2>/dev/null || netstat -an"),
            ("iptables_rules.txt", "iptables-save 2>/dev/null || iptables -L -v -n"),
            ("ip6tables_rules.txt", "ip6tables-save 2>/dev/null || ip6tables -L -v -n"),
            ("resolv_conf.txt", "cat /etc/resolv.conf"),
            ("hosts.txt", "cat /etc/hosts"),
            ("ethtool_status.txt", "for iface in $(ip -br link | awk '{print $1}'); do echo \"=== $iface ===\"; ethtool $iface 2>/dev/null; done"),
        ],
        "processes_services": [
            ("ps_ef.txt", "ps -ef"),
            ("systemd_units.txt", "systemctl list-units --all --no-pager 2>/dev/null || ls -la /etc/init.d/"),
            ("systemd_timers.txt", "systemctl list-timers --no-pager 2>/dev/null"),
            ("top_snapshot.txt", "top -b -n 1 | head -n 40"),
        ],
        "security_credentials": [
            ("passwd.txt", "cat /etc/passwd"),
            ("shadow.txt", "cat /etc/shadow"),
            ("group.txt", "cat /etc/group"),
            ("sudoers.txt", "cat /etc/sudoers 2>/dev/null || echo 'No sudoers'"),
            ("suid_binaries.txt", "find / -perm -4000 -type f 2>/dev/null"),
            ("ssh_keys.txt", "ls -la /root/.ssh/ /etc/ssh/ /etc/dropbear/ 2>/dev/null; cat /root/.ssh/* 2>/dev/null"),
            ("dropbear_keys.txt", "ls -la /etc/dropbear/ 2>/dev/null"),
            ("ca_certs.txt", "find /etc/ssl /etc/pki /usr/share/ca-certificates /usrdata/certs /data/certs -type f 2>/dev/null"),
        ],
        "telemetry_vendor": [
            ("dc_conf.json", "cat /usrdata/dc_config/dc.conf 2>/dev/null"),
            ("ver_conf.txt", "cat /usrdata/dc_config/ver.conf 2>/dev/null"),
            ("lux_atc_bootup_sh.txt", "cat /sbin/lux_atc_boot-up.sh 2>/dev/null"),
            ("lux_system_events.log", "tail -n 200 /data/lux_system_events.log 2>/dev/null"),
            ("lux_atc.log", "tail -n 200 /data/lux_atc.log 2>/dev/null"),
            ("absl_debug.log", "tail -n 200 /data/absl_debug.log.0 2>/dev/null"),
            ("usrdata_ls.txt", "ls -laR /usrdata/ 2>/dev/null"),
            ("data_ls.txt", "ls -laR /data/ 2>/dev/null"),
            ("vendor_ls.txt", "ls -laR /vendor/ 2>/dev/null; ls -laR /data/vendor/ 2>/dev/null"),
            ("persist_ls.txt", "ls -laR /persist/ 2>/dev/null"),
        ],
        "cellular_modem": [
            ("at_gsn.txt", "echo -e 'AT+GSN\r' | microcom -t 1000 /dev/smd11 2>/dev/null || echo -e 'AT+GSN\r' | microcom -t 1000 /dev/smd7 2>/dev/null"),
            ("at_ati.txt", "echo -e 'ATI\r' | microcom -t 1000 /dev/smd11 2>/dev/null || echo -e 'ATI\r' | microcom -t 1000 /dev/smd7 2>/dev/null"),
            ("at_qgmr.txt", "echo -e 'AT+QGMR\r' | microcom -t 1000 /dev/smd11 2>/dev/null || echo -e 'AT+QGMR\r' | microcom -t 1000 /dev/smd7 2>/dev/null"),
            ("at_cpin.txt", "echo -e 'AT+CPIN?\r' | microcom -t 1000 /dev/smd11 2>/dev/null || echo -e 'AT+CPIN?\r' | microcom -t 1000 /dev/smd7 2>/dev/null"),
            ("at_qeng.txt", "echo -e 'AT+QENG=\"servingcell\"\r' | microcom -t 1000 /dev/smd11 2>/dev/null || echo -e 'AT+QENG=\"servingcell\"\r' | microcom -t 1000 /dev/smd7 2>/dev/null"),
            ("at_qnwinfo.txt", "echo -e 'AT+QNWINFO\r' | microcom -t 1000 /dev/smd11 2>/dev/null || echo -e 'AT+QNWINFO\r' | microcom -t 1000 /dev/smd7 2>/dev/null"),
            ("at_qcainfo.txt", "echo -e 'AT+QCAINFO\r' | microcom -t 1000 /dev/smd11 2>/dev/null || echo -e 'AT+QCAINFO\r' | microcom -t 1000 /dev/smd7 2>/dev/null"),
            ("at_cgdcont.txt", "echo -e 'AT+CGDCONT?\r' | microcom -t 1000 /dev/smd11 2>/dev/null || echo -e 'AT+CGDCONT?\r' | microcom -t 1000 /dev/smd7 2>/dev/null"),
            ("at_quimslot.txt", "echo -e 'AT+QUIMSLOT?\r' | microcom -t 1000 /dev/smd11 2>/dev/null || echo -e 'AT+QUIMSLOT?\r' | microcom -t 1000 /dev/smd7 2>/dev/null"),
            ("at_qcfg_band.txt", "echo -e 'AT+QCFG=\"band\"\r' | microcom -t 1000 /dev/smd11 2>/dev/null || echo -e 'AT+QCFG=\"band\"\r' | microcom -t 1000 /dev/smd7 2>/dev/null"),
        ]
    }

    total_cmds = sum(len(cmds) for cmds in categories.values())
    executed = 0

    print(f"\n=======================================================")
    print(f"[*] Starting Deep Forensic Audit: {total_cmds} Evidence Tasks")
    print(f"=======================================================\n")

    for cat_name, cmd_list in categories.items():
        cat_dir = EVIDENCE_DIR / cat_name
        cat_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n---> [Category: {cat_name}] ({len(cmd_list)} artifacts)")
        
        for filename, command in cmd_list:
            executed += 1
            out_file = cat_dir / filename
            print(f"  [{executed}/{total_cmds}] Executing: {command[:55]}...")
            
            # Use longer timeout for dmesg, trees, logs
            timeout = 15 if ("dmesg" in command or "ls -laR" in command or "find /" in command) else 8
            body, code = auditor.exec(command, timeout=timeout)
            
            with open(out_file, "w", encoding="utf-8", errors="replace") as f:
                f.write(body)
                
            status_tag = f"OK ({len(body)}b)" if code == 0 else f"RC={code} ({len(body)}b)"
            print(f"        Saved to {filename} [{status_tag}]")

    # Now extract high-value binaries and configs via base64
    print(f"\n---> [File Extraction via Base64]")
    extracted_dir = EVIDENCE_DIR / "extracted_files"
    files_to_extract = [
        "/usrdata/dc_config/dc.conf",
        "/usrdata/dc_config/ver.conf",
        "/sbin/lux_atc_boot-up.sh",
        "/data/lux_system_events.log",
        "/data/lux_atc.log",
        "/data/service_config.txt",
        "/data/reboot_timestamp",
        "/data/reboot-cookie",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
    ]

    for remote_f in files_to_extract:
        fname = Path(remote_f).name
        target_f = extracted_dir / f"{fname}"
        auditor.extract_file_base64(remote_f, target_f)

    # Check for certificates or databases
    print(f"[*] Checking for database and certificate files...")
    find_certs, _ = auditor.exec("find / -name '*.pem' -o -name '*.crt' -o -name '*.db' 2>/dev/null")
    with open(EVIDENCE_DIR / "security_credentials" / "crypto_assets_found.txt", "w") as f:
        f.write(find_certs)
    
    cert_lines = [l.strip() for l in find_certs.splitlines() if l.strip()]
    print(f"[+] Found {len(cert_lines)} potential crypto/database assets on filesystem.")
    for cert_path in cert_lines[:8]: # Extract top assets
        cname = cert_path.replace("/", "_").lstrip("_")
        auditor.extract_file_base64(cert_path, extracted_dir / cname)

    auditor.close()
    print(f"\n=======================================================")
    print(f"[+] Deep Forensic Audit Collection Complete!")
    print(f"[+] All artifacts saved in: {EVIDENCE_DIR}")
    print(f"=======================================================\n")

if __name__ == "__main__":
    run_audit()
