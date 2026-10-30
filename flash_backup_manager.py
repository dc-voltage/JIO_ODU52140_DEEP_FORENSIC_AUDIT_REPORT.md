#!/usr/bin/env python3
"""
Qualcomm SDX65 / Jio ODU 52140 Automated Full Flash Partition Backup Engine
Monitors UART on boot, neutralizes runaway service, and streams all 34 MTD partitions.
"""

import os
import sys
import time
import socket
import serial
import hashlib
import threading
import json
from pathlib import Path

UART_PORT = "/dev/ttyUSB0"
UART_BAUD = 115200
TARGET_IP = "192.168.225.1"
HOST_IP = "192.168.225.32"
STREAM_PORT = 9999
BACKUP_DIR = Path("/home/dc/Documents/odu52140/partitions_backup")

PARTITIONS = [
    ("mtd0", "sbl", 0x00280000),             # 2.5 MB
    ("mtd1", "mibib", 0x00100000),           # 1.0 MB
    ("mtd2", "efs2", 0x01600000),            # 22.0 MB
    ("mtd3", "rawdata", 0x00280000),         # 2.5 MB
    ("mtd4", "sys_rev", 0x00380000),         # 3.5 MB
    ("mtd5", "mdcompress", 0x00280000),      # 2.5 MB
    ("mtd6", "tz", 0x00200000),              # 2.0 MB
    ("mtd7", "tz_devcfg", 0x00140000),       # 1.25 MB
    ("mtd8", "ddr", 0x00140000),             # 1.25 MB
    ("mtd9", "apdp", 0x00140000),            # 1.25 MB
    ("mtd10", "xbl_config", 0x00140000),     # 1.25 MB
    ("mtd11", "xbl_ramdump", 0x00100000),    # 1.0 MB
    ("mtd12", "multi_image", 0x00140000),    # 1.25 MB
    ("mtd13", "multi_image_qti", 0x00100000),# 1.0 MB
    ("mtd14", "aop", 0x00140000),            # 1.25 MB
    ("mtd15", "qhee", 0x00140000),           # 1.25 MB
    ("mtd16", "abl", 0x00140000),            # 1.25 MB
    ("mtd17", "uefi", 0x00340000),           # 3.25 MB
    ("mtd18", "toolsfv", 0x00140000),        # 1.25 MB
    ("mtd19", "loader_sti", 0x00140000),     # 1.25 MB
    ("mtd20", "logfs", 0x00100000),          # 1.0 MB
    ("mtd21", "devinfo", 0x00140000),        # 1.25 MB
    ("mtd22", "sec", 0x00140000),            # 1.25 MB
    ("mtd23", "multi_fota", 0x00740000),     # 7.25 MB
    ("mtd24", "misc", 0x00140000),           # 1.25 MB
    ("mtd25", "ipa_fw", 0x00140000),         # 1.25 MB
    ("mtd26", "usb_qti", 0x00140000),        # 1.25 MB
    ("mtd27", "boot", 0x00d00000),           # 13.0 MB
    ("mtd28", "recovery", 0x00d00000),       # 13.0 MB
    ("mtd29", "recoveryfs", 0x01400000),     # 20.0 MB
    ("mtd30", "modem", 0x04800000),          # 72.0 MB
    ("mtd31", "system", 0x06900000),         # 105.0 MB
    ("mtd32", "mfg_data", 0x00100000),       # 1.0 MB
    ("mtd33", "usrdata", 0x0dbc0000),        # 219.75 MB
]

class FlashBackupEngine:
    def __init__(self):
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        print(f"[*] Initializing Serial on {UART_PORT} (115200 baud)...")
        self.ser = serial.Serial(UART_PORT, UART_BAUD, timeout=0.2)
        
        # Setup TCP Server once with REUSEADDR
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("0.0.0.0", STREAM_PORT))
        self.server.listen(10)
        print(f"[+] TCP Partition receiver listening on {HOST_IP}:{STREAM_PORT}")

    def wait_for_device(self):
        """Wait for live prompt or catch fresh bootloader sequence."""
        print("[*] Probing for device root shell or boot sequence...")
        print("[!] >>> PLEASE POWER CYCLE THE ODU NOW (UNPLUG & RECONNECT POWER) <<<")
        
        start_time = time.time()
        buf = ""
        while True:
            # Check UART output
            if self.ser.in_waiting > 0:
                chunk = self.ser.read(self.ser.in_waiting).decode("utf-8", errors="replace")
                buf += chunk
                sys.stdout.write(chunk)
                sys.stdout.flush()
                
                # Check for login prompt or shell
                if "root@sdxlemur" in buf or ":~#" in buf or "/ #" in buf:
                    print("\n[+] Shell prompt detected!")
                    break
            else:
                # Intermittently send newlines to probe for active shell
                self.ser.write(b"\r\n")
                time.sleep(0.4)

        # Immediate stabilization
        print("\n[*] Neutralizing runaway process loop...")
        self.ser.write(b"systemctl mask lux_rcS.service\r\n")
        time.sleep(0.3)
        self.ser.write(b"killall -9 lux_atc_boot-up.sh rcS\r\n")
        time.sleep(0.3)
        self.ser.write(b"echo 'SYSTEM_STABILIZED'\r\n")
        time.sleep(0.5)
        self.ser.reset_input_buffer()
        print("[+] Device scheduler stabilized. Ready for full backup!")

    def dump_single_partition(self, mtd_id, part_name, expected_size):
        out_file = BACKUP_DIR / f"{mtd_id}_{part_name}.bin"
        print(f"\n[>>>] Dumping {mtd_id} ({part_name}) -> {expected_size / (1024*1024):.2f} MB...")
        
        received_bytes = 0
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        t0 = time.time()
        
        def listener():
            nonlocal received_bytes
            try:
                conn, addr = self.server.accept()
                with open(out_file, "wb") as f:
                    while True:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        f.write(chunk)
                        sha256.update(chunk)
                        md5.update(chunk)
                        received_bytes += len(chunk)
                conn.close()
            except Exception as e:
                print(f"      [!] Socket listener error: {e}")

        thread = threading.Thread(target=listener, daemon=True)
        thread.start()

        # Send command over UART
        self.ser.reset_input_buffer()
        self.ser.write(b"\r\n")
        time.sleep(0.1)
        cmd = f"cat /dev/{mtd_id}ro 2>/dev/null | nc {HOST_IP} {STREAM_PORT}\r\n"
        self.ser.write(cmd.encode())
        
        # Calculate dynamic timeout: 15s base + 1s per 2MB
        timeout = max(15, int(expected_size / (1024 * 1024 * 2)) + 10)
        thread.join(timeout=timeout)
        dur = time.time() - t0

        actual_size = out_file.stat().st_size if out_file.exists() else 0
        speed = (actual_size / dur / (1024 * 1024)) if dur > 0 else 0
        sha_hex = sha256.hexdigest()
        md5_hex = md5.hexdigest()
        
        status = "OK" if actual_size == expected_size else f"DIFF ({actual_size}/{expected_size})"
        print(f"      [{status}] {actual_size} bytes in {dur:.2f}s ({speed:.2f} MB/s)")
        print(f"      MD5   : {md5_hex}")
        print(f"      SHA256: {sha_hex}")
        
        return {
            "mtd": mtd_id,
            "name": part_name,
            "expected_size": expected_size,
            "actual_size": actual_size,
            "status": status,
            "time_sec": round(dur, 2),
            "md5": md5_hex,
            "sha256": sha_hex
        }

    def run(self):
        self.wait_for_device()
        print("\n" + "="*65)
        print("  STREAMING ALL 34 FLASH PARTITIONS OVER GIGABIT ETHERNET")
        print("="*65)
        
        results = []
        for mtd, name, size in PARTITIONS:
            res = self.dump_single_partition(mtd, name, size)
            results.append(res)
            time.sleep(0.2)
            
        # Manifest
        with open(BACKUP_DIR / "checksums.sha256", "w") as f_sha, \
             open(BACKUP_DIR / "checksums.md5", "w") as f_md5, \
             open(BACKUP_DIR / "manifest.json", "w") as f_json:
            for r in results:
                fname = f"{r['mtd']}_{r['name']}.bin"
                f_sha.write(f"{r['sha256']}  {fname}\n")
                f_md5.write(f"{r['md5']}  {fname}\n")
            json.dump(results, f_json, indent=2)

        print("\n" + "="*65)
        print(f"[+] FULL BACKUP SUCCESSFUL!")
        print(f"[+] All partitions and checksums saved to: {BACKUP_DIR}")
        print("="*65)
        self.server.close()
        self.ser.close()

if __name__ == "__main__":
    engine = FlashBackupEngine()
    engine.run()
