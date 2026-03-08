import time
import json
import os
import re
import requests
import logging
import sys
from datetime import datetime, timedelta
from pysnmp.hlapi import *

# ================= CONFIG =================

DB_FILE = "network_inventory.json"
HISTORY_FILE = "power_history.json"
ALERTS_FILE = "alerts_history.json"

TELEGRAM_TOKEN = "5365837414:AAGo1pHm0D2Hbh0l9elbpkUKDDIRjr_aN0g"
TELEGRAM_CHAT_ID = "-5083146219"

DEFAULT_WARNING = -16
DEFAULT_CRITICAL = -20
ALERT_REPEAT_HOURS = 12
POLL_INTERVAL = 60

# ================= OIDs =================

OID_IF_NAME = '1.3.6.1.2.1.2.2.1.2'
OID_IF_ALIAS = '1.3.6.1.2.1.31.1.1.1.18'
OID_ENTITY_NAME = '1.3.6.1.2.1.47.1.1.1.1.2'

# Cisco Entity Sensor
OID_CISCO_RX = '1.3.6.1.4.1.9.9.91.1.1.1.1.4'

# Arista
OID_ARISTA_SENSOR_VALUE = '1.3.6.1.2.1.99.1.1.1.4'
OID_ARISTA_SENSOR_NAME = '1.3.6.1.2.1.47.1.1.1.1.2'

# ================= LOGGER =================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
log = logging.getLogger()

# ================= CLASS =================

class NetworkCollector:

    def __init__(self):
        self.alert_state = {}

    # ---------- JSON ----------

    def load_json(self, file):
        if os.path.exists(file):
            try:
                with open(file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_json(self, data, file):
        try:
            with open(file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            log.error(f"Error saving JSON: {e}")

    # ---------- SNMP ----------

    def snmp_walk(self, host, community, oid):
        results = []
        try:
            for (errInd, errStat, _, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((host, 161), timeout=2, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            ):
                if errInd or errStat:
                    continue
                for v in varBinds:
                    results.append({
                        "oid": str(v[0]),
                        "value": str(v[1])
                    })
        except Exception as e:
            log.error(f"SNMP Error {host}: {e}")
            return []
        return results

    # ---------- Telegram ----------

    def send_telegram(self, message):
        if "YOUR_" in TELEGRAM_TOKEN:
            return
        try:
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": message,
                    "parse_mode": "HTML"
                },
                timeout=10
            )
        except:
            pass

    # ---------- Power Parse ----------

    def parse_power(self, raw):
        try:
            v = float(raw)
            if abs(v) > 2000:
                return round(v / 1000.0, 2)
            elif abs(v) > 500:
                return round(v / 100.0, 2)
            else:
                return round(v / 10.0, 2)
        except:
            return None

    # ---------- Discovery ----------

    def discover_ports(self, device):
        names = self.snmp_walk(device["ip"], device["community"], OID_IF_NAME)
        descs = self.snmp_walk(device["ip"], device["community"], OID_IF_ALIAS)

        idx_name = {n["oid"].split('.')[-1]: n["value"] for n in names}
        idx_desc = {d["oid"].split('.')[-1]: d["value"] for d in descs}

        ports = []
        port_desc = {}

        for idx, name in idx_name.items():
            lname = name.lower()
            if any(x in lname for x in ["vlan", "loopback", "null", "tunnel", "cpu", "mgmt"]):
                continue
            ports.append(name)
            port_desc[name] = idx_desc.get(idx, "")

        return sorted(ports), port_desc

    # ---------- Cisco Power ----------

    def collect_cisco(self, device, port_name):
        names = self.snmp_walk(device["ip"], device["community"], OID_ENTITY_NAME)
        values = self.snmp_walk(device["ip"], device["community"], OID_CISCO_RX)

        ndict = {n["oid"].split('.')[-1]: n["value"] for n in names}
        vdict = {v["oid"].split('.')[-1]: v["value"] for v in values}

        lanes = []
        for idx, name in ndict.items():
            if port_name.lower() in name.lower():
                if any(k in name.lower() for k in ["receive", "rx", "input"]):
                    raw = vdict.get(idx)
                    if raw:
                        p = self.parse_power(raw)
                        if p and -50 < p < 10:
                            lanes.append(p)

        if lanes:
            avg_power = round(sum(lanes)/len(lanes), 2)
            return avg_power, lanes

        return None, []

    # ---------- Arista Power ----------

    def collect_arista(self, device, port_name):
        names = self.snmp_walk(device["ip"], device["community"], OID_ARISTA_SENSOR_NAME)
        values = self.snmp_walk(device["ip"], device["community"], OID_ARISTA_SENSOR_VALUE)

        ndict = {n["oid"].split('.')[-1]: n["value"] for n in names}
        vdict = {v["oid"].split('.')[-1]: v["value"] for v in values}

        lanes = []
        for idx, s_name in ndict.items():
            if port_name.lower() in s_name.lower():
                if any(kw in s_name.lower() for kw in ["rx", "receive", "input"]):
                    raw = vdict.get(idx)
                    if raw and raw != "0":
                        p = self.parse_power(raw)
                        if p is not None and -45 < p < 10:
                            lanes.append(p)

        if lanes:
            avg_power = round(sum(lanes)/len(lanes), 2)
            return avg_power, lanes
        return None, []

    # ---------- Alert Logic ----------

    def check_alert(self, device_name, port_name, power, thresholds):
        port_id = f"{device_name}|{port_name}"
        now = datetime.now()

        warning = thresholds.get("warning", DEFAULT_WARNING)
        critical = thresholds.get("critical", DEFAULT_CRITICAL)

        # 1. تحديد مستوى المشكلة
        if power <= critical:
            level = "CRITICAL"
        elif power <= warning:
            level = "WARNING"
        else:
            # إذا رجع البور طبيعي، نحذف الحالة لإرسال تنبيه جديد مستقبلاً
            if port_id in self.alert_state:
                del self.alert_state[port_id]
                self.send_telegram(
                    f"✅ <b>Port Normal</b>\nDevice: {device_name}\nPort: {port_name}\nPower: {power} dBm"
                )
            return

        # 2. فحص حالة التنبيه الحالية (هل أرسلنا سابقاً؟)
        state = self.alert_state.get(port_id)

        # الحالة أ: أول مرة نكتشف المشكلة
        if not state:
            self.alert_state[port_id] = {
                "last_sent": now,
                "level": level
            }
            # إرسال التنبيه الفوري (المرة الأولى)
            self.send_telegram(
                f"⚠️ <b>Fiber Alert</b>\nDevice: {device_name}\nPort: {port_name}\nLevel: {level}\nPower: {power} dBm"
            )
            return

        # الحالة ب: المشكلة مستمرة، نفحص هل مرت 12 ساعة؟
        # ملاحظة: ALERT_REPEAT_HOURS معرفة في الأعلى بـ 12
        if now - state["last_sent"] >= timedelta(hours=ALERT_REPEAT_HOURS):
            # تحديث الوقت لإرسال التنبيه القادم بعد 12 ساعة أخرى
            state["last_sent"] = now
            self.send_telegram(
                f"⚠️ <b>Fiber Still Low (Reminder)</b>\nDevice: {device_name}\nPort: {port_name}\nLevel: {level}\nPower: {power} dBm"
            )

    # ---------- Main Loop ----------

    def run(self):
        log.info("Collector Started (4-Space Indentation Applied)")

        while True:
            inventory = self.load_json(DB_FILE)
            history = self.load_json(HISTORY_FILE)

            for device_name, device in inventory.items():

                # Discovery
                if not device.get("available_ports"):
                    log.info(f"Discovering ports for {device_name}...")
                    ports, desc = self.discover_ports(device)
                    device["available_ports"] = ports
                    device["port_descriptions"] = desc
                    self.save_json(inventory, DB_FILE)

                # Monitor Ports
                for port in device.get("ports", []):
                    # التحقق من كتم التنبيه
                    if port.get("ignore_threshold", False):
                        continue

                    pname = port["name"]
                    dtype = device.get("type", "").lower()

                    if "arista" in dtype:
                        res = self.collect_arista(device, pname)
                        power, lanes = res if isinstance(res, tuple) else (res, [])
                    else:
                        res = self.collect_cisco(device, pname)
                        power, lanes = res if isinstance(res, tuple) else (res, [])

                    if power is None:
                        log.warning(f"⚠️ Could not get power for {device_name} : {pname}")
                        continue

                    # --- استدعاء نظام التنبيهات (الإصلاح الرئيسي) ---
                    th = device.get("thresholds", {"warning": DEFAULT_WARNING, "critical": DEFAULT_CRITICAL})
                    self.check_alert(device_name, pname, power, th)
                    # -----------------------------------------------

                    pid = f"{device['ip']}_{pname}".replace("/", "-")
                    
                    if pid not in history:
                        history[pid] = []
                        
                    history[pid].append({
                        "timestamp": datetime.now().isoformat(),
                        "power": power,
                        "lanes": lanes 
                    })
                    history[pid] = history[pid][-5000:]

                    log.info(f"✅ Data for {device_name} {pname}: {power} dBm")

            self.save_json(history, HISTORY_FILE)
            time.sleep(POLL_INTERVAL)


# ================= RUN =================

if __name__ == "__main__":
    NetworkCollector().run()