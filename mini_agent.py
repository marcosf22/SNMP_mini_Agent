
# mini_agent.py — SNMP mini-agent (pysnmp 7.1.4)
# Author: Arturo
# Date: 2025-11-10

import asyncio
import json
import os
import psutil
import time
import smtplib
from email.message import EmailMessage

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, ntforg
from pysnmp.proto.api import v2c

JSON_FILE = "mib_state.json"

# -------------------------
#   JSON STATE MANAGEMENT
# -------------------------
class JsonStore:
    def __init__(self, filename):
        self.filename = filename
        if os.path.exists(filename):
            with open(filename) as f:
                self.model = json.load(f)
        else:
            raise FileNotFoundError("Missing mib_state.json")

        # Build lookup map
        self.oid_map = {tuple(map(int, v["oid"].split("."))): k
                        for k, v in self.model["scalars"].items()}
        self.sorted_oids = sorted(self.oid_map.keys())

    def save(self):
        with open(self.filename, "w") as f:
            json.dump(self.model, f, indent=2)

    def get_exact(self, oid_tuple):
        if oid_tuple in self.oid_map:
            key = self.oid_map[oid_tuple]
            val = self.model["scalars"][key]["value"]
            typ = self.model["scalars"][key]["type"]
            return True, self._to_snmp_type(val, typ)
        return False, None

    def get_next(self, oid_tuple):
        for next_oid in self.sorted_oids:
            if next_oid > oid_tuple:
                key = self.oid_map[next_oid]
                val = self.model["scalars"][key]["value"]
                typ = self.model["scalars"][key]["type"]
                return True, next_oid, self._to_snmp_type(val, typ)
        return False, None, None

    def validate_set(self, oid_tuple, val):
        if oid_tuple not in self.oid_map:
            return 6, 0  # noAccess
        key = self.oid_map[oid_tuple]
        meta = self.model["scalars"][key]

        if meta["access"] == "read-only":
            return 17, 0  # notWritable

        if meta["type"] == "DisplayString" and not isinstance(val, v2c.OctetString):
            return 7, 0  # wrongType
        if meta["type"] == "Integer32" and not isinstance(val, v2c.Integer):
            return 7, 0

        if meta["type"] == "DisplayString":
            s = str(val.prettyPrint())
            if not (meta["min_len"] <= len(s) <= meta["max_len"]):
                return 10, 0  # wrongValue
        if meta["type"] == "Integer32":
            i = int(val)
            if not (meta["min_val"] <= i <= meta["max_val"]):
                return 10, 0

        return 0, 0  # OK

    def commit_set(self, oid_tuple, val):
        key = self.oid_map[oid_tuple]
        meta = self.model["scalars"][key]
        if meta["type"] == "DisplayString":
            meta["value"] = str(val.prettyPrint())
        else:
            meta["value"] = int(val)
        self.save()

    def _to_snmp_type(self, value, typ):
        return v2c.OctetString(value.encode()) if typ == "DisplayString" else v2c.Integer(int(value))

    # internal setter for cpuUsage
    def set_cpu_usage_internal(self, value):
        self.model["scalars"]["cpuUsage"]["value"] = int(value)
        self.save()


STORE = JsonStore(JSON_FILE)

# -------------------------
#   SNMP RESPONDERS
# -------------------------
class JsonGet(cmdrsp.GetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = []
        for oid, _ in req:
            found, val = STORE.get_exact(tuple(oid))
            rsp.append((oid, val if found else v2c.NoSuchObject()))
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)


class JsonGetNext(cmdrsp.NextCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        req = v2c.apiPDU.getVarBinds(PDU)
        rsp = []
        for oid, _ in req:
            ok, next_oid, val = STORE.get_next(tuple(oid))
            if ok:
                rsp.append((v2c.ObjectIdentifier(next_oid), val))
            else:
                rsp.append((oid, v2c.EndOfMibView()))
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)


class JsonSet(cmdrsp.SetCommandResponder):
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU):
        req = v2c.apiPDU.getVarBinds(PDU)
        # Phase 1: validate
        for idx, (oid, val) in enumerate(req, start=1):
            err, _ = STORE.validate_set(tuple(oid), val)
            if err != 0:
                rspPDU = v2c.apiPDU.getResponse(PDU)
                v2c.apiPDU.setErrorStatus(rspPDU, err)
                v2c.apiPDU.setErrorIndex(rspPDU, idx)
                v2c.apiPDU.setVarBinds(rspPDU, req)
                self.sendPdu(snmpEngine, stateReference, rspPDU)
                return
        # Phase 2: commit
        for oid, val in req:
            STORE.commit_set(tuple(oid), val)
        # Response
        rsp = []
        for oid, _ in req:
            found, val = STORE.get_exact(tuple(oid))
            rsp.append((oid, val if found else v2c.NoSuchObject()))
        rspPDU = v2c.apiPDU.getResponse(PDU)
        v2c.apiPDU.setErrorStatus(rspPDU, 0)
        v2c.apiPDU.setErrorIndex(rspPDU, 0)
        v2c.apiPDU.setVarBinds(rspPDU, rsp)
        self.sendPdu(snmpEngine, stateReference, rspPDU)

# -------------------------
#   TRAP SENDER
# -------------------------
def send_trap():
    thr = int(STORE.model["scalars"]["cpuThreshold"]["value"])
    cpu = int(STORE.model["scalars"]["cpuUsage"]["value"])
    email = str(STORE.model["scalars"]["managerEmail"]["value"])

    print(f"[TRAP] CPU {cpu}% exceeded threshold {thr}% -> sending trap & email")

    ntfOrg = ntforg.NotificationOriginator()
    errorIndication = ntfOrg.sendNotification(
        snmpEngine,
        "my-area",
        None,
        "",
        "trap",
        (
            (v2c.ObjectIdentifier("1.3.6.1.4.1.28308.1.2.1"), v2c.Integer(1)),
            (v2c.ObjectIdentifier("1.3.6.1.4.1.28308.1.1.3.0"), v2c.Integer(cpu)),
            (v2c.ObjectIdentifier("1.3.6.1.4.1.28308.1.1.4.0"), v2c.Integer(thr)),
            (v2c.ObjectIdentifier("1.3.6.1.4.1.28308.1.1.2.0"), v2c.OctetString(email.encode())),
        ),
    )

    if errorIndication:
        print("Trap send failed:", errorIndication)
    else:
        send_email(email, cpu, thr)


def send_email(to_addr, cpu, thr):
    msg = EmailMessage()
    msg["Subject"] = "CPU Threshold Exceeded"
    msg["From"] = "mini-agent@localhost"
    msg["To"] = to_addr
    msg.set_content(f"CPU usage exceeded threshold:\nCPU={cpu}% > Threshold={thr}%")

    try:
        with smtplib.SMTP("localhost", 1025) as s:
            s.send_message(msg)
        print(f"Email sent to {to_addr}")
    except Exception as e:
        print(f"Email send failed: {e}")

# -------------------------
#   CPU MONITOR TASK
# -------------------------
AGENT_START = time.time()

async def cpu_sampler():
    psutil.cpu_percent(interval=None)
    last_over = False
    while True:
        await asyncio.sleep(5)
        cpu = round(psutil.cpu_percent(interval=None))
        cpu = max(0, min(100, cpu))
        STORE.set_cpu_usage_internal(cpu)
        thr = int(STORE.model["scalars"]["cpuThreshold"]["value"])
        over = cpu > thr
        if over and not last_over:
            send_trap()
        last_over = over

# -------------------------
#   SNMP ENGINE SETUP
# -------------------------
snmpEngine = engine.SnmpEngine()

# UDP endpoint
config.addTransport(
    snmpEngine,
    udp.DOMAIN_NAME + (1,),
    udp.UdpTransport().openServerMode(("127.0.0.1", 161))
)

# Communities
config.addV1System(snmpEngine, "public-area", "public")
config.addV1System(snmpEngine, "private-area", "private")

# VACM
for secModel in (1, 2):
    config.addVacmUser(
        snmpEngine, secModel, "public-area", "noAuthNoPriv",
        readSubTree=(1, 3, 6, 1)
    )
    config.addVacmUser(
        snmpEngine, secModel, "private-area", "noAuthNoPriv",
        readSubTree=(1, 3, 6, 1),
        writeSubTree=(1, 3, 6, 1)
    )

# Trap target
config.addTargetParams(snmpEngine, "my-creds", "public-area", "noAuthNoPriv", 1)
config.addTargetAddr(
    snmpEngine,
    "my-area",
    udp.DOMAIN_NAME,
    ("127.0.0.1", 162),
    "my-creds"
)

# ✅ Create SNMP context (required in pysnmp 7.x)
from pysnmp.entity.rfc3413 import context
snmpContext = context.SnmpContext(snmpEngine)

# ✅ Register responders
JsonGet(snmpEngine, snmpContext)
JsonGetNext(snmpEngine, snmpContext)
JsonSet(snmpEngine, snmpContext)

# -------------------------
#   RUN AGENT
# -------------------------
loop = asyncio.get_event_loop()
loop.create_task(cpu_sampler())
print("Mini SNMP Agent running on udp:161 (Ctrl+C to stop)")
try:
    loop.run_forever()
except KeyboardInterrupt:
    print("Agent stopped.")
