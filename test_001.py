# test_agent.py — pruebas automáticas del mini SNMP Agent
# Arturo (Network Management Course - Unizar)
# --- test_agent.py ---

import time

from pysnmp.hlapi.v3arch.asyncio import UdpTransportTarget

# 1. Importar los componentes de la API de alto nivel (hlapi)
from pysnmp.hlapi.asyncio import (
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd,
    setCmd,
    nextCmd,
    OctetString,
    Integer,
    ObjectIdentifier
)

# 2. Importar el motor SNMP (SnmpEngine) desde su ubicación central
from pysnmp.entity.engine import SnmpEngine

# (El resto de tu código continúa igual...)
import time

AGENT = ('127.0.0.1', 161)
COMMUNITY_RO = 'public'
COMMUNITY_RW = 'private'

OIDS = {
    "manager": "1.3.6.1.4.1.28308.1.1.1.0",
    "managerEmail": "1.3.6.1.4.1.28308.1.1.2.0",
    "cpuUsage": "1.3.6.1.4.1.28308.1.1.3.0",
    "cpuThreshold": "1.3.6.1.4.1.28308.1.1.4.0"
}

# -------------------------------
# FUNCIONES AUXILIARES
# -------------------------------

async def snmp_get(oid, community=COMMUNITY_RO):
    """Ejecuta un SNMP GET y devuelve el valor."""
    # (Esta función ya era correcta, ahora funcionará con la importación corregida)
    target = await UdpTransportTarget.create(('127.0.0.1', 161), timeout=1, retries=2)
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        target, # Esta línea ya no dará error
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication:
        print(f"[GET] Error: {errorIndication}")
        return None
    elif errorStatus:
        print(f"[GET] {errorStatus.prettyPrint()} at {errorIndex}")
        return None
    else:
        for oid, val in varBinds:
            print(f"[GET] {oid.prettyPrint()} = {val.prettyPrint()}")
            return val.prettyPrint()

async def snmp_set(oid, value, type_tag, community=COMMUNITY_RW):
    """Ejecuta un SNMP SET (solo RW community)."""
    # (Esta función ya era correcta)
    target = await UdpTransportTarget.create(('127.0.0.1', 161), timeout=1, retries=2)
    iterator = setCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        target,
        ContextData(),
        ObjectType(ObjectIdentity(oid), type_tag(value))
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication:
        print(f"[SET] Error: {errorIndication}")
    elif errorStatus:
        print(f"[SET] {errorStatus.prettyPrint()} at {errorIndex}")
    else:
        for oid, val in varBinds:
            print(f"[SET] {oid.prettyPrint()} = {val.prettyPrint()}")

# --- CORRECCIÓN 2: Lógica de WALK (GETNEXT) ---
# La función snmp_getnext original no recorría el árbol.
# Esta nueva función 'snmp_walk_subtree' lo hace correctamente.
async def snmp_walk_subtree(start_oid_str):
    """Realiza un SNMP WALK (usando GETNEXT) para recorrer un subárbol."""
    print(f"[WALK] Recorriendo subárbol: {start_oid_str}")
    
    # Objeto OID para comparar prefijos
    subtree_oid = ObjectIdentifier(start_oid_str)
    target = await UdpTransportTarget.create(('127.0.0.1', 161), timeout=1, retries=2)
    iterator = nextCmd(
        SnmpEngine(),
        CommunityData(COMMUNITY_RO, mpModel=1),
        target,
        ContextData(),
        ObjectType(ObjectIdentity(start_oid_str)), # OID inicial
        lexicographicMode=False # Mantenemos tu configuración
    )

    for (errorIndication, errorStatus, errorIndex, varBinds) in iterator:
        if errorIndication:
            print(f"  Error: {errorIndication}")
            break
        elif errorStatus:
            print(f"  SNMP Error: {errorStatus.prettyPrint()} at {errorIndex}")
            break
        else:
            # nextCmd devuelve un solo varBind
            oid, val = varBinds[0] 
            
            # Comprobamos si el OID devuelto sigue dentro de nuestro subárbol
            if not subtree_oid.isPrefixOf(oid):
                print("  Fin del subárbol.")
                break # Detiene el bucle
            
            print(f"  {oid.prettyPrint()} = {val.prettyPrint()}")

# -------------------------------
# SECUENCIA DE PRUEBAS
# -------------------------------
if __name__ == "__main__":
    print("=== TEST 1: GET inicial ===")
    for name, oid in OIDS.items():
        snmp_get(oid)
    print()

    print("=== TEST 2: SET valores modificables ===")
    snmp_set(OIDS["manager"], "Arturo-Agent", OctetString)
    snmp_set(OIDS["managerEmail"], "test@unizar.es", OctetString)
    snmp_set(OIDS["cpuThreshold"], 70, Integer)
    print()

    print("=== TEST 3: GET tras el SET ===")
    for name in ("manager", "managerEmail", "cpuThreshold"):
        snmp_get(OIDS[name])
    print()

    print("=== TEST 4: WALK (recorrido del subtree) ===")
    # Llamamos a la nueva función de walk
    snmp_walk_subtree("1.3.6.1.4.1.28308.1.1") 
    print()

    print("=== TEST 5: CPU dinámico ===")
    print("Leyendo cpuUsage 3 veces (cada ~5s):")
    for _ in range(3):
        snmp_get(OIDS["cpuUsage"])
        time.sleep(5)

    print("\n✅ Pruebas completadas.")
