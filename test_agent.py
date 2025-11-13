# test_agent.py — pruebas automáticas del mini SNMP Agent
# Versión mejorada con Pruebas Negativas y WALK completo
import asyncio
import time

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

# 2. Importar el motor SNMP (SnmpEngine)
from pysnmp.entity.engine import SnmpEngine

# 3. --- ¡NUEVA IMPORTACIÓN REQUERIDA! ---
# Necesitamos v2c para comprobar la excepción 'EndOfMibView'
from pysnmp.proto.api import v2c

AGENT = ('127.0.0.1', 161)
COMMUNITY_RO = 'public'
COMMUNITY_RW = 'private'

OIDS = {
    "manager": "1.3.6.1.4.1.28308.1.1.1.0",
    "managerEmail": "1.3.6.1.4.1.28308.1.1.2.0",
    "cpuUsage": "1.3.6.1.4.1.28308.1.1.3.0",
    "cpuThreshold": "1.3.6.1.4.1.28308.1.1.4.0",
    # OID base para el WALK (Test 2.7.8)
    "base_subtree": "1.3.6.1.4.1.28308.1.1" 
}

# -------------------------------
# FUNCIONES AUXILIARES (sin cambios)
# -------------------------------

async def snmp_get(oid, community=COMMUNITY_RO):
    """Ejecuta un SNMP GET y devuelve el valor."""
    target = await UdpTransportTarget.create(AGENT, timeout=1, retries=2)
    errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1), # mpModel=1 es v2c
        target,
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )

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
    target = await UdpTransportTarget.create(AGENT, timeout=1, retries=2)
    errorIndication, errorStatus, errorIndex, varBinds = await setCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        target,
        ContextData(),
        ObjectType(ObjectIdentity(oid), type_tag(value))
    )
    
    if errorIndication:
        print(f"[SET] Error: {errorIndication}")
    elif errorStatus:
        # Imprimimos el error SNMP, que es lo que buscamos en los tests negativos
        print(f"[SET] Error: {errorStatus.prettyPrint()} at index {errorIndex}")
    else:
        for oid, val in varBinds:
            print(f"[SET] {oid.prettyPrint()} = {val.prettyPrint()}")

# --- CORRECCIÓN 2: Lógica de WALK (GETNEXT) ---
# Esta es la función de WALK corregida

async def snmp_walk_subtree(start_oid_str):
    """Realiza un SNMP WALK (usando GETNEXT) para recorrer un subárbol."""
    print(f"[WALK] Recorriendo subárbol: {start_oid_str}")
    
    subtree_oid = ObjectIdentifier(start_oid_str)
    current_oid = ObjectIdentifier(start_oid_str)
    target = await UdpTransportTarget.create(AGENT, timeout=1, retries=2)

    while True:
        errorIndication, errorStatus, errorIndex, varBindsList = await nextCmd(
            SnmpEngine(),
            CommunityData(COMMUNITY_RO, mpModel=1),
            target,
            ContextData(),
            ObjectType(ObjectIdentity(current_oid)),
            lexicographicMode=True
        )

        if errorIndication:
            print(f"  [WALK] Error: {errorIndication}")
            break
        elif errorStatus:
            print(f"  [WALK] SNMP Error: {errorStatus.prettyPrint()} at {errorIndex}")
            break
        
        oid, val = varBindsList[0]
        
        # --- ¡ESTA ES LA LÍNEA DE CORRECCIÓN! ---
        # Comprobar si el VALOR es EndOfMibView antes de cualquier otra cosa
        if val.isSameTypeWith(v2c.EndOfMibView()):
            print(f"  [WALK] Fin del subárbol (EndOfMibView).")
            break
        
        # Comprobar si el OID se salió del subárbol
        if not subtree_oid.isPrefixOf(oid):
            print(f"  [WALK] Fin del subárbol (recibido {oid.prettyPrint()}).")
            break
        
        # Si todo está bien, imprimir y continuar
        print(f"  [WALK] {oid.prettyPrint()} = {val.prettyPrint()}")
        current_oid = oid # Preparamos la siguiente iteración

# -------------------------------
# SECUENCIA DE PRUEBAS (Principal)
# -------------------------------

async def run_all_tests():

    print("=== TEST 1: GET inicial ===")
    for name, oid in OIDS.items():
        if name != "base_subtree":
            await snmp_get(oid)
    print("--------------------------------\n")


    print("=== TEST 2: SET valores modificables ===")
    await snmp_set(OIDS["manager"], "Marcos-Agente", OctetString)
    await snmp_set(OIDS["managerEmail"], "marcosfraile2004@gmail.com", OctetString)
    await snmp_set(OIDS["cpuThreshold"], 75, Integer)
    print("--------------------------------\n")


    print("=== TEST 3: GET tras el SET (Verificación) ===")
    for name in ("manager", "managerEmail", "cpuThreshold"):
        await snmp_get(OIDS[name])
    print("--------------------------------\n")


    print(f"=== TEST 4: WALK (recorrido del subtree {OIDS['base_subtree']}) ===")
    await snmp_walk_subtree(OIDS['base_subtree'])
    print("--------------------------------\n")


    print("=== TEST 5: CPU dinámico ===")
    print("Leyendo cpuUsage 3 veces (cada ~5s):")
    for _ in range(3):
        await snmp_get(OIDS["cpuUsage"])
        time.sleep(5)
    print("--------------------------------\n")

    
    print("=== TEST 6: Pruebas Negativas (Test 2.7.4) ===")
    print("Intentando escribir en 'cpuUsage' (debe fallar con 'notWritable')...")
    await snmp_set(OIDS["cpuUsage"], 10, Integer)
    
    print("\nIntentando escribir un STRING en 'cpuThreshold' (debe fallar con 'wrongType')...")
    await snmp_set(OIDS["cpuThreshold"], "esto-no-es-un-string", OctetString)

    print("\nIntentando escribir 999 en 'cpuThreshold' (asumiendo 0-100, debe fallar con 'wrongValue')...")
    await snmp_set(OIDS["cpuThreshold"], 999, Integer)
    print("--------------------------------\n")


    print("=== TEST 7: Provocación de TRAP (Test 2.7.7) ===")
    print("NOTA: Este test solo PROVOCA el trap. No verifica su recepción.")
    print("      Debes usar 'tcpdump' o Wireshark en el puerto 162 para verificarlo manualmente.")
    
    print("\nBajando el umbral a 1%. El trap debería enviarse en ~5-10 segundos...")
    await snmp_set(OIDS["cpuThreshold"], 1, Integer)
    
    time.sleep(10) 

    print("\nRestaurando umbral a un valor normal (90%)...")
    await snmp_set(OIDS["cpuThreshold"], 90, Integer)
    print("--------------------------------\n")


    print("=== PRUEBA MANUAL: Persistencia (Test 2.7.5) ===")
    print("Para probar la persistencia:")
    print("1. Revisa el 'TEST 3'. Debería mostrar 'Marcos-Agente'.")
    print("2. Detén el 'mini_agent.py' (Ctrl+C).")
    print("3. Vuelve a iniciar 'mini_agent.py'.")
    print("4. Ejecuta este script 'test_agent.py' otra vez.")
    print("5. Verifica que el 'TEST 1' muestra 'Marcos-Agente' (y no el valor por defecto).")
    print("--------------------------------\n")


    print("\n✅ Pruebas automáticas completadas.")

if __name__ == "__main__":
    asyncio.run(run_all_tests())