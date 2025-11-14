import asyncio, time

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

from pysnmp.entity.engine import SnmpEngine
from pysnmp.proto.api import v2c


COMMUNITY_RO = 'public'
COMMUNITY_RW = 'private'
OIDS = {
    "manager": "1.3.6.1.4.1.28308.1.1.1.0",
    "managerEmail": "1.3.6.1.4.1.28308.1.1.2.0",
    "cpuUsage": "1.3.6.1.4.1.28308.1.1.3.0",
    "cpuThreshold": "1.3.6.1.4.1.28308.1.1.4.0",

    # OID base para el WALK.
    "base_subtree": "1.3.6.1.4.1.28308.1.1" 
}


# Función que realiza un GET.
async def snmp_get(oid, community=COMMUNITY_RO):
    target = await UdpTransportTarget.create(AGENT, timeout=1, retries=2)
    errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
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


# Función que realiza un GETNEXT.
async def snmp_getnext(oid, community=COMMUNITY_RO):
    target = await UdpTransportTarget.create(AGENT, timeout=1, retries=2) 
    errorIndication, errorStatus, errorIndex, varBindsList = await nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        target,
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    if errorIndication:
        print(f"  [GETNEXT] Error: {errorIndication}")
        return None, None
    elif errorStatus:
        print(f"  [GETNEXT] {errorStatus.prettyPrint()} at {errorIndex}")
        return None, None
    else:
        oid, val = varBindsList[0]
        if val.isSameTypeWith(v2c.EndOfMibView()):
            print(f"  [GETNEXT] Resultado: {oid.prettyPrint()} = EndOfMibView")
            return oid.prettyPrint(), "EndOfMibView"
        else:
            print(f"  [GETNEXT] Resultado: {oid.prettyPrint()} = {val.prettyPrint()}")
            return oid.prettyPrint(), val.prettyPrint()

# Función que realiza un SET.
async def snmp_set(oid, value, type_tag, community=COMMUNITY_RW):
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
        print(f"[SET] Error: {errorStatus.prettyPrint()} at index {errorIndex}")
    else:
        for oid, val in varBinds:
            print(f"[SET] {oid.prettyPrint()} = {val.prettyPrint()}")


# Función que realiza un SNMP WALK.
async def snmp_walk(start_oid_str):
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

        # Comprobamos si el VALOR es EndOfMibView antes de cualquier otra cosa.
        if val.isSameTypeWith(v2c.EndOfMibView()):
            print(f"  [WALK] Fin del subárbol (EndOfMibView).")
            break
        
        # Comprobamos si el OID se salió del subárbol.
        if not subtree_oid.isPrefixOf(oid):
            print(f"  [WALK] Fin del subárbol (recibido {oid.prettyPrint()}).")
            break
        
        print(f"  [WALK] {oid.prettyPrint()} = {val.prettyPrint()}")
        current_oid = oid


# Secuencia automática con varias pruebas.
async def run_all_tests():

    print("\n=== TEST 1: GET inicial ===")
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
    await snmp_walk(OIDS['base_subtree'])
    print("--------------------------------\n")


    print("=== TEST 5: CPU dinámico ===")
    print("Leyendo cpuUsage 3 veces (cada ~5s):")
    for _ in range(3):
        await snmp_get(OIDS["cpuUsage"])
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
    print("INICIANDO PRUEBAS DEL AGENTE SNMP\n")

    ip = input("Introduce la IP del agente SNMP (por defecto 127.0.0.1): \n").strip()
    if ip:
        AGENT = (ip, 161)
    else:
        AGENT = ('127.0.0.1', 161)

    opcion = "0"
    while opcion != "3":

        print("Opciones:")
        print("     1. Ejecutar todas las pruebas automáticas.")
        print("     2. Ejecutar pruebas manualmente.")
        print("     3. Salir.\n")
        opcion = input("Opción: ").strip()

        if opcion == "1":
            asyncio.run(run_all_tests())
        elif opcion == "2":
            opcion_manual = "0"
            while opcion_manual != "5":
                print("\nOpciones:")
                print("     1. GET")
                print("     2. GETNEXT")
                print("     3. SET")
                print("     4. WALK")
                print("     5. Volver al menú principal.\n")
                opcion_manual = input("Opción: ").strip()

                if opcion_manual == "1":
                    print("\nPosibles valores de OID:")
                    for name, oid_val in OIDS.items():
                        print(f"  {name}: {oid_val}")
                    nombre = input("\nIntroduce el nombre del OID a leer: ").strip()
                    if nombre not in OIDS:
                        oid = input("OID no encontrado. Introduce el OID directamente: ").strip()
                        print("")
                    else:
                        oid = OIDS.get(nombre, None)
                    try:
                        asyncio.run(snmp_get(oid))
                    except Exception as e:
                        print(f"Error al realizar GET: {e}")

                elif opcion_manual == "2":
                    print("\nPosibles valores de OID:")
                    for name, oid_val in OIDS.items():
                        print(f"  {name}: {oid_val}")
                    nombre = input("\nIntroduce el nombre del OID para GETNEXT: ").strip()
                    if nombre not in OIDS:
                        oid = input("\nOID no encontrado. Introduce el OID directamente: ").strip()
                        print("")
                    else:
                        oid = OIDS.get(nombre, None)
                        print("")

                    try:
                        asyncio.run(snmp_getnext(oid))
                    except Exception as e:
                        print(f"Error al realizar GETNEXT: {e}")
                elif opcion_manual == "3":
                    print("\nPosibles valores de OID:")
                    for name, oid_val in OIDS.items():
                        print(f"  {name}: {oid_val}")
                    nombre = input("\nIntroduce el nombre del OID a cambiar: ").strip()
                    if nombre not in OIDS:
                        oid = input("\nOID no encontrado. Introduce el OID directamente: ").strip()
                        print("")
                    else:
                        oid = OIDS.get(nombre, None)
                        print("")
                    value = input("Introduce el valor a escribir: ").strip()
                    print("")
                    try:
                        value = int(value)
                        try:
                            asyncio.run(snmp_set(oid, value, Integer))
                        except Exception as e:
                            print(f"Error al realizar el SET: {e}")
                    except ValueError:
                        try:
                            asyncio.run(snmp_set(oid, value, OctetString))
                        except Exception as e:
                            print(f"Error al realizar el SET: {e}")
                    
                    
                elif opcion_manual == "4":
                    print("\nPosibles valores de OID:")
                    for name, oid_val in OIDS.items():
                        print(f"  {name}: {oid_val}")
                    nombre = input("\nIntroduce el nombre del OID base para WALK: ").strip()
                    print("")
                    if nombre not in OIDS:
                        oid = input("\nOID no encontrado. Introduce el OID directamente: ").strip()
                        print("")
                    else:
                        oid = OIDS.get(nombre, None)
                        print("")
                    try:
                        asyncio.run(snmp_walk(oid))
                    except Exception as e:
                        print(f"Error al realizar WALK: {e}")
                elif opcion_manual == "5":
                    print("\nVolviendo al menú principal...\n")