import os
import ipaddress
import json
import hashlib
import secrets
import logging

ARCHIVO_DB = "base_datos_red.json"
ARCHIVO_TXT = "Documentacion_Red.txt"
ARCHIVO_USUARIOS = "usuarios_red.json"
ARCHIVO_LOG = "auditoria_red.log"

# --- CONFIGURACIÓN DE SISTEMA DE LOGS (AUDITORÍA ASCII) ---
logging.basicConfig(
    filename=ARCHIVO_LOG,
    level=logging.INFO,
    format='%(asctime)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def registrar_auditoria(usuario, accion, detalle):
    # Se eliminan las tildes de las cabeceras para evitar problemas de encoding
    log_msg = f"USUARIO: [{usuario}] | ACCION: [{accion}] | DETALLE: {detalle}"
    logging.info(log_msg)

# --- Estilos de Terminal ---
ROJO = '\033[91m'
VERDE = '\033[92m'
AZUL = '\033[94m'
AMARILLO = '\033[93m'
RESET = '\033[0m'

class VolverMenu(Exception):
    pass

CATALOGO_EQUIPOS = {
    "1": {"categoria": "Routers", "modelos": ["Cisco 2911", "Cisco 1941", "Cisco 4321", "Router Genérico", "Cisco 829 (Industrial)"]},
    "2": {"categoria": "Switches", "modelos": ["Cisco 2960 (L2)", "Cisco 3560 (L3)", "Cisco 3650", "Switch Genérico"]},
    "3": {"categoria": "Dispositivos Finales", "modelos": ["PC de Escritorio", "Laptop", "Servidor", "Impresora de Red", "Teléfono IP"]},
    "4": {"categoria": "Seguridad (Firewalls)", "modelos": ["Cisco ASA 5505", "Cisco ASA 5506-X"]}
}

SERVICIOS_POR_CATEGORIA = {
    "Routers": ["OSPF", "EIGRP", "BGP", "NAT / PAT", "VPN Site-to-Site", "Dual Stack (IPv4/v6)", "DHCP Server", "HSRP / VRRP", "Túnel GRE"],
    "Switches": ["Enrutamiento Inter-VLAN", "STP / RSTP", "EtherChannel (LACP/PAgP)", "Port Security", "VTP", "DHCP Snooping", "PoE"],
    "Dispositivos Finales": ["Servicio Web (HTTP/HTTPS)", "Servicio DNS", "Servicio DHCP", "Servicio Email", "FTP", "Cliente DHCP", "Ninguno"],
    "Seguridad (Firewalls)": ["Políticas de Acceso (ACL)", "VPN AnyConnect", "Inspección de Paquetes", "NAT Estático"]
}

CAPAS = ["Núcleo (Core)", "Distribución", "Acceso", "Internet / WAN", "Dispositivo Final"]

# =======================================================
# MÓDULO DE SEGURIDAD Y AUTENTICACIÓN
# =======================================================

def hashear_password(password, salt):
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

def cargar_usuarios():
    if os.path.exists(ARCHIVO_USUARIOS):
        with open(ARCHIVO_USUARIOS, "r") as f:
            return json.load(f)
    return {}

def guardar_usuarios(usuarios):
    with open(ARCHIVO_USUARIOS, "w") as f:
        json.dump(usuarios, f, indent=4)

def inicializar_seguridad():
    usuarios = cargar_usuarios()
    
    if not usuarios:
        mostrar_encabezado("CONFIGURACIÓN INICIAL DE SEGURIDAD")
        print(f"{AMARILLO}No existen usuarios. Registre el Administrador maestro.{RESET}")
        user = input("\nNuevo nombre de usuario: ").strip()
        pwd = input("Nueva contraseña: ").strip()
        
        salt = secrets.token_hex(8)
        pwd_hash = hashear_password(pwd, salt)
        
        usuarios[user] = {"salt": salt, "hash": pwd_hash, "rol": "Admin"}
        guardar_usuarios(usuarios)
        print(f"\n{VERDE}[+] Administrador '{user}' creado exitosamente.{RESET}")
        
        # Log sin tildes
        registrar_auditoria("SISTEMA", "INICIALIZACION", f"Se creo el usuario maestro: {user}")
        input("Presione Enter para iniciar sesión...")

    while True:
        mostrar_encabezado("CONTROL DE ACCESO (LOGIN)")
        user = input("Usuario: ").strip()
        pwd = input("Contraseña: ").strip()
        
        usuarios = cargar_usuarios()
        if user in usuarios:
            datos_usuario = usuarios[user]
            hash_intento = hashear_password(pwd, datos_usuario["salt"])
            
            if hash_intento == datos_usuario["hash"]:
                print(f"\n{VERDE}[+] Acceso concedido. Bienvenido, {user}.{RESET}")
                registrar_auditoria(user, "LOGIN", "Inicio de sesion exitoso.")
                input("Presione Enter para continuar...")
                return user
                
        print(f"\n{ROJO}[-] Credenciales inválidas. Intente nuevamente.{RESET}")
        registrar_auditoria("DESCONOCIDO", "ALERTA_SEGURIDAD", f"Intento de login fallido para usuario: {user}")
        input("Presione Enter...")

# --- MÓDULO AMPLIADO: GESTIÓN DE USUARIOS (CREAR Y ELIMINAR) ---
def gestionar_usuarios(usuario_actual):
    while True:
        usuarios = cargar_usuarios()
        
        # Verificación de Rol
        if usuarios.get(usuario_actual, {}).get("rol") != "Admin":
            print(f"{ROJO}[-] Acceso Denegado: Su cuenta no tiene privilegios de Administrador.{RESET}")
            registrar_auditoria(usuario_actual, "ALERTA_PRIVILEGIOS", "Intento de acceso denegado a Gestion de Usuarios.")
            input("\nPresione Enter para volver...")
            return

        mostrar_encabezado("Gestión de Usuarios y Accesos")
        print("1. Aprovisionar nueva cuenta (Crear)")
        print("2. Revocar acceso (Eliminar)")
        print("3. Volver al menú principal")
        
        opc = input("\nIngrese código de operación: ").strip()
        
        if opc == "1":
            print(f"\n{AZUL}Registrando nueva cuenta en el sistema...{RESET}")
            try:
                nuevo_user = input_b("Nombre del nuevo usuario").strip()
                if not nuevo_user:
                    continue
                    
                if nuevo_user in usuarios:
                    print(f"{ROJO}[-] El usuario '{nuevo_user}' ya existe en la base de datos.{RESET}")
                    input("Presione Enter para continuar...")
                    continue

                nueva_pwd = input_b("Asigne una contraseña")
                
                print(f"\n{AZUL}Seleccione el Nivel de Privilegios:{RESET}")
                print("1. Admin (Gestión total)")
                print("2. Operador (Solo gestión de red)")
                opc_rol = input_b("Seleccione rol (1/2)")
                
                rol = "Admin" if opc_rol == "1" else "Operador"
                
                salt = secrets.token_hex(8)
                pwd_hash = hashear_password(nueva_pwd, salt)
                
                usuarios[nuevo_user] = {"salt": salt, "hash": pwd_hash, "rol": rol}
                guardar_usuarios(usuarios)
                
                registrar_auditoria(usuario_actual, "NUEVO_USUARIO", f"Creo la cuenta '{nuevo_user}' con rol '{rol}'")
                print(f"\n{VERDE}[+] Cuenta '{nuevo_user}' ({rol}) aprovisionada correctamente.{RESET}")
            except VolverMenu:
                print(f"\n{ROJO}[!] Operación abortada.{RESET}")
            input("\nPresione Enter para continuar...")

        elif opc == "2":
            print(f"\n{AZUL}Revocación de cuentas en el sistema...{RESET}")
            try:
                lista_usuarios = list(usuarios.keys())
                for i, u in enumerate(lista_usuarios):
                    rol_str = usuarios[u].get('rol', 'Desconocido')
                    print(f"{i + 1}. {u} ({rol_str})")
                
                idx_str = input_b("\nNúmero del usuario a eliminar")
                idx = int(idx_str) - 1
                
                if 0 <= idx < len(lista_usuarios):
                    usuario_a_borrar = lista_usuarios[idx]
                    
                    # Sistema Anti-Lockout: No puedes borrarte a ti mismo
                    if usuario_a_borrar == usuario_actual:
                        print(f"{ROJO}[-] Infracción de Seguridad: No puede revocar su propia sesión activa.{RESET}")
                    else:
                        del usuarios[usuario_a_borrar]
                        guardar_usuarios(usuarios)
                        registrar_auditoria(usuario_actual, "ELIMINAR_USUARIO", f"Revoco el acceso y elimino la cuenta '{usuario_a_borrar}'")
                        print(f"\n{VERDE}[+] Cuenta '{usuario_a_borrar}' eliminada permanentemente.{RESET}")
                else:
                    print(f"{ROJO}[-] Opción fuera de rango.{RESET}")
            except VolverMenu:
                print(f"\n{ROJO}[!] Operación abortada.{RESET}")
            except ValueError:
                print(f"\n{ROJO}[-] Entrada inválida.{RESET}")
            input("\nPresione Enter para continuar...")
            
        elif opc == "3":
            break
        else:
            print(f"{ROJO}Código no reconocido.{RESET}")
            input("Presione Enter...")

# =======================================================
# MÓDULO DE INTERFAZ Y UTILIDADES
# =======================================================

def mostrar_encabezado(titulo):
    os.system("cls" if os.name == "nt" else "clear")
    print(f"{AZUL}===================================================={RESET}")
    print(f"{AZUL}  {titulo.upper()} {RESET}")
    print(f"{AZUL}===================================================={RESET}\n")

def limpiar_pantalla():
    os.system("cls" if os.name == "nt" else "clear")

def cargar_db():
    if os.path.exists(ARCHIVO_DB):
        with open(ARCHIVO_DB, "r") as f:
            return json.load(f)
    return {}

def guardar_db(db):
    with open(ARCHIVO_DB, "w") as f:
        json.dump(db, f, indent=4)

def exportar_txt(db):
    with open(ARCHIVO_TXT, "w", encoding="utf-8") as file:
        file.write("="*60 + "\n")
        file.write("REPORTE DE TOPOLOGÍA E INVENTARIO DE RED\n")
        file.write("="*60 + "\n\n")
        
        if not db:
            file.write("No existen registros en la base de datos.\n")
            return

        for campus, dispositivos in db.items():
            file.write(f"### SUCURSAL / ZONA: {campus.upper()} ###\n")
            file.write("-" * 50 + "\n")
            if not dispositivos:
                file.write("  [Zona sin dispositivos asignados]\n")
            for disp in dispositivos:
                file.write(f"  Categoría       : {disp['categoria']}\n")
                file.write(f"  Modelo/Equipo   : {disp['modelo']} ({disp['nombre']})\n")
                
                file.write("  Interfaces      :\n")
                if not disp['interfaces']:
                    file.write("      - Ninguna registrada\n")
                for intf in disp['interfaces']:
                    file.write(f"      [{intf['puerto']}] IP: {intf['ip']} | Máscara: {intf['mascara']}\n")
                
                file.write(f"  VLAN(s) config. : {disp['vlans']}\n")
                file.write(f"  Servicios       : {', '.join(disp['servicios'])}\n")
                file.write(f"  Capa Jerárquica : {disp['capa']}\n")
                
                if disp.get('notas'):
                    file.write(f"  Notas           : {disp['notas']}\n")
                    
                file.write("  " + "."*48 + "\n")
            file.write("\n")

def input_b(prompt):
    res = input(prompt + " (o 'b' para volver): ").strip()
    if res.lower() == 'b':
        raise VolverMenu()
    return res

def seleccionar_de_lista(lista, titulo):
    print(f"\n{AZUL}{titulo}:{RESET}")
    for i, item in enumerate(lista):
        print(f"{i + 1}. {item}")
    while True:
        try:
            opcion = int(input_b("Seleccione una opción")) - 1
            if 0 <= opcion < len(lista):
                return lista[opcion]
            print(f"{ROJO}[-] Opción fuera de rango.{RESET}")
        except ValueError:
            print(f"{ROJO}[-] Ingrese un número válido.{RESET}")

def seleccionar_servicios_multiples(categoria):
    servicios_disponibles = SERVICIOS_POR_CATEGORIA[categoria]
    print(f"\n{AZUL}Servicios disponibles para {categoria}:{RESET}")
    for i, srv in enumerate(servicios_disponibles):
        print(f"{i + 1}. {srv}")
    
    while True:
        seleccion = input_b("\nElija los servicios por coma (Ej. 1,4,5) o Enter para 'Ninguno'")
        if not seleccion:
            return ["Ninguno"]
        
        servicios_elegidos = []
        valido = True
        for num_str in seleccion.split(','):
            try:
                idx = int(num_str.strip()) - 1
                if 0 <= idx < len(servicios_disponibles):
                    servicios_elegidos.append(servicios_disponibles[idx])
                else:
                    valido = False
            except ValueError:
                valido = False
        
        if valido:
            return servicios_elegidos
        else:
            print(f"{ROJO}[-] Error: Ingrese solo números válidos.{RESET}")

def obtener_ips_usadas(db, equipo_ignorado=None):
    ips = set()
    for dispositivos in db.values():
        for d in dispositivos:
            if d == equipo_ignorado:
                continue
            if 'interfaces' in d:
                for intf in d['interfaces']:
                    ips.add(intf['ip'])
    return ips

def agregar_interfaces(db, equipo_actual=None):
    interfaces = []
    ips_en_uso = obtener_ips_usadas(db, equipo_actual)
    
    print(f"\n{AZUL}--- CONFIGURACIÓN DE INTERFACES ---{RESET}")
    print("Ingrese las interfaces requeridas. Deje el nombre del puerto en blanco para finalizar.")
    while True:
        puerto = input_b("\nNombre del puerto (Ej. G0/0, S0/0/1)")
        if not puerto:
            break
            
        while True:
            ip = input_b(f"Dirección IP para {puerto} (Ej. 192.168.1.1 o DHCP)")
            if ip.upper() == "DHCP":
                break
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_multicast:
                    print(f"{ROJO}[-] IP Reservada. Ingrese una dirección unicast válida.{RESET}")
                    continue
                    
                if ip in ips_en_uso or ip in [i['ip'] for i in interfaces]:
                    print(f"{ROJO}[-] Conflicto de IP: La dirección {ip} ya se encuentra asignada a otro equipo en la topología.{RESET}")
                    continue
                    
                break
            except ValueError:
                print(f"{ROJO}[-] Formato de IP inválido.{RESET}")
                
        mascara = input_b(f"Máscara de subred para {ip} (Ej. /24 o 255.255.255.0)")
        interfaces.append({"puerto": puerto, "ip": ip, "mascara": mascara})
        
        print(f"{VERDE}[+] Interfaz '{puerto}' registrada correctamente.{RESET}")
        
    return interfaces

# =======================================================
# MÓDULO CRUD DE RED
# =======================================================

def anadir_dispositivo(db, usuario):
    if not db:
        mostrar_encabezado("Advertencia del Sistema")
        print(f"{ROJO}[-] La base de datos no contiene sucursales. Registre una zona primero.{RESET}")
        input("\nPresione Enter para continuar...")
        return

    try:
        mostrar_encabezado("Registro de Dispositivo")
        lista_campus = list(db.keys())
        campus_seleccionado = seleccionar_de_lista(lista_campus, "Seleccione la Zona/Sucursal de destino")
        
        mostrar_encabezado(f"Despliegue en Zona: {campus_seleccionado}")
        
        print(f"{AZUL}Categorías de Hardware:{RESET}")
        for clave, datos in CATALOGO_EQUIPOS.items():
            print(f"{clave}. {datos['categoria']}")
        
        while True:
            opc_cat = input_b("\nSeleccione la categoría")
            if opc_cat in CATALOGO_EQUIPOS:
                cat_nombre = CATALOGO_EQUIPOS[opc_cat]["categoria"]
                modelos = CATALOGO_EQUIPOS[opc_cat]["modelos"]
                modelo = seleccionar_de_lista(modelos, f"Modelos disponibles de {cat_nombre}")
                break
            print(f"{ROJO}[-] Opción inválida.{RESET}")

        nombre = input_b(f"\nIngrese el Hostname para el equipo {modelo}")

        interfaces = agregar_interfaces(db)

        vlans = input_b("\nVLANs asignadas (Deje en blanco o indique '0' si no requiere)")
        if not vlans or vlans == "0" or vlans.lower() == "ninguno":
            vlans = "Ninguna / N/A"

        servicios = seleccionar_servicios_multiples(cat_nombre)
        capa = seleccionar_de_lista(CAPAS, "Nivel del Modelo Jerárquico")
        notas = input_b("\nComentarios técnicos adicionales (Opcional)")

        nuevo_equipo = {
            "categoria": cat_nombre,
            "modelo": modelo,
            "nombre": nombre,
            "interfaces": interfaces,
            "vlans": vlans,
            "servicios": servicios,
            "capa": capa,
            "notas": notas
        }
        
        db[campus_seleccionado].append(nuevo_equipo)
        guardar_db(db)
        exportar_txt(db)
        
        registrar_auditoria(usuario, "CREACION", f"Registro equipo '{nombre}' ({modelo}) en zona '{campus_seleccionado}'")
        print(f"\n{VERDE}[+] Equipo '{nombre}' registrado. Base de datos y reporte actualizados.{RESET}")
        
    except VolverMenu:
        print(f"\n{ROJO}[!] Operación abortada por el usuario. No se aplicaron cambios.{RESET}")
    
    input("\nPresione Enter para volver al menú principal...")

def editar_dispositivo(db, usuario):
    if not db:
        mostrar_encabezado("Advertencia del Sistema")
        print(f"{ROJO}[-] La base de datos de infraestructura está vacía.{RESET}")
        input("\nPresione Enter para continuar...")
        return
        
    try:
        mostrar_encabezado("Modificación de Dispositivo")
        lista_campus = list(db.keys())
        campus_sel = seleccionar_de_lista(lista_campus, "Seleccione la Zona/Sucursal")
        
        if not db[campus_sel]:
            print(f"\n{ROJO}[-] No existen equipos desplegados en esta zona.{RESET}")
            input("Presione Enter para continuar...")
            return

        mostrar_encabezado(f"Inventario en: {campus_sel}")
        for i, d in enumerate(db[campus_sel]):
            print(f"{i + 1}. {d['modelo']} ({d['nombre']})")
            
        opc = int(input_b("\nIngrese el ID del equipo a modificar")) - 1
        if 0 <= opc < len(db[campus_sel]):
            disp = db[campus_sel][opc]
            nombre_original = disp['nombre']
            
            print(f"\n{AZUL}Modificando configuración de: {disp['nombre']}{RESET}")
            print("Presione Enter en los campos que desee conservar sin cambios.")
            
            nuevo_nom = input(f"Nuevo Hostname [{disp['nombre']}]: ").strip()
            if nuevo_nom: disp['nombre'] = nuevo_nom
            
            nueva_vlan = input(f"Nuevas VLANs [{disp['vlans']}]: ").strip()
            if nueva_vlan: disp['vlans'] = nueva_vlan
            
            nueva_nota = input(f"Nuevos comentarios [{disp.get('notas', '')}]: ").strip()
            if nueva_nota: disp['notas'] = nueva_nota
            
            ree_intf = input_b("\n¿Requiere reconfigurar las interfaces de red? (s/n)")
            if ree_intf.lower() == 's':
                disp['interfaces'] = agregar_interfaces(db, equipo_actual=disp)
            
            guardar_db(db)
            exportar_txt(db)
            
            registrar_auditoria(usuario, "EDICION", f"Modifico el equipo '{nombre_original}' (Ahora: '{disp['nombre']}') en '{campus_sel}'")
            print(f"\n{VERDE}[+] Configuración de equipo actualizada correctamente.{RESET}")
        else:
            print(f"{ROJO}[-] ID de equipo fuera de rango.{RESET}")
            
    except VolverMenu:
        print(f"\n{ROJO}[!] Modificación abortada.{RESET}")
    except ValueError:
        print(f"\n{ROJO}[-] Entrada de datos inválida.{RESET}")
        
    input("\nPresione Enter para volver al menú principal...")

def eliminar_dispositivo(db, usuario):
    if not db:
        return
        
    try:
        mostrar_encabezado("Baja de Dispositivo")
        lista_campus = list(db.keys())
        campus_sel = seleccionar_de_lista(lista_campus, "Seleccione la Zona/Sucursal")
        
        if not db[campus_sel]:
            print(f"\n{ROJO}[-] No existen equipos desplegados en esta zona.{RESET}")
            input("Presione Enter para continuar...")
            return

        mostrar_encabezado(f"Inventario en: {campus_sel}")
        for i, d in enumerate(db[campus_sel]):
            print(f"{i + 1}. {d['modelo']} ({d['nombre']})")
            
        opc = int(input_b("\nIngrese el ID del equipo a dar de baja")) - 1
        if 0 <= opc < len(db[campus_sel]):
            eliminado = db[campus_sel].pop(opc)
            guardar_db(db)
            exportar_txt(db)
            
            registrar_auditoria(usuario, "ELIMINACION", f"Elimino el equipo '{eliminado['nombre']}' de '{campus_sel}'")
            print(f"\n{VERDE}[+] El equipo '{eliminado['nombre']}' ha sido retirado del inventario.{RESET}")
        else:
            print(f"{ROJO}[-] ID de equipo fuera de rango.{RESET}")
            
    except VolverMenu:
        print(f"\n{ROJO}[!] Operación abortada.{RESET}")
    except ValueError:
        print(f"\n{ROJO}[-] Entrada de datos inválida.{RESET}")
        
    input("\nPresione Enter para volver al menú principal...")

def anadir_campus(db, usuario):
    mostrar_encabezado("Añadir Zona / Sucursal")
    try:
        nuevo_campus = input_b("Identificador de la nueva zona").strip()
        if nuevo_campus and nuevo_campus not in db:
            db[nuevo_campus] = []
            guardar_db(db)
            exportar_txt(db)
            
            registrar_auditoria(usuario, "NUEVA_ZONA", f"Inicializo la zona: '{nuevo_campus.title()}'")
            print(f"\n{VERDE}[+] Zona '{nuevo_campus.title()}' inicializada en la base de datos.{RESET}")
        else:
            print(f"\n{ROJO}[-] Nombre inválido o la zona ya se encuentra registrada.{RESET}")
    except VolverMenu:
        print(f"\n{ROJO}[!] Operación abortada.{RESET}")
    input("\nPresione Enter para continuar...")

def ver_documentacion(usuario):
    mostrar_encabezado("Reporte de Inventario Actual")
    if os.path.exists(ARCHIVO_TXT):
        with open(ARCHIVO_TXT, "r", encoding="utf-8") as f:
            print(f.read())
        registrar_auditoria(usuario, "LECTURA", "Visualizo el reporte de documentacion TXT")
    else:
        print(f"{ROJO}No se encontró el archivo de reporte generado.{RESET}")
    input("\nPresione Enter para volver al menú principal...")


# =======================================================
# EJECUCIÓN PRINCIPAL
# =======================================================
def main():
    usuario_actual = inicializar_seguridad()

    while True:
        db = cargar_db()
        exportar_txt(db)
        
        usuarios = cargar_usuarios()
        rol_actual = usuarios.get(usuario_actual, {}).get("rol", "Desconocido")
        
        mostrar_encabezado(f"SISTEMA DE INFRAESTRUCTURA | USER: {usuario_actual} ({rol_actual})")
        
        print("1. Visualizar Reporte de Inventario")
        print("2. Registrar Nuevo Equipo")
        print("3. Modificar Configuración de Equipo")
        print("4. Dar de Baja un Equipo")
        print("5. Inicializar Nueva Zona / Sucursal")
        print("6. Gestión de Usuarios y Accesos (Solo Admin)")
        print("7. Cerrar Sesión")
        
        opcion = input("\nIngrese código de operación: ").strip()
        
        if opcion == "1":
            ver_documentacion(usuario_actual)
        elif opcion == "2":
            anadir_dispositivo(db, usuario_actual)
        elif opcion == "3":
            editar_dispositivo(db, usuario_actual)
        elif opcion == "4":
            eliminar_dispositivo(db, usuario_actual)
        elif opcion == "5":
            anadir_campus(db, usuario_actual)
        elif opcion == "6":
            gestionar_usuarios(usuario_actual)
        elif opcion == "7":
            limpiar_pantalla()
            registrar_auditoria(usuario_actual, "LOGOUT", "Cierre de sesion seguro.")
            print(f"{VERDE}Cerrando sesión de usuario. Base de datos asegurada.{RESET}")
            break
        else:
            print(f"{ROJO}Código de operación no reconocido.{RESET}")
            input("Presione Enter para continuar...")

if __name__ == "__main__":
    main()