1. ARQUITECTURA ESCALABLE (Soporte Multi-Campus)
   - El sistema permite registrar múltiples "Zonas" o "Sucursales"
   - Los dispositivos se agrupan lógicamente por sede.

2. GESTIÓN AVANZADA DE DISPOSITIVOS (CRUD Multi-Interfaz)
   - Creación, Lectura, Actualización y Borrado de equipos.
   - Soporte para configurar múltiples interfaces (LAN, WAN, Loopback) en 
     un solo dispositivo, incluyendo asignación de IP y Máscara de Subred.
   - Catálogo integrado con equipos reales de infraestructura (Cisco 2911, 
     Switches L2/L3, Firewalls ASA, Servidores, etc.).

3. SISTEMA DE AUTENTICACIÓN Y ROLES (RBAC)
   - Login de seguridad obligatorio al iniciar la aplicación.
   - Criptografía robusta: Las contraseñas se almacenan mediante hashing 
     SHA-256 más un "Salt" criptográfico aleatorio, garantizando que nunca 
     se guarden en texto plano.
   - Control de Acceso Basado en Roles (RBAC):
     * Administrador: Acceso total al sistema y gestión de cuentas.
     * Operador: Acceso limitado solo a la gestión de red.

4. SISTEMA DE AUDITORÍA (Logs)
   - El sistema genera un archivo inmutable (`auditoria_red.log`).
   - Registra cada acción realizada (Crear, Editar, Eliminar, Login, Logout), 
     marcando la fecha exacta, el nombre del usuario y el detalle técnico de 
     la operación.

5. PREVENCIÓN DE ERRORES Y VALIDACIONES DE RED
   - Validación Estricta de IP: Rechaza formatos incorrectos de IPv4/IPv6.
   - Prevención de IPs Reservadas: Bloquea automáticamente el ingreso de IPs 
     de Loopback, Multicast o direcciones no asignables a host.
   - Control de Duplicidad: Escanea el segmento del area en la tabla de datos para evitar colisiones 
     de IP en la topología.

6. USABILIDAD Y EXPERIENCIA DE USUARIO (UX/UI)
   - Interfaz de terminal enriquecida con códigos de color ANSI (Verde para 
     éxitos, Rojo para alertas, Azul para navegación).
   - Función "Hot-Swap": La base de datos y los reportes se actualizan y 
     refrescan en tiempo real en cada ciclo del menú.
   - Botón de Aborto Seguro: Posibilidad de escribir "b" en cualquier momento 
     para cancelar una operación en curso sin corromper la base de datos.

7. EXPORTACIÓN AUTOMATIZADA DE DOCUMENTACIÓN
   - Genera automáticamente un reporte llamado 
     `Documentacion_Red.txt` que tabula todo el inventario agrupado por campus,
     listo para ser entregado en auditorías o evaluaciones.
