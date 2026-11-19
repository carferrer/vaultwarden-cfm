# Vaultwarden para Home Assistant

Complemento de gestión de contraseñas de código abierto basado en Vaultwarden.

## Descripción

Vaultwarden es una implementación ligera y de código abierto compatible con los clientes de Bitwarden. Permite almacenar información confidencial, como credenciales de sitios web, en una bóveda cifrada y alojada en tu propio servidor.

Puedes acceder mediante la interfaz web, las aplicaciones de escritorio y móvil y las extensiones para navegadores compatibles.

El robo de contraseñas es un riesgo importante. Reutilizar una misma contraseña en varios servicios facilita el acceso no autorizado cuando uno de ellos sufre una filtración. Se recomienda utilizar contraseñas únicas y activar la autenticación de dos factores.

## Restricción opcional del panel de administración

El complemento puede limitar `/admin` y sus subrutas a una lista de direcciones
o redes permitidas. La bóveda, la API y la sincronización siguen accesibles por
el puerto 7277. Se aplica tanto con HTTP como con HTTPS y también si el dominio
de Vaultwarden utiliza un prefijo de ruta.

La opción está **desactivada por defecto** para conservar el acceso de las
instalaciones existentes. Para activarla en la red `192.168.2.0/23`:

```yaml
admin_restriction_enabled: true
admin_allowed_networks:
  - 192.168.2.0/23
```

- `admin_restriction_enabled`: activa o desactiva la restricción por red.
- `admin_allowed_networks`: lista editable de IP individuales o redes CIDR,
  tanto IPv4 como IPv6. Puedes añadir más entradas, por ejemplo la subred real
  de una VPN. No se autorizan automáticamente otras redes privadas ni loopback.
- `192.168.2.0/23` incluye `192.168.2.x` y `192.168.3.x`.
- Con la restricción activa, una lista vacía deniega todo acceso a `/admin`.
  Las direcciones no autorizadas reciben **HTTP 403**, incluido IPv6 si no se
  ha permitido una dirección o red IPv6.
- Las entradas inválidas impiden arrancar Nginx y generan un error en el
  registro; no se interpretan como directivas. Las redes se normalizan, por
  ejemplo `192.168.2.184/23` se convierte en `192.168.2.0/23`.
- Guarda las opciones y **reinicia el complemento** para aplicar los cambios.
  El panel mantiene su contraseña; la lista permitida no evita un bloqueo
  independiente de Fail2ban.

### Comprobación y recuperación

Conserva una sesión local de Home Assistant para poder modificar las opciones.

1. Desde la red permitida, abre el dominio HTTPS habitual con `/admin`:
   debe aparecer el acceso al panel.
2. Desde datos móviles, sin Wi-Fi ni VPN, comprueba que `/admin` y
   `/admin/` devuelven 403, pero que la bóveda permite entrar y sincronizar.
3. Reinicia el complemento y repite ambas comprobaciones.
4. Si necesitas recuperar el acceso, configura
   `admin_restriction_enabled: false` desde Home Assistant y reinicia.
   Esto elimina solamente esta restricción; no retira sanciones de Fail2ban.

La regla utiliza la IP de origen de la conexión a Nginx, no las cabeceras
`X-Real-IP`, `X-Forwarded-For` ni `Forwarded` enviadas por el cliente.
Está prevista para una redirección directa del puerto 7277. Comprueba desde
fuera que el router conserva la IP del cliente: si un NAT, una VPN o un proxy
sustituye el origen por una IP de la red permitida, Nginx no puede distinguir
a los clientes originales. No añadas la IP de un proxy como solución sin
configurar antes la identificación fiable de los clientes.

Si el dominio público no funciona desde la LAN por el NAT de retorno del
router, utiliza DNS local para resolver ese mismo dominio a la IP local de
Home Assistant. Así se conserva la validación del certificado HTTPS.

## Protección opcional con Fail2ban (experimental)

El complemento puede detectar intentos reiterados de inicio de sesión con contraseñas incorrectas en los registros de Vaultwarden y bloquear de forma permanente la IP de origen mediante el Nginx incluido. No necesita conceder `NET_ADMIN` al contenedor de Home Assistant ni modificar el cortafuegos del anfitrión.

**Esta funcionalidad está desactivada por defecto y todavía requiere pruebas antes de utilizarse en producción.**

### Opciones del complemento

```yaml
fail2ban_enabled: false
fail2ban_maxretry: 10
fail2ban_findtime: 600
fail2ban_bantime: -1
```

- `fail2ban_enabled`: activa o desactiva la protección.
- `fail2ban_maxretry`: número máximo de intentos fallidos.
- `fail2ban_findtime`: período de detección, en segundos.
- `fail2ban_bantime`: duración de la sanción, en segundos. El valor `-1` establece bloqueos permanentes, que solo se eliminan con un desbloqueo manual.

La configuración predeterminada prevé **10 intentos fallidos desde una misma IP en 10 minutos**, seguidos de un **bloqueo permanente hasta que se desbloquee manualmente**. El bloqueo afecta a cualquier usuario que comparta esa IP pública. La protección sigue desactivada por defecto mientras no se hayan validado las pruebas.

### Requisitos de red

La configuración prevista utiliza una redirección NAT directa del puerto 7277 hacia el complemento, sin otro proxy inverso.

Nginx obtiene la IP del cliente mediante `$remote_addr`. Si se añade un proxy inverso, deberá configurarse correctamente la identificación de IP reales de proxies de confianza. De lo contrario, podría bloquearse la IP del proxy y afectar a varios usuarios.

### Funcionamiento previsto

Cuando se activa, Vaultwarden escribe los mensajes del nivel de registro configurado (incluidos los errores de autenticación) en `/data/fail2ban/vaultwarden.log`. El filtro de Fail2ban exige el prefijo exacto del registro de autenticación y captura la IP antes del nombre de usuario, para impedir que un nombre manipulado seleccione otra IP.

El servicio S6 de rotación comprueba el registro cada 60 segundos. Al superar 10 MiB, lo rota, conserva tres archivos anteriores y comprime los más antiguos. Envía SIGHUP a Vaultwarden para reabrir el archivo nuevo, con permisos `0600`. El tamaño puede superar el umbral entre comprobaciones; no es una cuota estricta. Los mensajes internos de Fail2ban se envían al registro del contenedor.

Nginx consulta `/data/fail2ban/banned.map` y devuelve una respuesta **HTTP 403** a las IP sancionadas. La fuente de las sanciones es SQLite en `/data/fail2ban/fail2ban.sqlite3`. El mapa se vacía antes de arrancar Nginx y antes de cada arranque de Fail2ban, que restaura desde SQLite únicamente las sanciones vigentes. Esto evita entradas duplicadas y bloqueos caducados tras una parada brusca, incluso si solo se reinicia Fail2ban. Durante la restauración existe un breve intervalo sin los bloqueos HTTP.

Al arrancar, Fail2ban comienza a leer al final del registro: no vuelve a contar errores antiguos que podrían anular un desbloqueo manual después de una parada brusca. Las sanciones vigentes se restauran desde SQLite, pero los intentos escritos mientras Fail2ban está detenido no se contabilizan.

La CI ejecuta pruebas con las imágenes amd64 y aarch64 y datos desechables: filtro, cabeceras, IPv4/IPv6, umbral de diez fallos, HTTP 403, desbloqueo, restauración tras SIGKILL y rotación. Las pruebas no sustituyen la validación de la red pública ni del ciclo completo de Home Assistant.

### Verificaciones obligatorias antes de desplegar

1. Comprobar que la imagen compila para **amd64 y aarch64** y que los servicios arrancan correctamente con S6.
2. Con Fail2ban desactivado, verificar que el acceso HTTPS y el inicio de sesión habitual siguen funcionando.
3. Activar Fail2ban y comprobar que `nginx -t` y `fail2ban-client status vaultwarden-cfm` funcionan correctamente.
4. Desde una **IP de pruebas diferente**, realizar diez accesos deliberadamente incorrectos con una cuenta de prueba en menos de diez minutos. Comprobar el bloqueo mediante `fail2ban-client status vaultwarden-cfm` y la respuesta HTTP 403. Verificar que otra IP no resulte afectada.
5. Desbloquear la IP de prueba con `fail2ban-client set vaultwarden-cfm unbanip IP_DE_PRUEBA` y confirmar que el acceso vuelve a funcionar.
6. Comprobar que reiniciar el complemento y establecer `fail2ban_enabled: false` no provocan bloqueos accidentales. No realizar pruebas desde el único acceso de administración.
7. Verificar la rotación de los registros y su consumo de espacio antes de mantener la funcionalidad activada de forma continua.

### Consulta y desbloqueo manual

Una vez desplegado y verificado, desde una consola que pueda ejecutar comandos **dentro del contenedor del complemento**:

```bash
fail2ban-client status vaultwarden-cfm
fail2ban-client set vaultwarden-cfm unbanip 203.0.113.42
```

Sustituir `203.0.113.42` por la IP real que quieras desbloquear. No editar manualmente `banned.map` ni la base de datos SQLite: el desbloqueo debe actualizar ambos estados a través de Fail2ban.

### Recuperación del acceso

Si se pierde el acceso por un bloqueo, desactivar Fail2ban desde las opciones del complemento y reiniciarlo. Durante la inicialización se vacía el mapa de bloqueo de Nginx, pero **los registros permanentes siguen almacenados en SQLite y pueden volver a aplicarse al reactivar Fail2ban**. Para retirar definitivamente una IP, hay que desbloquearla mediante `fail2ban-client` mientras el servicio esté activo.

Es recomendable conservar una vía alternativa y local de administración de Home Assistant. La sanción permanente puede afectar a varios usuarios que compartan una IP o sufran cambios de IP pública.

### Limitaciones

El bloqueo se realiza en la **capa HTTP** mediante una respuesta 403; **no** equivale a bloquear el tráfico TCP en el cortafuegos del router.

El filtro previsto cubre únicamente los mensajes documentados de contraseñas incorrectas. Los errores de acceso al panel de administración, TOTP, otros problemas de autenticación y sondeos HTTP requerirían filtros adicionales.

Fail2ban es una medida complementaria: deben mantenerse una contraseña maestra robusta y la autenticación de dos factores.
