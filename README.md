# Vaultwarden para Home Assistant

Complemento de gestión de contraseñas de código abierto basado en Vaultwarden.

## Descripción

Vaultwarden es una implementación ligera y de código abierto compatible con los clientes de Bitwarden. Permite almacenar información confidencial, como credenciales de sitios web, en una bóveda cifrada y alojada en tu propio servidor.

Puedes acceder mediante la interfaz web, las aplicaciones de escritorio y móvil y las extensiones para navegadores compatibles.

El robo de contraseñas es un riesgo importante. Reutilizar una misma contraseña en varios servicios facilita el acceso no autorizado cuando uno de ellos sufre una filtración. Se recomienda utilizar contraseñas únicas y activar la autenticación de dos factores.

## Protección opcional con Fail2ban (experimental)

El complemento puede detectar intentos reiterados de inicio de sesión con contraseñas incorrectas en los registros de Vaultwarden y bloquear temporalmente la IP de origen mediante el Nginx incluido. No necesita conceder `NET_ADMIN` al contenedor de Home Assistant ni modificar el cortafuegos del anfitrión.

**Esta funcionalidad está desactivada por defecto y todavía requiere pruebas antes de utilizarse en producción.**

### Opciones del complemento

```yaml
fail2ban_enabled: false
fail2ban_maxretry: 5
fail2ban_findtime: 600
fail2ban_bantime: 3600
```

- `fail2ban_enabled`: activa o desactiva la protección.
- `fail2ban_maxretry`: número máximo de intentos fallidos.
- `fail2ban_findtime`: período de detección, en segundos.
- `fail2ban_bantime`: duración de la sanción, en segundos.

La configuración predeterminada prevé **5 intentos fallidos en 10 minutos**, seguidos de **1 hora de bloqueo**.

### Requisitos de red

La configuración prevista utiliza una redirección NAT directa del puerto 7277 hacia el complemento, sin otro proxy inverso.

Nginx obtiene la IP del cliente mediante `$remote_addr`. Si se añade un proxy inverso, deberá configurarse correctamente la identificación de IP reales de proxies de confianza. De lo contrario, podría bloquearse la IP del proxy y afectar a varios usuarios.

### Funcionamiento previsto

Cuando se activa, Vaultwarden escribe los errores de autenticación en `/data/fail2ban/vaultwarden.log`. Fail2ban examina ese registro mediante su filtro y mantiene las IP sancionadas en `/data/fail2ban/banned.map`.

Nginx consulta la lista de bloqueo y devuelve una respuesta **HTTP 403** a las IP sancionadas. La base de datos de estado de Fail2ban se almacena en `/data/fail2ban`.

### Verificaciones obligatorias antes de desplegar

1. Comprobar que la imagen compila para **amd64 y aarch64** y que los servicios arrancan correctamente con S6.
2. Con Fail2ban desactivado, verificar que el acceso HTTPS y el inicio de sesión habitual siguen funcionando.
3. Activar Fail2ban y comprobar que `nginx -t` y `fail2ban-client status vaultwarden-cfm` funcionan correctamente.
4. Desde una **IP de pruebas diferente**, realizar cinco accesos deliberadamente incorrectos con una cuenta de prueba en menos de diez minutos. Comprobar el bloqueo mediante `fail2ban-client status vaultwarden-cfm` y la respuesta HTTP 403. Verificar que otra IP no resulte afectada.
5. Desbloquear la IP de prueba con `fail2ban-client set vaultwarden-cfm unbanip IP_DE_PRUEBA` y confirmar que el acceso vuelve a funcionar.
6. Comprobar que reiniciar el complemento y establecer `fail2ban_enabled: false` no provocan bloqueos accidentales. No realizar pruebas desde el único acceso de administración.
7. Verificar la rotación de los registros y su consumo de espacio antes de mantener la funcionalidad activada de forma continua.

### Recuperación del acceso

Si se pierde el acceso por un bloqueo, desactivar Fail2ban desde las opciones del complemento y reiniciarlo. Durante la inicialización se vacía el mapa de bloqueo de Nginx. Es recomendable conservar un acceso de administración local a Home Assistant.

### Limitaciones

El bloqueo se realiza en la **capa HTTP** mediante una respuesta 403; **no** equivale a bloquear el tráfico TCP en el cortafuegos del router.

El filtro previsto cubre únicamente los mensajes documentados de contraseñas incorrectas. Los errores de acceso al panel de administración, TOTP, otros problemas de autenticación y sondeos HTTP requerirían filtros adicionales.

Fail2ban es una medida complementaria: deben mantenerse una contraseña maestra robusta y la autenticación de dos factores.
