# Transfer

Transferencia de ficheros entre amigos por túneles TCP. Cada usuario tiene una cuenta y una app en el system tray; los ficheros pasan por servidores intermediarios que solo ven datos cifrados.

```text
 Cliente A ──TLS──► Servidor de control ◄──TLS── Cliente B
     │              cuentas · amigos · presencia     │
     │              señalización · elige relay       │
     │                                               │
     └──TLS──────►  Relay (uno o varios)  ◄──TLS─────┘
                    empareja y reenvía bytes
          ═══════ cifrado Noise de extremo a extremo ═══════
```

| Crate | Contenido |
| --- | --- |
| `crates/proto` | Protocolo, tickets y TLS compartidos |
| `crates/server` | Binario `transfer-server`: control, relay y base de datos SQLite |
| `crates/client-core` | Motor del cliente: sesión, reconexión, cifrado y transferencias |
| `crates/app` | App de escritorio Tauri 2: tray, ventana y notificaciones |

## Puesta en marcha local

Requiere Rust estable. En Windows también hacen falta las Build Tools de Visual Studio; WebView2 ya viene con Windows 11.

```bash
cargo build --release -p transfer-server -p transfer-app
```

Arranca el servidor en una terminal:

```bash
./target/release/transfer-server all
```

Crea `data/` y muestra la `fingerprint` del certificado autofirmado. Abre `target/release/transfer.exe`, despliega **Servidor**, pega esa huella y crea la cuenta.

Para probar dos clientes en un mismo equipo, lanza el segundo con otros datos. En PowerShell:

```powershell
$env:TRANSFER_DATA_DIR = "$env:TEMP\transfer-b"; $env:WEBVIEW2_USER_DATA_FOLDER = "$env:TEMP\transfer-b\wv"; .\target\release\transfer.exe
```

## Despliegue

### Un solo servidor

Abre los puertos TCP 7443 (control) y 7444 (relay). `--relay-public-addr` es obligatorio: es la dirección que reciben los clientes, y su valor por defecto solo sirve en local.

```bash
TRANSFER_DATA_DIR=/var/lib/transfer transfer-server all --relay-public-addr mi-servidor.com:7444
```

También hay `Dockerfile` y `docker-compose.yml`. Pon la dirección pública en `.env` como `RELAY_PUBLIC_ADDR=mi-servidor.com:7444` y arranca:

```bash
docker compose up -d --build
```

La huella del certificado aparece en los logs y se conserva entre reinicios, igual que las cuentas, en el volumen `transfer-data`:

```bash
docker compose logs transfer
```

### Varios relays

Genera un secreto y úsalo en todos los servidores:

```bash
openssl rand -hex 32
```

En el servidor de control:

```bash
TRANSFER_RELAY_SECRET=<secreto> transfer-server control
```

En cada relay:

```bash
TRANSFER_RELAY_SECRET=<secreto> transfer-server relay --control-addr control.mi-dominio.com:7443 --control-fingerprint <huella> --relay-public-addr relay1.mi-dominio.com:7444
```

Cada relay se registra solo e informa de su carga; el control asigna cada transferencia al menos ocupado.

### Certificado de control

Sin configuración se usa un certificado autofirmado y cada cliente debe pegar su huella. Con uno de Let's Encrypt, los clientes dejan la huella vacía:

```bash
transfer-server all --tls-cert fullchain.pem --tls-key privkey.pem --relay-public-addr mi-servidor.com:7444
```

Los relays siempre usan certificado autofirmado: el control entrega su huella a los clientes.

## Cómo funciona una transferencia

1. El emisor cifra la lista de ficheros para el receptor y la envía como oferta. El servidor no ve nombres ni tamaños.
2. Al aceptar, el control elige un relay y entrega a cada cliente un ticket firmado, válido 60 segundos, de un solo uso y ligado a ese relay.
3. Ambos clientes se conectan al relay, que los empareja y pasa a reenviar bytes.
4. Sobre ese túnel negocian una sesión `Noise_KK` con claves efímeras y sus claves de identidad.
5. Cada fichero se escribe como `.part`, se verifica con BLAKE3 y solo entonces recibe su nombre definitivo.

## Seguridad

- **Contraseñas:** Argon2id, con límite de intentos por IP y por usuario.
- **Sesiones:** en el servidor solo se guarda el hash SHA-256 del token, que caduca tras 30 días sin uso.
- **Claves de amigos:** se fijan la primera vez que se ven. Si cambian, las transferencias se bloquean hasta que el usuario confía en la clave nueva. Para protegerse de un servidor malicioso desde el primer momento, compara la huella por otra vía.
- **Rutas recibidas:** se rechaza `..` y se neutralizan rutas absolutas, flujos alternativos de NTFS y nombres reservados de Windows. Los enlaces simbólicos no se envían.

## Limitaciones conocidas

- Una cuenta tiene un solo dispositivo activo: iniciar sesión en otro desconecta el anterior y cambia la clave.
- Una transferencia interrumpida se reinicia desde cero.
- Ambos usuarios deben estar conectados.
- No hay recuperación de contraseña, verificación de correo ni borrado de cuenta.
- El registro está abierto a cualquiera que alcance el servidor, con un límite por IP.
- Cuota y ancho de banda de los relays no están limitados por usuario.
- En el cliente, la clave de identidad y el token se guardan en la carpeta de datos del usuario sin cifrar. Son accesibles para cualquier programa que se ejecute con esa cuenta.

## Desarrollo

```bash
cargo test --workspace
```

Los tests de `crates/client-core/tests/e2e.rs` levantan servidor y relays reales y conectan clientes por TCP y TLS.

## Instalador de Windows

Hace falta `tauri-cli`:

```bash
cargo install tauri-cli --version "^2" --locked
```

Genera el instalador con un directorio de compilación propio, para que funcione aunque la app de `target/release` esté abierta:

```bash
cd crates/app && CARGO_TARGET_DIR=../../target/installer cargo tauri build
```

El resultado queda en `target/installer/release/bundle/nsis/`. No requiere permisos de administrador: instala para el usuario actual y descarga WebView2 si falta.

El instalador añade la entrada de inicio con Windows y la opción **Enviar con Transfer** al menú contextual de ficheros y carpetas; la desinstalación las elimina. En Windows 11 esa opción aparece bajo **Mostrar más opciones**, porque el menú nuevo solo admite aplicaciones empaquetadas. Si el usuario desactivó el inicio automático en Ajustes, una actualización respeta esa decisión.

## Actualizaciones

El cliente busca una versión nueva 20 segundos después de arrancar y luego cada 6 horas, en `latest.json` de la última release de GitHub. Si la hay, la descarga en segundo plano y comprueba su firma. Después avisa con una notificación, un aviso en la ventana y la opción **Instalar la versión…** del icono de la bandeja. La actualización se instala cuando el usuario lo pide, o al elegir **Salir**. Si hay transferencias en curso, pide confirmación antes de reiniciar. **Buscar actualizaciones** comprueba al momento, desde la bandeja o desde Ajustes.

Las actualizaciones van firmadas con una clave propia, independiente del certificado de Windows. La clave pública está en `tauri.conf.json`. La privada se genera una vez fuera del repositorio:

```bash
cargo tauri signer generate -w "$env:USERPROFILE\.tauri\transfer-updater.key"
```

Guarda una copia de esa clave: si se pierde, los clientes instalados no aceptarán más actualizaciones y habrá que reinstalarlos a mano. Para compilar el instalador hace falta indicarla:

```bash
$env:TAURI_SIGNING_PRIVATE_KEY = "$env:USERPROFILE\.tauri\transfer-updater.key"; $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = ""
```

Para publicar una versión, con todo confirmado en git y la GitHub CLI con la sesión iniciada:

```bash
.\scripts\release.ps1 -Version 0.2.1 -Notes "Qué cambia"
```

El script cambia la versión, compila y firma el instalador y genera `latest.json`. Después hace commit, crea la etiqueta, hace push y publica la release. Los clientes la reciben en su siguiente comprobación.
