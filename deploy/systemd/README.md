# systemd

Las units son plantillas deliberadas: sustituir `ROLE_RADAR_USER`,
`/ROLE_RADAR_APP_DIR` y el `EnvironmentFile` por rutas de la instalación. No
contienen secretos ni ejecutan migraciones al arrancar.

## Modelo de despliegue F8.8.1

- `/home/jmse/labs/role-radar`: copia de desarrollo y Git.
- `/opt/role-radar`: copia runtime que usa systemd; desplegar desde un commit
  dedicado y no copiar `.git`, `.venv`, `.env`, `.codegraph` ni `data/`.
- `/etc/role-radar`: configuración y credenciales administradas por root.
- `/opt/role-radar/data/role-radar.db`: DB runtime; nunca sincronizar, borrar,
  reemplazar ni cambiar ownership recursivamente durante un deploy.

La API de RoleRadar escucha en el puerto operativo configurado por
`ROLE_RADAR_API_PORT` en `/etc/role-radar/role-radar.env`. El ejemplo usa `8010`.
La variable es obligatoria y debe ser un entero entre `1` y `65535`; uvicorn
rechaza valores ausentes, no numéricos o fuera de rango antes de servir tráfico.
El puerto `8000` pertenece a otra aplicación y no debe detenerse, recargarse ni
modificarse durante el despliegue de RoleRadar.

Un deploy reproducible debe copiar solo código/fixtures desde el commit
seleccionado, recrear o sincronizar el `.venv` en `/opt/role-radar`, conservar
la DB existente como `role-radar:role-radar 0600`, instalar las units, ejecutar
`systemd-analyze verify`, `daemon-reload` y registrar el commit desplegado.

```bash
sudo install -d /etc/role-radar
sudo install -m 0600 role-radar.env /etc/role-radar/role-radar.env
# Install acquisition.toml.example as root:role-radar 0640.
# For the initial Gmail-only smoke, create these root-owned 0600 source files
# under /etc/role-radar/credentials/ and put one value in each: gmail-username,
# gmail-app-password, mailbox-message-hmac and mailbox-content-hmac. Never
# commit or paste them.
# Install only target capability credentials as root-owned 0600 source files.
# editar las cuatro units y copiarlas a /etc/systemd/system/
uv run alembic upgrade head             # paso separado
sudo systemctl daemon-reload
sudo systemctl enable --now role-radar-api.service role-radar-worker.service
sudo systemctl enable --now role-radar-scheduler.timer
curl -f http://127.0.0.1:8010/health
sudo journalctl -u role-radar-worker.service -f
```

Antes de cualquier escritura de perfil, verificar la identidad de RoleRadar (no
basta con recibir HTTP 200): `/health` debe devolver exactamente `status`,
`version` y `environment`, y `/openapi.json` debe incluir `/profiles`, `/jobs`,
`/runs` y `/sources`. Un mismatch bloquea el write.

Para Telegram, configurar `ROLE_RADAR_TELEGRAM_PROVIDER=http`,
`ROLE_RADAR_TELEGRAM_BOT_TOKEN` y `ROLE_RADAR_TELEGRAM_CHAT_ID` únicamente en el
EnvironmentFile con permisos 0600. El provider por defecto es `disabled`; fake
solo sirve para pruebas. Los estados `unknown` no se reenvían automáticamente.

La adquisición Brave/Tavily solo se compone dentro del worker programado. Las
credenciales se inyectan mediante drop-ins `LoadCredential` mínimos y separados;
API y scheduler no las cargan. Paid Brave permanece
deshabilitado por defecto y Tavily paid no existe.

Jobicy LATAM es una fuente gratuita fija y nace deshabilitada. Su activación
requiere un bundle externo inmutable de dos páginas y su `terms_sha256` en
`acquisition.toml` (`reviewed_at`, `policy_version` y los tres acknowledgements de fair use,
destino original y no redistribución). El worker no acepta URL, host, path,
query ni headers desde ese archivo y nunca hace más de una consulta por hora.
Los valores reales de aceptación son artefactos locales del homelab; el ejemplo
solo contiene placeholders.

F8.7 Gmail usa únicamente IMAP TLS implícito en `imap.gmail.com:993`, la label
exacta `RoleRadar`, `SELECT` read-only y `BODY.PEEK`. El perfil inicial usa app
password desde `LoadCredential`; XOAUTH2 queda para una activación posterior.
La app password requiere 2FA y acknowledgement explícito del operador. El API y scheduler no reciben
estos mounts. Crear la label es responsabilidad del operador: RoleRadar no
ejecuta CREATE/RENAME/DELETE ni hace fallback a INBOX/All Mail.

Los comandos locales son `role-radar mailbox status <source>`, `preflight`,
`smoke` y `reconcile` (este último exige CAS, `--strategy bounded-lookback` y
ack explícito). `mailbox smoke` requiere `--ack-live`, toma como máximo el
mensaje más reciente de los últimos 14 días, usa `BODY.PEEK`, no persiste nada,
no habilita la source y devuelve solo códigos/counters sanitizados. Para el
resto de Gate B, `role-radar acquisition gate-b --ack-live --confirmation
"LIVE GATE-B"` ejecuta Jobicy, Brave Free y Tavily Free secuencialmente, con una
llamada por capability, sin persistencia y con stop-on-failure. Paid Brave y
las sources de DB permanecen deshabilitadas. No hay endpoint ni trigger HTTP
para estos smokes.

Para rollback, detener timer, después worker y finalmente API; conservar DB y
backups. `systemd-analyze verify` sobre las cuatro units es el smoke estático
recomendado cuando systemd está disponible.

El scheduler solo crea una intención. `role-radar run create --reason
scheduled` deriva el slot diario en `America/Argentina/Buenos_Aires`; la key
hasheada hace idempotente una repetición del timer.
