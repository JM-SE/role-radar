# systemd

Las units son plantillas deliberadas: sustituir `ROLE_RADAR_USER`,
`/ROLE_RADAR_APP_DIR` y el `EnvironmentFile` por rutas de la instalación. No
contienen secretos ni ejecutan migraciones al arrancar.

```bash
sudo install -d /etc/role-radar
sudo install -m 0600 role-radar.env /etc/role-radar/role-radar.env
# Install acquisition.toml.example as acquisition.toml with owner root/mode 0600.
# Place the three worker-only credentials under /etc/role-radar/credentials/0600.
# editar las cuatro units y copiarlas a /etc/systemd/system/
uv run alembic upgrade head             # paso separado
sudo systemctl daemon-reload
sudo systemctl enable --now role-radar-api.service role-radar-worker.service
sudo systemctl enable --now role-radar-scheduler.timer
curl -f http://127.0.0.1:8000/health
sudo journalctl -u role-radar-worker.service -f
```

Para Telegram, configurar `ROLE_RADAR_TELEGRAM_PROVIDER=http`,
`ROLE_RADAR_TELEGRAM_BOT_TOKEN` y `ROLE_RADAR_TELEGRAM_CHAT_ID` únicamente en el
EnvironmentFile con permisos 0600. El provider por defecto es `disabled`; fake
solo sirve para pruebas. Los estados `unknown` no se reenvían automáticamente.

La adquisición Brave/Tavily solo se compone dentro del worker programado. Las
credenciales `brave_api_key`, `tavily_api_key` y `query_hmac_key` se inyectan
mediante `LoadCredential`; API y scheduler no las cargan. Paid Brave permanece
deshabilitado por defecto y Tavily paid no existe.

Jobicy LATAM es una fuente gratuita fija y nace deshabilitada. Su activación
requiere una aceptación externa vigente en `acquisition.toml` (`terms_url`,
`reviewed_at`, `policy_version` y los tres acknowledgements de fair use,
destino original y no redistribución). El worker no acepta URL, host, path,
query ni headers desde ese archivo y nunca hace más de una consulta por hora.
Los valores reales de aceptación son artefactos locales del homelab; el ejemplo
solo contiene placeholders.

Para rollback, detener timer, después worker y finalmente API; conservar DB y
backups. `systemd-analyze verify` sobre las cuatro units es el smoke estático
recomendado cuando systemd está disponible.

El scheduler solo crea una intención. `role-radar run create --reason
scheduled` deriva el slot diario en `America/Argentina/Buenos_Aires`; la key
hasheada hace idempotente una repetición del timer.
