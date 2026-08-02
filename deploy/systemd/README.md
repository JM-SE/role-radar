# systemd

Las units son plantillas deliberadas: sustituir `ROLE_RADAR_USER`,
`/ROLE_RADAR_APP_DIR` y el `EnvironmentFile` por rutas de la instalación. No
contienen secretos ni ejecutan migraciones al arrancar.

```bash
sudo install -d /etc/role-radar
sudo install -m 0600 role-radar.env /etc/role-radar/role-radar.env
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

Para rollback, detener timer, después worker y finalmente API; conservar DB y
backups. `systemd-analyze verify` sobre las cuatro units es el smoke estático
recomendado cuando systemd está disponible.

El scheduler solo crea una intención. `role-radar run create --reason
scheduled` deriva el slot diario en `America/Argentina/Buenos_Aires`; la key
hasheada hace idempotente una repetición del timer.
