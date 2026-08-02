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

Para rollback, detener timer, después worker y finalmente API; conservar DB y
backups. `systemd-analyze verify` sobre las cuatro units es el smoke estático
recomendado cuando systemd está disponible.

El scheduler solo crea una intención. `role-radar run create --reason
scheduled` deriva el slot UTC más reciente; la key hasheada hace idempotente
una repetición del timer.
