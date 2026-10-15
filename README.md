# Ghost X

Requires Go 1.26 and Node.js 24.5+.

## Server

```sh
cd server
go run .
```

WebSocket endpoint: `/ws`

| Variable | Default |
| --- | --- |
| `SERVER_ADDR` | `:8080` |
| `SHUTDOWN_TIMEOUT` | `10s` |
| `AUTH_TIMEOUT` | `60s`; a positive duration such as `30s`, after which a connection that has not authenticated is closed |
| `ALLOWED_ORIGINS` | same host only |
| `DEVICE_STORE` | `ghostx/devices.json` in the user config directory |
| `LOCAL_SOCKET` | unset; an absolute path enables the local stream carrier on a Unix socket |

## Web

```sh
cd web
npm ci
NEXT_PUBLIC_SOCKET_URL=ws://localhost:8080/ws npm run dev
```

Run the server with `ALLOWED_ORIGINS=http://localhost:3000`.
