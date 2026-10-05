# Ghost X

Requires Go 1.26 and Node.js 20.9+.

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
| `ALLOWED_ORIGINS` | same host only |

## Web

```sh
cd web
npm ci
NEXT_PUBLIC_SOCKET_URL=ws://localhost:8080/ws npm run dev
```

Run the server with `ALLOWED_ORIGINS=http://localhost:3000`.
