# Ghost X

Requires Go 1.26.

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
