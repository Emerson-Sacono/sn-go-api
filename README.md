# sn-go-api

API em Go para evolução gradual da plataforma, sem migrar produção de uma vez.

## Objetivo

- Subir uma API Go em paralelo ao backend atual (Node).
- Implementar endpoints por etapas.
- Fazer cutover apenas quando a paridade estiver validada.

## Requisitos

- Go 1.25+

## Rodar local

1. Copie `env.sample` para `.env`.
2. Exporte variáveis (ou use seu gerenciador de env).
3. Rode:

```bash
go run ./cmd/api
```

Endpoint de saúde:

- `GET /health`
- `GET /api/health`

## Estrutura inicial

- `cmd/api/main.go`: bootstrap + graceful shutdown.
- `internal/config`: leitura/validação de env.
- `internal/server`: router e middlewares.
- `internal/handlers`: handlers HTTP (health e stubs).

## Nota sobre CORS

Esta base já bloqueia wildcard `*` para evitar erro com `credentials: include`.
Use sempre lista explícita em `CORS_ALLOWED_ORIGINS`.

