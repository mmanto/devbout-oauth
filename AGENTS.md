# AGENTS.md — devbout-oauth

**Fuente de verdad:** [`devbout-docs`](/home/mmanto/workspace/devbout-docs/).

Antes de trabajar en **este** proyecto, el agente debe leer:
1. `/home/mmanto/workspace/devbout-docs/AGENTS.md` — reglas globales, stack y convenciones.
2. El/los doc(s) relevantes de `devbout-docs/docs/` según el tipo de cambio (mapa abajo).

> Si este archivo u otro `AGENTS.md` de proyecto contradice a `devbout-docs`, **prevalece `devbout-docs`**.

## Mapa de cambios → documentación (devbout-docs)

| Tipo de cambio | Actualizar |
|---|---|
| Endpoint / contrato de API | `docs/dev/API.md` |
| Modelo de datos / migración Alembic | `docs/dev/DATA_MODEL.md` |
| Pantalla / ruta / flujo de usuario | `docs/design/SCREENS.md` |
| Componentes / design tokens | `docs/design/DESIGN.md` |
| Infraestructura / Nginx / Docker | `docs/ops/INFRASTRUCTURE.md` |
| Deploy / CI/CD | `docs/ops/DEPLOYMENT.md` |
| Decisión técnica (ADR) | `docs/dev/DECISIONS.md` |
| Feature / bug / breaking change | `CHANGELOG.md` |
| Variable de entorno | `ENV.md` |
| Setup / dependencias | `docs/dev/SETUP.md` |

## Código (grafo zero-tokens)

Para consultar el código usa el **CLI nativo** de codebase-memory (menos tokens):

```bash
codebase-memory-mcp cli search_graph '{"query":"...","project":"home-mmanto-workspace"}'
codebase-memory-mcp cli trace_path '{"function_name":"...","direction":"inbound","project":"home-mmanto-workspace"}'
codebase-memory-mcp cli query_graph '{"query":"MATCH (n:Function) ...","project":"home-mmanto-workspace"}'
codebase-memory-mcp cli get_code_snippet '{"qualified_name":"...","project":"home-mmanto-workspace"}'
```

**Nunca** llames `index_repository`: el índice se mantiene fresco automáticamente con `cb-watch` + git hooks.

## Regla final

**Nunca cierres una tarea sin verificar si un documento de `devbout-docs/docs/` debe actualizarse.**
