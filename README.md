# security-context-before

Authenticated **remote MCP** proxy in front of [Security Context](https://securitycontext.dev). Same tools as SC. Repo queries take a snapshot `ref` (tag or commit). Responses keep only CVEs and fix fingerprints that already landed **before** that snapshot, so live bugs at the tag are not handed to the agent.

## Endpoint

After Vercel deploy: `https://<project>.vercel.app/api/mcp` (Streamable HTTP).

Auth (required):

```
Authorization: Bearer $PROXY_API_KEY
```

or `x-api-key: $PROXY_API_KEY`.

## Tools

| Tool | Extra vs SC |
|---|---|
| `get_security_context` | required `ref` |
| `create_security_context` | required `ref` |
| `get_vulnerability_leads` | required `ref` |
| `get_vulnerability` | pass-through |
| `search_vulnerabilities` | pass-through |

`ref` is a git tag (`7.0.1`) or commit SHA.

## Filter

1. Resolve `ref` on GitHub (SHA, date, product version / `$wp_version`).
2. Fetch SC JSON for the repo **in parallel** with GitHub and the upstream MCP call.
3. Parse each CVE’s affected/fixed version via Vercel AI Gateway. Cache by CVE id.
4. Keep a CVE only if `snapshotVersion > affectedMax/fixedIn`.
5. Keep a fingerprint only if its fix commit is an ancestor of the snapshot SHA.

Unknown version ranges are **dropped** (no leak).

## Deploy

```bash
cp .env.example .env.local
# set PROXY_API_KEY, AI_GATEWAY_API_KEY, GITHUB_TOKEN
npx vercel
```

Vercel env: `PROXY_API_KEY`, `AI_GATEWAY_API_KEY`, `AI_GATEWAY_MODEL`, `GITHUB_TOKEN`. Optional durable cache: `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN`.

Local:

```bash
pnpm install
pnpm test
pnpm dev
```

MCP inspector: Streamable HTTP → `http://localhost:3210/api/mcp` with the bearer token.

## Vulseek

Point the org MCP server `securitycontext` URL at this `/api/mcp` and send `ref` from the job tag. The upstream SC tools do **not** have `ref`; orch/hunter tool schemas must include it when using this proxy.
