import type { SecurityContextJson, VariantLead } from "./types";

const mcpUrl = () =>
	process.env.SECURITYCONTEXT_MCP_URL || "https://securitycontext.dev/mcp";

const jsonBase = () =>
	process.env.SECURITYCONTEXT_JSON_BASE || "https://securitycontext.dev/r";

type JsonRpcResult = {
	jsonrpc?: string;
	id?: unknown;
	result?: { content?: Array<{ type?: string; text?: string }> };
	error?: { message?: string; code?: number };
};

const parseSseOrJson = async (res: Response): Promise<JsonRpcResult> => {
	const ctype = res.headers.get("content-type") || "";
	const text = await res.text();
	if (ctype.includes("text/event-stream")) {
		const lines = text.split("\n");
		let last: JsonRpcResult | null = null;
		for (const line of lines) {
			if (!line.startsWith("data:")) continue;
			const payload = line.slice(5).trim();
			if (!payload || payload === "[DONE]") continue;
			try {
				last = JSON.parse(payload) as JsonRpcResult;
			} catch {
				// skip malformed event
			}
		}
		if (!last) throw new Error("empty SSE from Security Context");
		return last;
	}
	return JSON.parse(text) as JsonRpcResult;
};

export const callSecurityContextTool = async (
	name: string,
	args: Record<string, unknown>,
) => {
	const initRes = await fetch(mcpUrl(), {
		method: "POST",
		headers: {
			accept: "application/json, text/event-stream",
			"content-type": "application/json",
		},
		body: JSON.stringify({
			jsonrpc: "2.0",
			id: 1,
			method: "initialize",
			params: {
				protocolVersion: "2024-11-05",
				capabilities: {},
				clientInfo: { name: "security-context-before", version: "0.1.0" },
			},
		}),
	});
	if (!initRes.ok) {
		throw new Error(`SC initialize ${initRes.status}: ${(await initRes.text()).slice(0, 300)}`);
	}
	const session = initRes.headers.get("mcp-session-id");
	await parseSseOrJson(initRes);
	const headers: Record<string, string> = {
		accept: "application/json, text/event-stream",
		"content-type": "application/json",
	};
	if (session) headers["mcp-session-id"] = session;

	await fetch(mcpUrl(), {
		method: "POST",
		headers,
		body: JSON.stringify({
			jsonrpc: "2.0",
			method: "notifications/initialized",
		}),
	}).catch(() => undefined);

	const callRes = await fetch(mcpUrl(), {
		method: "POST",
		headers,
		body: JSON.stringify({
			jsonrpc: "2.0",
			id: 2,
			method: "tools/call",
			params: { name, arguments: args },
		}),
	});
	if (!callRes.ok) {
		throw new Error(`SC tools/call ${callRes.status}: ${(await callRes.text()).slice(0, 300)}`);
	}
	const rpc = await parseSseOrJson(callRes);
	if (rpc.error) {
		throw new Error(rpc.error.message || "Security Context tool error");
	}
	const text = (rpc.result?.content ?? [])
		.filter((block) => block.type === "text" && block.text)
		.map((block) => block.text)
		.join("\n\n");
	return text;
};

export const fetchContextJson = async (owner: string, repo: string) => {
	const url = `${jsonBase()}/${owner}/${repo}.json`;
	const res = await fetch(url, { headers: { accept: "application/json" } });
	if (!res.ok) {
		throw new Error(`SC json ${res.status} ${url}`);
	}
	return (await res.json()) as SecurityContextJson;
};

export const fetchLeadsJson = async (owner: string, repo: string) => {
	const url = `${jsonBase()}/${owner}/${repo}.leads.json`;
	const res = await fetch(url, { headers: { accept: "application/json" } });
	if (!res.ok) return [] as VariantLead[];
	const body = await res.json();
	if (Array.isArray(body)) return body as VariantLead[];
	if (Array.isArray(body?.leads)) return body.leads as VariantLead[];
	return [];
};

export const mcpTextResult = (text: string) => ({
	content: [{ type: "text" as const, text }],
});
