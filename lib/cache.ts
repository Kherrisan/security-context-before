import type { CveParse } from "./types";

const PARSER_VERSION = "v1";
const memory = new Map<string, CveParse>();

const upstash = () => {
	const url = process.env.UPSTASH_REDIS_REST_URL?.replace(/\/$/, "");
	const token = process.env.UPSTASH_REDIS_REST_TOKEN;
	if (!url || !token) return null;
	return { url, token };
};

export const cacheKey = (cveId: string) =>
	`${PARSER_VERSION}:${cveId.trim().toUpperCase()}`;

const upstashCommand = async (args: unknown[]) => {
	const cfg = upstash();
	if (!cfg) return null;
	const res = await fetch(`${cfg.url}`, {
		method: "POST",
		headers: {
			authorization: `Bearer ${cfg.token}`,
			"content-type": "application/json",
		},
		body: JSON.stringify(args),
	});
	if (!res.ok) return null;
	const body = (await res.json()) as { result?: unknown };
	return body.result ?? null;
};

export const getCachedParse = async (cveId: string): Promise<CveParse | null> => {
	const key = cacheKey(cveId);
	const local = memory.get(key);
	if (local) return local;
	const raw = await upstashCommand(["GET", key]);
	if (typeof raw !== "string") return null;
	try {
		const value = JSON.parse(raw) as CveParse;
		memory.set(key, value);
		return value;
	} catch {
		return null;
	}
};

export const setCachedParse = async (parsed: CveParse) => {
	const key = cacheKey(parsed.cveId);
	memory.set(key, parsed);
	await upstashCommand(["SET", key, JSON.stringify(parsed)]);
};

export const parserVersion = PARSER_VERSION;
