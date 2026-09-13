export const unauthorized = () =>
	new Response("Unauthorized", {
		status: 401,
		headers: { "www-authenticate": 'Bearer realm="security-context-before"' },
	});

export const isAuthorized = (req: Request) => {
	const expected = process.env.PROXY_API_KEY?.trim();
	if (!expected) return false;
	const header = req.headers.get("authorization") ?? "";
	const bearer = header.match(/^Bearer\s+(.+)$/i)?.[1]?.trim();
	const apiKey = req.headers.get("x-api-key")?.trim();
	return bearer === expected || apiKey === expected;
};
