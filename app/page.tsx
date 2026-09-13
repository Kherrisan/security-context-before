export default function Page() {
	return (
		<main style={{ fontFamily: "system-ui", padding: 24, maxWidth: 720 }}>
			<h1>security-context-before</h1>
			<p>
				Authenticated remote MCP proxy for{" "}
				<a href="https://securitycontext.dev">Security Context</a>. Repo tools
				require a snapshot <code>ref</code> (tag or commit). CVEs that still
				affect that snapshot are dropped.
			</p>
			<p>
				Endpoint: <code>/api/mcp</code> (Streamable HTTP). Send{" "}
				<code>Authorization: Bearer $PROXY_API_KEY</code>.
			</p>
		</main>
	);
}
