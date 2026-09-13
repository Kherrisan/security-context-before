import { createMcpHandler } from "mcp-handler";
import { z } from "zod";
import { isAuthorized, unauthorized } from "@/lib/auth";
import { parseRepo } from "@/lib/github";
import { filteredLeads, filteredSecurityContext } from "@/lib/pipeline";
import { callSecurityContextTool, mcpTextResult } from "@/lib/sc-client";

export const maxDuration = 60;

const repoProps = {
	repo: z.string().min(1).describe("GitHub repo as owner/name"),
	ref: z
		.string()
		.min(1)
		.describe("Snapshot commit SHA or tag (e.g. 7.0.1 or abcdef0)"),
};

const handler = createMcpHandler(
	(server) => {
		server.registerTool(
			"get_security_context",
			{
				description:
					"Security context for a GitHub repo at a snapshot ref. Same as Security Context, but CVEs/fixes that still affect this snapshot are removed.",
				inputSchema: {
					...repoProps,
					wait: z.number().int().min(0).max(60).optional(),
				},
			},
			async ({ repo, ref, wait }) => {
				if (wait) {
					await callSecurityContextTool("get_security_context", {
						repo,
						wait,
					}).catch(() => "");
				}
				return mcpTextResult(await filteredSecurityContext(repo, ref));
			},
		);

		server.registerTool(
			"create_security_context",
			{
				description:
					"Build or refresh Security Context for a repo, then filter to a snapshot ref.",
				inputSchema: {
					...repoProps,
					wait: z.number().int().min(0).max(60).optional(),
				},
			},
			async ({ repo, ref, wait }) => {
				const { owner, repo: name } = parseRepo(repo);
				await callSecurityContextTool("create_security_context", {
					repo: `${owner}/${name}`,
					...(wait != null ? { wait } : { wait: 60 }),
				}).catch(() => "");
				return mcpTextResult(await filteredSecurityContext(repo, ref));
			},
		);

		server.registerTool(
			"get_vulnerability_leads",
			{
				description:
					"Variant leads for a repo, filtered so only leads whose fix is already in the snapshot remain.",
				inputSchema: {
					...repoProps,
					severity: z.string().optional(),
					limit: z.number().int().optional(),
				},
			},
			async ({ repo, ref }) => mcpTextResult(await filteredLeads(repo, ref)),
		);

		server.registerTool(
			"get_vulnerability",
			{
				description:
					"Fetch one CVE or Nuclei template by id (pass-through to Security Context).",
				inputSchema: { id: z.string().min(1) },
			},
			async ({ id }) =>
				mcpTextResult(await callSecurityContextTool("get_vulnerability", { id })),
		);

		server.registerTool(
			"search_vulnerabilities",
			{
				description:
					"Search the vulnerability database (pass-through to Security Context).",
				inputSchema: {
					query: z.string().min(1),
					limit: z.number().int().optional(),
				},
			},
			async ({ query, limit }) =>
				mcpTextResult(
					await callSecurityContextTool("search_vulnerabilities", {
						query,
						...(limit != null ? { limit } : {}),
					}),
				),
		);
	},
	{
		serverInfo: {
			name: "security-context-before",
			version: "0.1.0",
		},
	},
	{
		basePath: "/api",
		maxDuration: 60,
		disableSse: true,
	},
);

const withAuth = (method: (req: Request) => Promise<Response>) => {
	return async (req: Request) => {
		if (!isAuthorized(req)) return unauthorized();
		return method(req);
	};
};

export const GET = withAuth(handler);
export const POST = withAuth(handler);
export const DELETE = withAuth(handler);
