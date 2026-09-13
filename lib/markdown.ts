import type { Fingerprint, KnownCve, SecurityContextJson, Snapshot } from "./types";

export const renderFilteredMarkdown = (input: {
	snapshot: Snapshot;
	context: SecurityContextJson;
	cves: KnownCve[];
	fingerprints: Fingerprint[];
	droppedCves: number;
	droppedFingerprints: number;
}) => {
	const { snapshot, context, cves, fingerprints, droppedCves, droppedFingerprints } =
		input;
	const lines: string[] = [];
	lines.push(`# Security Context (before snapshot): ${snapshot.owner}/${snapshot.repo}`);
	lines.push(
		`_snapshot ref \`${snapshot.ref}\` · sha \`${snapshot.sha.slice(0, 12)}\` · product ${snapshot.productVersion ?? "unknown"}_`,
	);
	lines.push("");
	lines.push(
		`Filtered for eval: keep CVEs/fixes that already landed **before** this snapshot. Dropped ${droppedCves} CVE(s) and ${droppedFingerprints} fingerprint(s) that still affect it or were committed later.`,
	);
	lines.push("");
	if (context.summary) {
		lines.push(context.summary);
		lines.push("");
	}
	lines.push(`**At a glance:** ${cves.length} historical CVE(s) · ${fingerprints.length} prior fix fingerprint(s)`);
	lines.push("");
	if (cves.length) {
		lines.push("## Known CVEs (already fixed before snapshot)");
		for (const cve of cves) {
			lines.push(
				`- **${cve.id}** · ${cve.severity ?? "n/a"} · ${cve.summary ?? ""}`.trim(),
			);
		}
		lines.push("");
	}
	if (fingerprints.length) {
		lines.push("## Prior fix fingerprints (in this snapshot)");
		for (const fp of fingerprints.slice(0, 40)) {
			lines.push(
				`- \`${(fp.commit_sha ?? "").slice(0, 12)}\` ${fp.vuln_class ?? ""} — ${fp.commit_subject ?? fp.summary ?? ""}`.trim(),
			);
		}
		lines.push("");
	}
	if (context.agent_brief) {
		lines.push("## Hunting brief");
		lines.push(context.agent_brief);
	}
	return lines.join("\n");
};
