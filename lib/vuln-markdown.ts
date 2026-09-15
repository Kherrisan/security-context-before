export type ParsedVuln = {
	id: string;
	title: string;
	affected: string[];
	description: string;
	remediation: string;
};

export type SearchHit = {
	id: string;
	body: string;
};

const section = (markdown: string, heading: string) => {
	const re = new RegExp(`^##\\s+${heading}\\s*\\n([\\s\\S]*?)(?=^##\\s+|$)`, "im");
	return markdown.match(re)?.[1]?.trim() ?? "";
};

export const parseAffectedList = (line: string) =>
	line
		.split(",")
		.map((part) => part.trim())
		.filter(Boolean);

export const parseVulnMarkdown = (markdown: string, fallbackId = ""): ParsedVuln => {
	const id =
		markdown.match(/^#\s+(\S+)/m)?.[1]?.trim() ||
		markdown.match(/\b(CVE-\d{4}-\d+)\b/i)?.[1] ||
		fallbackId;
	const title = markdown.match(/^\*\*([^*]+)\*\*/m)?.[1]?.trim() ?? "";
	const affectedLine = markdown.match(/\*\*Affected:\*\*\s*(.+)/i)?.[1] ?? "";
	return {
		id,
		title,
		affected: parseAffectedList(affectedLine),
		description: section(markdown, "Description"),
		remediation: section(markdown, "Remediation"),
	};
};

export const vulnSummaryForParse = (record: ParsedVuln) =>
	[
		record.id,
		record.title,
		record.affected.length ? `Affected: ${record.affected.join(", ")}` : "",
		record.description,
		record.remediation,
	]
		.filter(Boolean)
		.join("\n");

export const parseSearchHits = (markdown: string): SearchHit[] => {
	const hits: SearchHit[] = [];
	let current: { id: string; lines: string[] } | null = null;
	const flush = () => {
		if (!current) return;
		hits.push({ id: current.id, body: current.lines.join("\n").trimEnd() });
		current = null;
	};
	for (const line of markdown.split("\n")) {
		const start = line.match(/^(\d+)\.\s+\*\*([^*]+)\*\*(.*)$/);
		if (start) {
			flush();
			current = {
				id: start[2].trim(),
				lines: [`**${start[2]}**${start[3]}`],
			};
			continue;
		}
		if (/^Call get_vulnerability/i.test(line) || /^#\s/.test(line)) {
			flush();
			continue;
		}
		if (current) current.lines.push(line);
	}
	flush();
	return hits;
};

export const renderSearchHits = (query: string, hits: SearchHit[]) => {
	const lines = [
		"# Vulnerability search",
		`_query:_ \`${query}\``,
		`_showing ${hits.length} of ${hits.length}_`,
		"",
	];
	hits.forEach((hit, index) => {
		lines.push(`${index + 1}. ${hit.body}`);
		lines.push("");
	});
	lines.push("Call get_vulnerability with an id above for the full record.");
	return lines.join("\n");
};

export const filteredGetMessage = (project: string, ref: string) =>
	`Filtered: this id was withheld because it belongs to project ${project} and still appears to affect snapshot ${ref} (or the affected version range could not be determined).`;

export const filteredSearchEmptyMessage = (project: string, ref: string) =>
	`No vulnerabilities remain after filtering to snapshot ${ref} for ${project}. Same-project CVEs that still affect this version (or have an unknown range) were dropped.`;
