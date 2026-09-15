import { parseCves } from "./cve-parse";
import {
	cveExistsOnlyBeforeSnapshot,
	filterKnownCves,
	fingerprintInSnapshot,
	keepVulnerability,
	sameProject,
} from "./filter";
import { parseRepo, resolveProjectSnapshot, resolveSnapshot } from "./github";
import { renderFilteredMarkdown } from "./markdown";
import { mapPool } from "./pool";
import {
	callSecurityContextTool,
	fetchContextJson,
	fetchLeadsJson,
} from "./sc-client";
import type { KnownCve, VariantLead } from "./types";
import {
	filteredGetMessage,
	filteredSearchEmptyMessage,
	parseSearchHits,
	parseVulnMarkdown,
	renderSearchHits,
	vulnSummaryForParse,
} from "./vuln-markdown";

const HYDRATE_CONCURRENCY = 8;

export const filteredSecurityContext = async (repo: string, ref: string) => {
	const { owner, repo: name } = parseRepo(repo);
	const [snapshot, context] = await Promise.all([
		resolveSnapshot(repo, ref),
		fetchContextJson(owner, name),
	]);
	const cves = context.known_cves ?? [];
	const fingerprints = context.fingerprints ?? [];
	const parsed = await parseCves(cves);
	const keptFingerprints = fingerprints.filter((fp) =>
		fingerprintInSnapshot(snapshot, fp),
	);
	const keptCves = filterKnownCves(cves, parsed, snapshot);
	return renderFilteredMarkdown({
		snapshot,
		context,
		cves: keptCves,
		fingerprints: keptFingerprints,
		droppedCves: cves.length - keptCves.length,
		droppedFingerprints: fingerprints.length - keptFingerprints.length,
	});
};

export const filteredLeads = async (repo: string, ref: string) => {
	const { owner, repo: name } = parseRepo(repo);
	const [snapshot, leads] = await Promise.all([
		resolveSnapshot(repo, ref),
		fetchLeadsJson(owner, name),
	]);
	const kept = leads.filter((lead: VariantLead) => {
		const sha = lead.commit_sha || lead.fix_commit;
		if (!sha) return false;
		return fingerprintInSnapshot(snapshot, { commit_sha: sha });
	});
	if (kept.length === 0) {
		return `No variant leads remain after filtering to snapshot ${snapshot.ref} (${snapshot.sha.slice(0, 12)}). Leads describe current HEAD; live answers at this tag are dropped.`;
	}
	return kept
		.map(
			(lead) =>
				`- ${lead.file ?? "?"}:${lead.line ?? "?"} ${lead.sink ?? ""} — ${lead.rationale ?? ""}`,
		)
		.join("\n");
};

const knownCveFromMarkdown = (markdown: string, fallbackId: string): KnownCve => {
	const record = parseVulnMarkdown(markdown, fallbackId);
	return {
		id: record.id || fallbackId,
		summary: vulnSummaryForParse(record),
	};
};

export const filteredGetVulnerability = async (
	id: string,
	project: string,
	ref: string,
) => {
	const [markdown, snapshot] = await Promise.all([
		callSecurityContextTool("get_vulnerability", { id }),
		resolveProjectSnapshot(project, ref),
	]);
	if (!markdown.trim()) return markdown;
	const record = parseVulnMarkdown(markdown, id);
	if (!sameProject(project, record.affected)) return markdown;
	const parsed = await parseCves([knownCveFromMarkdown(markdown, id)]);
	const key = (record.id || id).toUpperCase();
	if (cveExistsOnlyBeforeSnapshot(parsed.get(key), snapshot)) return markdown;
	return filteredGetMessage(project, ref);
};

export const filteredSearchVulnerabilities = async (
	query: string,
	project: string,
	ref: string,
	limit?: number,
) => {
	const [searchMd, snapshot] = await Promise.all([
		callSecurityContextTool("search_vulnerabilities", {
			query,
			...(limit != null ? { limit } : {}),
		}),
		resolveProjectSnapshot(project, ref),
	]);
	const hits = parseSearchHits(searchMd);
	if (hits.length === 0) return searchMd;

	const hydrated = await mapPool(hits, HYDRATE_CONCURRENCY, async (hit) => {
		try {
			const markdown = await callSecurityContextTool("get_vulnerability", {
				id: hit.id,
			});
			return { hit, markdown };
		} catch {
			return { hit, markdown: "" };
		}
	});

	const sameProjectRecords: KnownCve[] = [];
	for (const { hit, markdown } of hydrated) {
		if (!markdown.trim()) continue;
		const record = parseVulnMarkdown(markdown, hit.id);
		if (sameProject(project, record.affected)) {
			sameProjectRecords.push(knownCveFromMarkdown(markdown, hit.id));
		}
	}
	const parsed = await parseCves(sameProjectRecords);

	const kept = hydrated
		.filter(({ hit, markdown }) => {
			const record = parseVulnMarkdown(markdown, hit.id);
			return keepVulnerability(
				project,
				record.affected,
				parsed.get((record.id || hit.id).toUpperCase()),
				snapshot,
			);
		})
		.map(({ hit }) => hit);

	if (kept.length === 0) return filteredSearchEmptyMessage(project, ref);
	return renderSearchHits(query, kept);
};
