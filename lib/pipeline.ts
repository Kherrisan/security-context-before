import { parseCves } from "./cve-parse";
import { filterKnownCves, fingerprintInSnapshot } from "./filter";
import { parseRepo, resolveSnapshot } from "./github";
import { renderFilteredMarkdown } from "./markdown";
import {
	callSecurityContextTool,
	fetchContextJson,
	fetchLeadsJson,
} from "./sc-client";
import type { VariantLead } from "./types";

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
