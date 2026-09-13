import { parseCves } from "./cve-parse";
import { filterKnownCves } from "./filter";
import { isAncestorOfSnapshot, parseRepo, resolveSnapshot } from "./github";
import { renderFilteredMarkdown } from "./markdown";
import { mapPool } from "./pool";
import {
	callSecurityContextTool,
	fetchContextJson,
	fetchLeadsJson,
} from "./sc-client";
import type { Fingerprint, Snapshot, VariantLead } from "./types";

const ANCESTOR_CONCURRENCY = 8;

const keepFingerprints = async (snapshot: Snapshot, fingerprints: Fingerprint[]) => {
	const flags = await mapPool(fingerprints, ANCESTOR_CONCURRENCY, (fp) =>
		isAncestorOfSnapshot(snapshot, fp.commit_sha),
	);
	return fingerprints.filter((_, index) => flags[index]);
};

export const filteredSecurityContext = async (
	repo: string,
	ref: string,
	wait?: number,
) => {
	const { owner, repo: name } = parseRepo(repo);
	const fullName = `${owner}/${name}`;
	const [snapshot, context] = await Promise.all([
		resolveSnapshot(repo, ref),
		fetchContextJson(owner, name),
		callSecurityContextTool("get_security_context", {
			repo: fullName,
			...(wait != null ? { wait } : {}),
		}).catch(() => ""),
	]);
	const cves = context.known_cves ?? [];
	const fingerprints = context.fingerprints ?? [];
	const [parsed, keptFingerprints] = await Promise.all([
		parseCves(cves),
		keepFingerprints(snapshot, fingerprints),
	]);
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
	const fullName = `${owner}/${name}`;
	const [snapshot, leads] = await Promise.all([
		resolveSnapshot(repo, ref),
		fetchLeadsJson(owner, name),
		callSecurityContextTool("get_vulnerability_leads", { repo: fullName }).catch(
			() => "",
		),
	]);
	const flags = await mapPool(leads, ANCESTOR_CONCURRENCY, (lead: VariantLead) =>
		isAncestorOfSnapshot(snapshot, lead.commit_sha || lead.fix_commit),
	);
	const kept = leads.filter((_, index) => flags[index]);
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
