import { compareVersions } from "./semver";
import type { CveParse, Fingerprint, KnownCve, Snapshot } from "./types";

export const normalizeProjectToken = (value: string) =>
	value
		.trim()
		.toLowerCase()
		.replace(/^https?:\/\/(www\.)?github\.com\//, "")
		.replace(/\.git$/, "")
		.replace(/_/g, "-");

/**
 * True when `project` (GitHub owner/name or product slug) is the same product
 * as one of the CVE Affected vendor/product entries.
 */
export const sameProject = (project: string, affected: string[] | undefined) => {
	const proj = normalizeProjectToken(project);
	if (!proj) return false;
	const projLast = proj.split("/").filter(Boolean).pop() ?? proj;
	for (const raw of affected ?? []) {
		const entry = normalizeProjectToken(raw);
		if (!entry) continue;
		const entryLast = entry.split("/").filter(Boolean).pop() ?? entry;
		if (entry === proj || entryLast === projLast || entry === projLast || proj === entryLast) {
			return true;
		}
	}
	return false;
};

/**
 * Keep CVEs that do not affect the snapshot (already fixed strictly before it).
 * Unknown ranges are dropped so live answers cannot leak.
 */
export const cveExistsOnlyBeforeSnapshot = (
	parsed: CveParse | undefined,
	snapshot: Snapshot,
): boolean => {
	if (!parsed || !snapshot.productVersion) return false;
	const ceiling = parsed.fixedIn || parsed.affectedMax;
	if (!ceiling) return false;
	return compareVersions(snapshot.productVersion, ceiling) > 0;
};

/** Other-project CVEs pass through. Same-project CVEs use the snapshot version rule. */
export const keepVulnerability = (
	project: string,
	affected: string[] | undefined,
	parsed: CveParse | undefined,
	snapshot: Snapshot,
) => {
	if (!sameProject(project, affected)) return true;
	return cveExistsOnlyBeforeSnapshot(parsed, snapshot);
};

export const filterKnownCves = (
	cves: KnownCve[] | undefined,
	parsed: Map<string, CveParse>,
	snapshot: Snapshot,
): KnownCve[] =>
	(cves ?? []).filter((cve) =>
		cveExistsOnlyBeforeSnapshot(parsed.get(cve.id.toUpperCase()), snapshot),
	);

/** Fix commits dated after the snapshot are future knowledge. */
export const fingerprintInSnapshot = (snapshot: Snapshot, fp: Fingerprint) => {
	if (!fp.commit_date || !snapshot.commitDate) return false;
	const fixAt = Date.parse(fp.commit_date);
	const snapAt = Date.parse(snapshot.commitDate);
	if (Number.isNaN(fixAt) || Number.isNaN(snapAt)) return false;
	return fixAt <= snapAt;
};
