import { compareVersions } from "./semver";
import type { CveParse, Fingerprint, KnownCve, Snapshot } from "./types";

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
