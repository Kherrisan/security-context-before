import { describe, expect, it } from "vitest";
import { cveExistsOnlyBeforeSnapshot, filterKnownCves } from "../lib/filter";
import { compareVersions } from "../lib/semver";
import type { CveParse, Snapshot } from "../lib/types";

const snapshot = (version: string): Snapshot => ({
	owner: "WordPress",
	repo: "WordPress",
	ref: version,
	sha: "abc123def456",
	commitDate: "2025-01-01T00:00:00Z",
	productVersion: version,
});

const parse = (id: string, affectedMax: string | null, fixedIn: string | null): CveParse => ({
	cveId: id,
	affectedMax,
	fixedIn,
	parserVersion: "v1",
});

describe("compareVersions", () => {
	it("orders dotted WordPress versions", () => {
		expect(compareVersions("6.0.2", "7.0.1")).toBe(-1);
		expect(compareVersions("7.0.1", "7.0.1")).toBe(0);
		expect(compareVersions("7.1", "7.0.1")).toBe(1);
		expect(compareVersions("v6.5", "6.4.2")).toBe(1);
	});
});

describe("cveExistsOnlyBeforeSnapshot", () => {
	it("keeps CVEs already fixed before the snapshot", () => {
		expect(
			cveExistsOnlyBeforeSnapshot(parse("CVE-2022-4973", "6.0.2", "6.0.2"), snapshot("7.0.1")),
		).toBe(true);
	});

	it("drops CVEs that still include the snapshot version", () => {
		expect(
			cveExistsOnlyBeforeSnapshot(parse("CVE-FAKE", "7.5.0", "7.5.0"), snapshot("7.0.1")),
		).toBe(false);
		expect(
			cveExistsOnlyBeforeSnapshot(parse("CVE-FAKE2", "7.0.1", "7.0.1"), snapshot("7.0.1")),
		).toBe(false);
	});

	it("drops unknown ranges so live answers cannot leak", () => {
		expect(cveExistsOnlyBeforeSnapshot(parse("CVE-X", null, null), snapshot("7.0.1"))).toBe(
			false,
		);
		expect(
			cveExistsOnlyBeforeSnapshot(parse("CVE-X", "6.0.2", "6.0.2"), {
				...snapshot("7.0.1"),
				productVersion: null,
			}),
		).toBe(false);
	});
});

describe("filterKnownCves", () => {
	it("keeps historical CVEs and drops live ones for 7.0.1", () => {
		const parsed = new Map([
			["CVE-2022-4973", parse("CVE-2022-4973", "6.0.2", "6.0.2")],
			["CVE-2024-4439", parse("CVE-2024-4439", "6.5.2", "6.5.2")],
			["CVE-LIVE", parse("CVE-LIVE", "7.2.0", "7.2.0")],
		]);
		const kept = filterKnownCves(
			[
				{ id: "CVE-2022-4973", summary: "WordPress Core up to 6.0.2" },
				{ id: "CVE-2024-4439", summary: "up to 6.5.2" },
				{ id: "CVE-LIVE", summary: "affects 7.0 through 7.2" },
			],
			parsed,
			snapshot("7.0.1"),
		);
		expect(kept.map((cve) => cve.id)).toEqual(["CVE-2022-4973", "CVE-2024-4439"]);
	});
});
