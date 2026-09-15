import { describe, expect, it } from "vitest";
import { resolveProjectSnapshot } from "../lib/github";
import {
	parseSearchHits,
	parseVulnMarkdown,
	renderSearchHits,
	vulnSummaryForParse,
} from "../lib/vuln-markdown";

const wpLive = `# CVE-2026-63030
**WordPress - SQL Injection & Remote Code Execution**
_critical · CVSS 9.8_

**Affected:** wordpress/wordpress
**CWE:** CWE-436

## Description
WordPress 6.9.x < 6.9.5 and 7.0.x < 7.0.2 contain a SQL injection caused by REST API batch endpoint route confusion.

## Impact
Remote attackers can execute arbitrary code.

## Remediation
Upgrade to WordPress 6.9.5, 7.0.2 or later.
`;

const log4j = `# CVE-2021-44228
**Apache Log4j2 - JNDI Injection**

**Affected:** apache/log4j, siemens/6bk1602-0aa12-0tp0_firmware

## Description
Apache Log4j2 <=2.14.1 contains a remote code execution.

## Remediation
Update to Log4j2 version 2.15.0 or later.
`;

const searchMd = `# Vulnerability search
_query:_ \`WordPress REST API author_exclude SQL injection\`
_showing 2 of 2_

1. **CVE-2026-63030** · critical · CVSS 9.8 · KEV
   WordPress - SQL Injection & Remote Code Execution

2. **CVE-2021-44228** · critical · CVSS 10.0 · KEV
   Apache Log4j2 - JNDI Injection

Call get_vulnerability with an id above for the full record.
`;

describe("parseVulnMarkdown", () => {
	it("reads id, affected products, and version-bearing sections", () => {
		const record = parseVulnMarkdown(wpLive);
		expect(record.id).toBe("CVE-2026-63030");
		expect(record.affected).toEqual(["wordpress/wordpress"]);
		expect(record.description).toContain("7.0.x < 7.0.2");
		expect(record.remediation).toContain("7.0.2");
		expect(vulnSummaryForParse(record)).toContain("wordpress/wordpress");
	});

	it("splits multiple affected products", () => {
		expect(parseVulnMarkdown(log4j).affected).toEqual([
			"apache/log4j",
			"siemens/6bk1602-0aa12-0tp0_firmware",
		]);
	});
});

describe("parseSearchHits", () => {
	it("extracts compact hit ids and bodies", () => {
		const hits = parseSearchHits(searchMd);
		expect(hits.map((hit) => hit.id)).toEqual(["CVE-2026-63030", "CVE-2021-44228"]);
		expect(hits[0]?.body).toContain("WordPress - SQL Injection");
	});

	it("re-renders a filtered list without dropped ids", () => {
		const kept = parseSearchHits(searchMd).filter((hit) => hit.id === "CVE-2021-44228");
		const out = renderSearchHits("log4j", kept);
		expect(out).toContain("CVE-2021-44228");
		expect(out).not.toContain("CVE-2026-63030");
		expect(out).toContain("_showing 1 of 1_");
	});
});

describe("resolveProjectSnapshot", () => {
	it("uses a non-SHA ref as productVersion when project is a slug", async () => {
		const snap = await resolveProjectSnapshot("wordpress", "7.0.1");
		expect(snap.productVersion).toBe("7.0.1");
		expect(snap.ref).toBe("7.0.1");
	});

	it("leaves productVersion unknown for a bare SHA slug snapshot", async () => {
		const snap = await resolveProjectSnapshot("wordpress", "abc123def456");
		expect(snap.productVersion).toBeNull();
	});
});
