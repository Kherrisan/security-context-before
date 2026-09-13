import { describe, expect, it } from "vitest";
import { cacheKey } from "../lib/cache";

describe("cacheKey", () => {
	it("is stable per CVE id, ignoring case", () => {
		expect(cacheKey("CVE-2022-4973")).toBe(cacheKey("cve-2022-4973"));
		expect(cacheKey("CVE-2022-4973")).toMatch(/^v1:CVE-2022-4973$/);
	});
});
