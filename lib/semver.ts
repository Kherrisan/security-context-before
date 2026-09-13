const split = (value: string) =>
	value
		.trim()
		.replace(/^v/i, "")
		.split(/[.+-]/)
		.map((part) => {
			const n = Number.parseInt(part, 10);
			return Number.isFinite(n) ? n : 0;
		});

/** -1 if a < b, 0 if equal, 1 if a > b. Missing/empty compares as 0.0.0. */
export const compareVersions = (a: string | null | undefined, b: string | null | undefined) => {
	const left = split(a || "0");
	const right = split(b || "0");
	const len = Math.max(left.length, right.length);
	for (let i = 0; i < len; i++) {
		const lv = left[i] ?? 0;
		const rv = right[i] ?? 0;
		if (lv < rv) return -1;
		if (lv > rv) return 1;
	}
	return 0;
};

export const isSha = (ref: string) => /^[0-9a-f]{7,40}$/i.test(ref.trim());
