export const mapPool = async <T, R>(
	items: T[],
	limit: number,
	fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> => {
	if (items.length === 0) return [];
	const results = new Array<R>(items.length);
	let next = 0;
	const worker = async () => {
		while (true) {
			const index = next;
			next += 1;
			if (index >= items.length) return;
			results[index] = await fn(items[index]!, index);
		}
	};
	const n = Math.min(Math.max(1, limit), items.length);
	await Promise.all(Array.from({ length: n }, () => worker()));
	return results;
};
