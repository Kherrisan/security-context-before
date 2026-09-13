import { isSha } from "./semver";
import type { Snapshot } from "./types";

const githubHeaders = () => {
	const token = process.env.GITHUB_TOKEN?.trim();
	const headers: Record<string, string> = {
		accept: "application/vnd.github+json",
		"user-agent": "security-context-before",
	};
	if (token) headers.authorization = `Bearer ${token}`;
	return headers;
};

export const parseRepo = (repo: string) => {
	const cleaned = repo.trim().replace(/^https?:\/\/github\.com\//i, "").replace(/\.git$/, "");
	const [owner, name] = cleaned.split("/");
	if (!owner || !name) {
		throw new Error(`repo must be owner/name, got ${JSON.stringify(repo)}`);
	}
	return { owner, repo: name };
};

const ghJson = async <T>(url: string) => {
	const res = await fetch(url, { headers: githubHeaders() });
	if (!res.ok) {
		const body = await res.text();
		throw new Error(`GitHub ${res.status} ${url}: ${body.slice(0, 300)}`);
	}
	return (await res.json()) as T;
};

const ghText = async (url: string) => {
	const res = await fetch(url, { headers: githubHeaders() });
	if (!res.ok) return null;
	return res.text();
};

const parseWpVersion = (source: string) => {
	const match = source.match(/\$wp_version\s*=\s*['"]([^'"]+)['"]/);
	return match?.[1] ?? null;
};

export const resolveSnapshot = async (repo: string, ref: string): Promise<Snapshot> => {
	const { owner, repo: name } = parseRepo(repo);
	const trimmed = ref.trim();
	const commit = await ghJson<{
		sha: string;
		commit?: { committer?: { date?: string }; author?: { date?: string } };
	}>(
		`https://api.github.com/repos/${owner}/${name}/commits/${encodeURIComponent(trimmed)}`,
	);
	const sha = commit.sha;
	const commitDate =
		commit.commit?.committer?.date ?? commit.commit?.author?.date ?? null;

	let productVersion: string | null = null;
	if (!isSha(trimmed)) {
		productVersion = trimmed.replace(/^v/i, "");
	}

	const [tags, wpSource] = await Promise.all([
		productVersion
			? Promise.resolve(null)
			: ghJson<Array<{ name: string; commit: { sha: string } }>>(
					`https://api.github.com/repos/${owner}/${name}/tags?per_page=100`,
				).catch(() => null),
		ghText(
			`https://raw.githubusercontent.com/${owner}/${name}/${sha}/wp-includes/version.php`,
		),
	]);

	if (!productVersion && tags) {
		const hit = tags.find(
			(tag) => tag.commit.sha === sha || sha.startsWith(tag.commit.sha),
		);
		if (hit) productVersion = hit.name.replace(/^v/i, "");
	}
	if (!productVersion && wpSource) {
		productVersion = parseWpVersion(wpSource);
	}

	return {
		owner,
		repo: name,
		ref: trimmed,
		sha,
		commitDate,
		productVersion,
	};
};

/** True when `commitSha` is the snapshot or an ancestor of it (fix already in tree). */
export const isAncestorOfSnapshot = async (
	snapshot: Snapshot,
	commitSha: string | undefined,
): Promise<boolean> => {
	if (!commitSha) return false;
	if (snapshot.sha.startsWith(commitSha) || commitSha.startsWith(snapshot.sha)) {
		return true;
	}
	try {
		const compare = await ghJson<{ status?: string }>(
			`https://api.github.com/repos/${snapshot.owner}/${snapshot.repo}/compare/${encodeURIComponent(commitSha)}...${encodeURIComponent(snapshot.sha)}`,
		);
		return compare.status === "ahead" || compare.status === "identical";
	} catch {
		return false;
	}
};
