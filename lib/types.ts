export type Snapshot = {
	owner: string;
	repo: string;
	ref: string;
	sha: string;
	commitDate: string | null;
	productVersion: string | null;
};

export type KnownCve = {
	id: string;
	cwe?: string[];
	severity?: string;
	cvss?: number;
	published?: string;
	summary?: string;
	references?: string[];
	is_kev?: boolean;
	has_poc?: boolean;
};

export type Fingerprint = {
	id?: string;
	commit_sha?: string;
	commit_date?: string;
	vuln_class?: string;
	cwe?: string[];
	components?: string[];
	sink?: string;
	sink_symbols?: string[];
	fix_shape?: string;
	severity?: string;
	summary?: string;
	commit_subject?: string;
};

export type VariantLead = {
	id?: string;
	file?: string;
	line?: number;
	sink?: string;
	severity?: string;
	rationale?: string;
	commit_sha?: string;
	fix_commit?: string;
};

export type SecurityContextJson = {
	repo?: { owner?: string; name?: string; ref?: string; head_sha?: string };
	generated_at?: string;
	summary?: string;
	agent_brief?: string;
	known_cves?: KnownCve[];
	fingerprints?: Fingerprint[];
	top_risks?: unknown[];
	shared_surfaces?: unknown[];
	[key: string]: unknown;
};

export type CveParse = {
	cveId: string;
	affectedMax: string | null;
	fixedIn: string | null;
	parserVersion: string;
};
