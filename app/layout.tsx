export const metadata = {
	title: "security-context-before",
	description: "Authenticated Security Context MCP proxy that hides live-version CVEs",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
	return (
		<html lang="en">
			<body>{children}</body>
		</html>
	);
}
