/**
 *	@Project: @cldmv/digby-ext-wire
 *	@Filename: /scripts/build.mjs
 *	@Date: 2026-11-27T00:00:00-08:00
 *	@Author: Nate Corcoran <CLDMV>
 *	@Email: <Shinrai@users.noreply.github.com>
 *	-----
 *	@Last modified by: Nate Corcoran <CLDMV> (Shinrai@users.noreply.github.com)
 *	@Last modified time: 2026-11-27T00:00:00-08:00
 *	-----
 *	@Copyright: Copyright (c) 2013-2026 Catalyzed Motivation Inc. All rights reserved.
 *
 */

/**
 * @fileoverview The per-module build (npm run build): esbuild with `bundle: false` — every src file compiled and
 * minified in place with `keepNames: true`, dist/ mirroring src/ one file per module. Nothing is merged, moved,
 * split or duplicated: a module's code stays in exactly one file at the path it lives at in src/, so import shapes
 * and `new URL(..., import.meta.url)` paths survive (CLDMV fleet build convention, package-layout). The build is a
 * compile check, not a packaging step (r4-3): nothing ships dist/ — the package's `files` and the rummage manifest
 * compose src/ directly, and there is no `prepack` (the fleet's generic dist/index.cjs shim is a ship-shape
 * concern, and wire ships no dist/ at all). dist/ is a gitignored build artifact, rebuilt by the CI coverage and
 * bundle-size legs (`coverage_build_command` / `build_command` both run `npm run build:ci`).
 */

import { build } from "esbuild";
import { readdir, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const pkgRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = path.join(pkgRoot, "src");
const dist = path.join(pkgRoot, "dist");

/** Every .mjs file under src/, recursively. */
const walk = async (dir) => {
	const out = [];
	for (const e of await readdir(dir, { withFileTypes: true, recursive: true })) if (e.isFile() && e.name.endsWith(".mjs")) out.push(path.join(e.parentPath, e.name));
	return out;
};

await rm(dist, { recursive: true, force: true });
const entries = await walk(src);
await build({
	entryPoints: entries,
	outdir: dist,
	outbase: src,
	// one file per module: no bundling, no chunking, no code movement — each file compiled and minified where it is
	bundle: false,
	minify: true,
	keepNames: true,
	format: "esm",
	target: "node24",
	outExtension: { ".js": ".mjs" },
	sourcemap: true,
	logLevel: "info"
});
console.log(`built ${entries.length} module(s) into dist/`);
