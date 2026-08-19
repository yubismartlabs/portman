import { readFileSync } from "node:fs";

const packageVersion = JSON.parse(readFileSync(new URL("../package.json", import.meta.url))).version;
const tauriVersion = JSON.parse(readFileSync(new URL("../src-tauri/tauri.conf.json", import.meta.url))).version;
const cargoToml = readFileSync(new URL("../src-tauri/Cargo.toml", import.meta.url), "utf8");
const cargoVersion = cargoToml.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
const versions = { package: packageVersion, tauri: tauriVersion, cargo: cargoVersion };

if (!cargoVersion || new Set(Object.values(versions)).size !== 1) {
  throw new Error(`Release versions must match: ${Object.entries(versions).map(([source, version]) => `${source}=${version ?? "missing"}`).join(", ")}`);
}

const tag = process.env.RELEASE_TAG;
if (tag && tag !== `v${packageVersion}`) {
  throw new Error(`Release tag ${tag} does not match v${packageVersion}.`);
}

console.log(`Release version ${packageVersion} is consistent.`);
