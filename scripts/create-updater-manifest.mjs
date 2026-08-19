import { readFileSync, writeFileSync } from "node:fs";

const tag = process.env.RELEASE_TAG;
const repository = process.env.GITHUB_REPOSITORY;
if (!tag || !repository) throw new Error("RELEASE_TAG and GITHUB_REPOSITORY are required.");

const version = tag.replace(/^v/, "");
const targets = [
  ["darwin-aarch64", "aarch64-apple-darwin"],
  ["darwin-x86_64", "x86_64-apple-darwin"],
];
const platforms = Object.fromEntries(targets.map(([platform, target]) => {
  const asset = `PortMan_${target}.app.tar.gz`;
  return [platform, {
    url: `https://github.com/${repository}/releases/download/${tag}/${asset}`,
    signature: readFileSync(`${asset}.sig`, "utf8").trim(),
  }];
}));

writeFileSync("latest.json", `${JSON.stringify({
  version,
  notes: `PortMan ${version}`,
  pub_date: new Date().toISOString(),
  platforms,
}, null, 2)}\n`);
