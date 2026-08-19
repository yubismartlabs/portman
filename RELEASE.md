# Release checklist

PortMan currently ships unsigned macOS test DMGs for Apple Silicon and Intel Macs. These builds are not suitable for public distribution: Gatekeeper will warn before first launch. The Tauri updater archives remain independently signed to prevent update tampering.

Before the first release, add this GitHub Actions secret:

- `TAURI_SIGNING_PRIVATE_KEY`: the private Tauri updater key. Generate it once with `npm run tauri -- signer generate --ci --password '' --write-keys /secure/path/portman-updater.key`; commit only its public key in `tauri.conf.json` and store this private key as a GitHub secret. The release workflow deliberately supplies an empty password, so the key itself must remain secret.

To release, update the shared version in `package.json`, `src-tauri/Cargo.toml`, and `src-tauri/tauri.conf.json`, merge to `main`, then push a matching `v<version>` tag. The release workflow builds both macOS architectures, generates signed updater archives and `latest.json`, and uploads unsigned DMGs to a draft GitHub release for controlled testing.

Before using a draft, download each DMG on a clean macOS user account and verify that it launches only after the tester explicitly approves the Gatekeeper warning. Do not publicly distribute these builds. When an Apple Developer membership is available, restore Developer ID signing and notarization before publishing a public release.
