# Release checklist

PortMan ships as signed and notarized macOS DMGs for Apple Silicon and Intel Macs.

Before the first release, add these GitHub Actions secrets:

- `APPLE_CERTIFICATE`: base64-encoded `.p12` for a **Developer ID Application** certificate.
- `APPLE_CERTIFICATE_PASSWORD`: password used when exporting that certificate.
- `APPLE_SIGNING_IDENTITY`: exact Developer ID identity from `security find-identity -v -p codesigning`.
- `APPLE_ID`: Apple ID email for notarization.
- `APPLE_PASSWORD`: app-specific Apple ID password.
- `APPLE_TEAM_ID`: Apple Developer Team ID.
- `KEYCHAIN_PASSWORD`: a randomly generated, CI-only keychain password.

To release, update the shared version in `package.json`, `src-tauri/Cargo.toml`, and `src-tauri/tauri.conf.json`, merge to `main`, then push a matching `v<version>` tag. The release workflow builds both macOS architectures, signs and notarizes each DMG, and uploads them to a draft GitHub release for final manual QA and publication.

Before publishing a draft, download each DMG on a clean macOS user account and verify `spctl --assess --type open --context context:primary-signature -v /Applications/PortMan.app` succeeds after installation.
