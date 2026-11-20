Credential files of an example user, `alice`, for the `credential-files` artifact.

**None of these are real credentials.** Every secret in `tree/` is a `PLANTED-*` placeholder
(`PLANTED-PYPI-TOKEN-0023`, `PLANTED-OCI-KEY-0018`...), for example hosts (`example.com`,
`localhost:5055`). The Docker `auth` value is base64 of `alice:PLANTED-REGISTRY-PASSWORD-0007`.
Nothing here can be revoked or rotated, and secret scanners that flag these files are reporting
false positives.

The placeholders are the point of the fixture: the test `no_planted_secret_reaches_any_output`
(`crates/nixcavate-artifacts/src/linux/credential_files.rs`) parses every file and fails if any
`PLANTED-*` string, or the Docker `auth` value, appears in nixcavate's output. The artifact
reports which credentials exist (names, profiles, hosts), never the secrets.

`build.sh` creates the files with the real tools (aws, kubectl, npm, git, vault, docker against a
local registry) in a throwaway container, and writes the files of the tools that need a vendor
login (gcloud, az, terraform, oci) in their documented formats. `collect.sh` copies them here,
with the tools' own listings in `truth/`.
