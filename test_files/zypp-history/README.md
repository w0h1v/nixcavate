# zypp-history fixture

`history` is `/var/log/zypp/history` of a throwaway `opensuse/leap:15.6` container (aarch64),
unchanged, after

```sh
docker run --rm --platform linux/arm64 -v "$PWD/out:/out" opensuse/leap:15.6 bash -c '
  zypper -n in --no-recommends tree zip jq
  zypper -n rm zip
  cp /var/log/zypp/history /out/'
```

It holds both commands, the installs and the removal, and the `patch` lines libzypp writes
for patches already applied in the repository metadata.
