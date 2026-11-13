# emerge-log fixture

`emerge.log` is `/var/log/emerge.log` of a throwaway `gentoo/stage3` container (aarch64):

```sh
docker run --rm --platform linux/arm64 -v "$PWD/out:/out" gentoo/stage3:latest bash -c '
  emerge-webrsync
  rm -f /var/log/emerge.log
  emerge --getbinpkg --usepkg app-text/tree app-misc/jq app-arch/zip
  emerge --unmerge app-arch/zip
  cp /var/log/emerge.log /out/'
```

`::: completed emerge` lines are the installs (binary packages for `tree`, `zip` and
`oniguruma`; `jq` was compiled from the ebuild); the `>>> unmerge success` line is the removal.
