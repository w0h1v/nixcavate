# xbps-pkgdb fixture

`pkgdb-0.38.plist` is `/var/db/xbps/pkgdb-0.38.plist` of a throwaway
`ghcr.io/void-linux/void-glibc` container (aarch64) after

```sh
docker run --rm --platform linux/arm64 -v "$PWD/out:/out" ghcr.io/void-linux/void-glibc:latest sh -c '
  xbps-install -Sy tree jq zip
  xbps-remove -y zip
  cp /var/db/xbps/pkgdb-0.38.plist /out/'
```

The file was cut down to six of its 33 top-level entries (`_XBPS_ALTERNATIVES_`, `acl`, `jq`,
`oniguruma`, `tree`, `xbps-triggers`) by keeping their text blocks unchanged, to keep it small.
