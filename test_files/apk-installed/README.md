# apk-installed fixture

`installed` and `world` are `/lib/apk/db/installed` and `/etc/apk/world` of a throwaway
`alpine:3` container (aarch64, apk-tools 3), unchanged:

```sh
docker run --rm --platform linux/arm64 -v "$PWD/out:/out" alpine:3 sh -c '
  apk add --no-cache tree jq zip
  apk del zip
  cp /lib/apk/db/installed /etc/apk/world /out/'
```

The 19 packages are the base image plus `tree`, `jq` and `oniguruma` (a dependency of `jq`).
