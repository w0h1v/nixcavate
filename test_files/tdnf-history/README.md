# tdnf-history fixture

`history.db` is `/usr/lib/sysimage/tdnf/history.db` of a throwaway `photon:5.0` container
(aarch64, tdnf 3.5), unchanged:

```sh
docker run --rm --platform linux/arm64 -v "$PWD/out:/out" photon:5.0 bash -c '
  tdnf install -y tree zip jq
  tdnf remove -y zip
  cp /usr/lib/sysimage/tdnf/history.db /out/'
```

Transaction 1 is the baseline snapshot, 2 is the image build, 3 the key import, 4 the install
and 5 the removal.
