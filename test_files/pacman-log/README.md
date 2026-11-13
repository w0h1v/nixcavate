# pacman-log fixture

`pacman.log` is the whole log of a throwaway `archlinux:latest` container (x86-64, run with
`--platform linux/amd64`) after installing and removing packages with pacman 7:

```sh
docker run --rm --platform linux/amd64 -v "$PWD/out:/out" archlinux:latest bash -c '
  sed -i "s/^\[options\]/[options]\nDisableSandbox/" /etc/pacman.conf   # seccomp fails under emulation
  rm -f /var/log/pacman.log
  pacman -Sy --noconfirm tree jq
  pacman -S --noconfirm zip
  pacman -R --noconfirm zip
  cp /var/log/pacman.log /out/'
```

The upgrade, downgrade, reinstall and old-format (`[2019-01-02 03:04]`) lines are written
inline in the unit tests from libalpm's log format; no container produced them.
