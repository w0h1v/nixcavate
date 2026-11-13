# alternatives-log fixture

`alternatives.log` is `/var/log/alternatives.log` of a throwaway `debian:12` container (aarch64):

```sh
docker run --rm --platform linux/arm64 -v "$PWD/out:/out" debian:12 bash -c '
  apt-get update -qq && apt-get install -y -qq nano vim-tiny
  update-alternatives --set editor /usr/bin/nano
  update-alternatives --remove editor /usr/bin/vim.tiny
  cp /var/log/alternatives.log /out/'
```
