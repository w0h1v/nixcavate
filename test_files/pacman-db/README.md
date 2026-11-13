# pacman-db fixture

The three `desc` files are copies of `/var/lib/pacman/local/<name>-<version>/desc` from the
container described in `../pacman-log/README.md`, taken after the installs
(`cp -r /var/lib/pacman/local/{tree,jq,oniguruma}-* /out/`). The `files` and `mtree` files next
to each `desc` are not read and were left out. `oniguruma` was pulled in as a dependency
(`%REASON%` 1); `tree` and `jq` were asked for.
