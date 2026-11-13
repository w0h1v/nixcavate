# portage-db fixture

`counter` is `/var/cache/edb/counter` and the three package directories hold the files the
parser reads (`BUILD_TIME SIZE SLOT repository COUNTER DESCRIPTION LICENSE`) from
`/var/db/pkg/<category>/<name>-<version>/`, all copied from the container described in
`../emerge-log/README.md` after the installs. The other files of a package directory
(`CONTENTS`, `environment.bz2`, the ebuild, ...) are not read and were left out.
