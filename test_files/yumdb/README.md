# yumdb fixture

The two package directories are `/var/lib/yum/yumdb/<letter>/<checksum>-<name>-<ver>-<rel>-<arch>/`
of the `nano` and `tree` packages in the container described in `../yum-history/README.md`.
Eight of the attribute files (`command_line from_repo installed_by origin_url reason releasever
checksum_type var_uuid`) were copied; the rest are not read. The fixture's file times are the
checkout's, not yum's.
