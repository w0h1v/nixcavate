`repository.db` is an SQLite 2.1 repository made by the real `svccfg` on illumos (OmniOS r151054, x86) in a throwaway KVM guest; example users only:
`SVCCFG_REPOSITORY=small.db svccfg import /var/svc/manifest/site/nxmk-smf.xml` and then the same for `nxmk-smf-lib.xml`
(manifests in `smf-manifests/`). `dump.*.txt` are the tables as the repository's own shell prints them
(`/lib/svc/bin/sqlite small.db 'select * from TABLE'`), the reference the reader's rows are compared with, row for row.
