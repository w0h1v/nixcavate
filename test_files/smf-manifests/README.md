Three manifests of illumos (OmniOS r151054, x86) in a throwaway KVM guest; example users only: two written by hand for the harness (an enabled service whose method script starts a background
program, and one whose start method is `/tmp/.NXMK_SMFLIB/agent`), and one that `inetconv` generated from an `inetd.conf` line.
`export-nxmk-smf.xml` is `svccfg export` of the imported first service.
