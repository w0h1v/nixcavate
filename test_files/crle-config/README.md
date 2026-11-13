`ld.config.32` and `ld.config.64` are `/var/ld/ld.config` and `/var/ld/amd64/ld.config` of illumos (OmniOS r151054, x86) in a throwaway KVM guest; example users only, made with
`crle -c /var/ld/ld.config -l /lib:/usr/lib:/tmp/.NXMK_CRLE` and `crle -64 -c /var/ld/64/ld.config -l /lib/64:/usr/lib/64:/tmp/.NXMK_CRLE64`.
`crle-32.txt` and `crle-64.txt` are what `crle` and `crle -64` print for them.
