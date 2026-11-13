`prof_attr`, `exec_attr` and `auth_attr` are the first lines of the files in `/etc/security` of illumos (OmniOS r151054, x86) in a throwaway KVM guest; example users only plus the profile the
harness added (`NXMK_Profile`, which runs `/tmp/.NXMK_EXECATTR/agent` with `uid=0;gid=0`); `prof_attr.d_nxmk` and `exec_attr.d_nxmk` are the
`.d` fragments it wrote.
