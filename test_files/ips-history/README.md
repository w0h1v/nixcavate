Four files of `/var/pkg/history` of illumos (OmniOS r151054, x86) in a throwaway KVM guest; example users only: `pkg install system/header` (one package added), `pkg uninstall ooce/file/lsof`,
`pkg set-publisher` (add-publisher) and a `refresh-publishers`. `pkg history -l` of the same image is the reference
(see the test: operation, start, end, user and command line equal).
