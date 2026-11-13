Three files of `/var/svc/log` of illumos (OmniOS r151054, x86) in a throwaway KVM guest; example users only: a service whose method ran (`Executing start method`, `Method "start" exited with status 0`),
ssh (restart, with output of `ssh-keygen` from the method), and a service whose start method is missing (maintenance).
