`user_attr` is `/etc/user_attr` of illumos (OmniOS r151054, x86) in a throwaway KVM guest; example users only after `useradd`, `roleadd -P`, `usermod -R` and `usermod -P 'Primary Administrator'`
(a role, a user that holds it, one with a root-equivalent profile, the stock accounts and the root entry with an escaped `\:`).
`profiles-*.txt` and `roles-alice.txt` are the output of `profiles USER` and `roles alice` on that system.
