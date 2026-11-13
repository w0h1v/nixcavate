# yum-history fixture

`history-2020-11-13.sqlite` is yum's history database of a throwaway `centos:7` container
(x86-64, run with `--platform linux/amd64`, repositories pointed at vault.centos.org):

```sh
docker run --rm --platform linux/amd64 -v "$PWD/out:/out" centos:7 bash -c '
  sed -i "s|^mirrorlist=|#mirrorlist=|; s|^#baseurl=http://mirror.centos.org/[a-z]*/\$releasever|baseurl=http://vault.centos.org/centos/7.9.2009|" /etc/yum.repos.d/CentOS-Base.repo
  yum -y install tree zip nano
  yum -y remove zip
  cp /var/lib/yum/history/history-*.sqlite /out/'
```

The database was then cut down to the two transactions this run made (the image's own 174
package install and its cleanup were deleted, followed by `VACUUM`), to keep it small.
Rows are otherwise yum's own.
