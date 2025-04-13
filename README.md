# dhcpsyncd

sync dhcpd(8) leases into unbound(8)

## build

```
make
```

## install

```
sudo install dhcpleased /usr/local/sbin
sudo install -m 555 rc.d/dhcpleased /etc/rc.d
```

## references

https://gist.github.com/yjh0502/53d696ce1b89824ba200b90623eaaf61
