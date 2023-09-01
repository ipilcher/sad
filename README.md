# Source Address Daemon

&copy; 2023 Ian Pilcher <<arequipeno@gmail.com>>

Monitors the IPv4 source address associated with the default route and announces
it periodically (or when it changes) on "internal" networks.

The [Source Address Client](https://github.com/ipilcher/sac) or another program
can be used to reconfigure local or remote resources when the source address
changes.

* [**Building**](#building)
* [**Installing**](#installing)
* [**Running**](#running)

## Building

Ensure the `libmnl` development files are installed.  On Fedora:

```
$ rpm -q libmnl-devel
libmnl-devel-1.0.5-2.fc38.x86_64
```

Build the executable.

```
$ gcc -O3 -Wall -Wextra -Wcast-align=strict -o sad sad.c -lmnl
```

Ensure the SELinux policy development files are installed.  On Fedora:

```
$ rpm -q selinux-policy-devel
selinux-policy-devel-38.25-1.fc38.noarch
```

Build the policy module.

```
make -f /usr/share/selinux/devel/Makefile
```

## Installing

Install the policy module.

```
# semodule -i sad.pp
```

Install the executable

```
# cp sad /usr/local/bin/
# restorecon /usr/local/bin/sad
```

Install the `systemd` unit file.

```
# cp sad.service /etc/systemd/system/
```

Edit the unit file and modify the line which reads
`ExecStart=/usr/local/bin/sad eth1 eth2`.  Replace `eth1 eth2` with the name(s)
of the network interface(s) on which the source address should be announced.
Any desired command-line options can also be added.  (See the output of `sad -h`
for the available options.)

## Running

Enable and start the service.

```
# systemctl enable sad.service --now
```

Check that the service started successfully.

```
# journalctl -u sad.service
Sep 01 12:06:40 firewall.penurio.us systemd[1]: Started Source Address Daemon.
Sep 01 12:06:40 firewall.penurio.us sad[14928]: INFO: sad.c:562: Sending from port 42 to 239.255.42.42:4242 on these interfaces:
Sep 01 12:06:40 firewall.penurio.us sad[14928]: INFO: sad.c:566:   - bond0.255
Sep 01 12:06:40 firewall.penurio.us sad[14928]: INFO: sad.c:743: Found route to 8.8.8.8 via 192.63.96.1 from 192.63.109.134 on bon>
Sep 01 12:06:40 firewall.penurio.us sad[14928]: INFO: sad.c:980: Advertising source address: 192.63.109.134
```

Check that the daemon correctly detected the default source addresses and is
announcing the it on the correct interfaces.

If necessary, the daemon can be run from the command line (usually with `-d` or
`--debug`) for debugging purposes.  To run as a non-`root` user, specify a
source port greater than 1023 with the `-P` or `--source-port` option.
