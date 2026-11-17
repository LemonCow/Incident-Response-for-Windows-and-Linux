# Building the `linux/tools/` directory

The Linux collector calls every command through `$tools/<name>` (for example `$tools/ps`) instead of trusting the target's `PATH`. This avoids running binaries a compromised host may have replaced. The binaries are **not committed to this repo** (they are git-ignored). Build `linux/tools/` yourself from a clean, trusted system.

## Required tools

```
arp  avml  cat  cp  crontab  cut  date  df  dmesg  dpkg  du  echo  find  free
getent  hostname  hostnamectl  ip  last  lastb  ls  lsblk  lsmod  lsof  mkdir
mount  netstat  printf  ps  resolvectl  route  sha1sum  ss  systemctl  tee
uname  uptime  vmstat  wc  who  whoami
```

`avml` (memory acquisition) comes from <https://github.com/microsoft/avml>. It is only needed if you choose to capture RAM.

## Dependencies

Most of these are dynamically linked, and the drive carries no shared libraries. Check each one with `ldd`:

```bash
ldd linux/tools/lsof        # see linux/ldd_output/ for a worked example
```

Two options, as discussed in `linux/ldd_output/lsof_ldd_shared_library_analysis.txt`:

1. Use statically linked builds, which have no library dependencies.
2. Use binaries copied from Ubuntu 24.04 and only run on targets with a compatible glibc and the same libraries.

`netstat`, `route`, and `arp` come from the `net-tools` package, which is not installed by default on recent Ubuntu. Install it on your build system before copying them.

## Verify

```bash
for t in $(cat docs/required-tools.txt 2>/dev/null); do [ -x linux/tools/$t ] || echo "missing: $t"; done
```
