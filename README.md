# devops-ladder — server hardening and an Always-Free VM launcher

Two scripts from a DevSecOps ladder: secure a fresh Linux box before anything is exposed,
and get hold of a free Oracle Cloud VM when the region has no capacity.

`harden.sh` now runs against a real Ubuntu VM on every push, and every control it
claims to set is verified against the running system afterwards. That pipeline found
two real bugs on its first three runs; both are described below.

## `harden.sh` — first ten minutes on a fresh Ubuntu box

A new server on a public IP starts getting SSH login attempts within minutes. This script
does the six things that close the doors bots actually push on, in the order that matters:

| Step | What it closes |
| --- | --- |
| Update packages | Known CVEs, before anything is reachable |
| Create a non-root user | Nothing routine should run as root |
| Install your SSH public key | Key login, so there is no password to guess |
| Lock SSH: no root login, no password login | The single most-attacked surface on a new box |
| `ufw` — deny by default, allow SSH and web | Everything you did not mean to expose |
| `fail2ban` | Bans IPs that keep trying |

Order matters: the key goes in **before** password login is disabled, so a mistake does not
lock you out of your own server.

```bash
./harden.sh <username> "<your ssh public key>"
```

The script is commented for someone learning what each step defends against, not just what
it types.

## `oci-grab-vm.sh` — retry until Always-Free capacity opens

Oracle's Always-Free shapes are genuinely free and genuinely scarce. In a single-domain
home region they can answer **"Out of host capacity"** for days, and Always-Free is locked
to your home region, so you cannot simply try elsewhere.

This runs in OCI Cloud Shell (already authenticated, no API keys needed) and loops until a
slot frees up. It discovers what it needs rather than making you paste OCIDs:

- the availability domain in your compartment
- the newest Ubuntu image that matches the chosen shape
- a **public** subnet, selected by filtering on `prohibit-public-ip-on-vnic == false`

If no public subnet exists it stops and tells you to run the VCN wizard, because a subnet
created inline during instance launch is not a public one — a detail that costs an
afternoon to discover on your own.

```bash
export SSH_KEY="$(cat ~/.ssh/id_ed25519.pub)"
export OCI_TENANCY="<your compartment OCID>"
./oci-grab-vm.sh
```

## `verify-hardening.sh` — checking the result instead of the exit code

`harden.sh` has `set -e`, which only tells you that no command returned an error. That is
a different question from whether the machine is actually harder to break into.

The verifier answers the second question, by reading the state of the running system:

| Area | What is checked |
| --- | --- |
| Automatic updates | `unattended-upgrades` installed **and** switched on in `20auto-upgrades` |
| Non-root user | exists, is in `sudo`, and its `sudoers.d` file is mode 440 — `sudo` silently ignores the whole file if it is not |
| SSH key | `.ssh` 700, `authorized_keys` 600 and owned by the user, and parseable as a key — sshd refuses a too-permissive file without saying why |
| sshd | read from `sshd -T`, the config sshd actually resolves, not from the file that was just edited |
| Firewall | `ufw` active, default deny in, allow out, ports 22/80/443 open |
| fail2ban | service active **and** a jail actually watching ssh — a running fail2ban with no jail bans nobody |

CI runs it **before** hardening as well, and fails the build if it passes there. Without
that step, a verifier that returns success unconditionally would look identical to a
working one. On the current runner it reports 19 failures before and 0 after.

## The two bugs CI found

**1. Password login was never actually disabled.** The script edited
`/etc/ssh/sshd_config` with `sed`, printed *"password login is now OFF"*, and exited 0.
`sshd -T` said `passwordauthentication yes`.

Ubuntu's stock config opens with `Include /etc/ssh/sshd_config.d/*.conf`, and sshd takes
the **first** value it sees for a keyword rather than the last. Every file in that
directory is therefore read before the body of the main file and wins. Ubuntu cloud images
ship one — `50-cloud-init.conf` on the runner, `60-cloudimg-settings.conf` elsewhere —
containing `PasswordAuthentication yes`.

`sed` reports success whether or not it matched anything, so nothing looked wrong. The
script now writes `/etc/ssh/sshd_config.d/00-hardening.conf`, which sorts ahead of the
vendor file, still patches the main file for older images with no `Include`, and then
**refuses to restart sshd unless `sshd -T` resolves to the values it set** — naming the
conflicting file if it does not.

This one matters beyond this repository: it is the most-attacked surface on a new box, the
failure is silent, and the same drop-in exists on DigitalOcean, AWS, Oracle Cloud and
Hetzner images.

**2. `sshd -t` fails when sshd is not running.** It needs `/run/sshd`, a tmpfs directory
systemd creates through `RuntimeDirectory=sshd`, so it is absent for the moment after apt
upgrades `openssh-server` in step 1. The script creates it before validating, which is
what the service unit does anyway.

## Status

- **`harden.sh`** — runs on a real Ubuntu VM in CI on every push, all 21 checks passing.
  Not yet run against a long-lived internet-facing host, which is a different thing: no
  reboot, no persistence across days, no real attack traffic
- **`verify-hardening.sh`** — 21 checks and 3 warnings, with a negative control proving it
  detects an unhardened machine
- **`oci-grab-vm.sh`** — exercised against the live OCI API, never reached a running VM.
  Singapore had no Always-Free capacity for either shape, and the billing step rejected my
  card when I tried to unlock capacity through a paid account

The warnings are worth reading rather than clearing: the vendor drop-in that caused bug 1
is still on disk. Our file currently wins on name order, and that is a weaker guarantee
than removing the conflict.

## Roadmap

- [x] R1 write the hardening script
- [x] R1 run it against a real machine, with each control verified afterwards
- [ ] Run against a long-lived VPS and confirm the settings survive a reboot
- [ ] Convert `harden.sh` to an Ansible playbook, tested by the same verifier
- [ ] Terraform for the infrastructure instead of console clicks
