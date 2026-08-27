# devops-ladder — server hardening and an Always-Free VM launcher

Two scripts from a DevSecOps ladder: secure a fresh Linux box before anything is exposed,
and get hold of a free Oracle Cloud VM when the region has no capacity.

**Read this first:** `harden.sh` has never been run against a real server. See
[Status](#status) before you judge it as production-tested, because it is not.

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

## Status

`oci-grab-vm.sh` ran for real against Oracle Cloud. It discovered the availability domain,
image and subnet correctly and looped on capacity as designed.

It never returned an instance. Singapore had no capacity for either the ARM or the AMD
Always-Free shape, and when I moved to unlock capacity through a paid account, the billing
step rejected my card. So:

- **`oci-grab-vm.sh`** — exercised against the live OCI API, never reached a running VM
- **`harden.sh`** — written and reviewed, **never executed against a server**

I am publishing it in that state on purpose. A hardening script that claims to be
battle-tested when it has only ever been read is worse than one that says where it stands.
When I have a box, the next commit will say so.

## Roadmap

- [x] R1 write the hardening script
- [ ] R1 run it against a real remote box and re-scan with [raidkit](https://github.com/Vl4dimirz/raidkit)
- [ ] Convert `harden.sh` to an Ansible playbook tested against a container in CI
- [ ] Terraform for the infrastructure instead of console clicks
