# devops-ladder — server hardening and an Always-Free VM launcher

Two scripts from a DevSecOps ladder: secure a fresh Linux box before anything is exposed,
and get hold of a free Oracle Cloud VM when the region has no capacity.

`harden.sh` runs against a real Ubuntu VM on every push, and every control it claims to
set is verified against the running system afterwards. It has also been run end to end
against an internet-facing server — 23 checks passing, and still passing after a reboot.

That was worth doing separately: CI found two bugs, and the real server found three more
that CI structurally cannot see, because CI runs the script locally and a real server is
set up over SSH. All five are described below.

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

## `ansible/harden.yml` — the same machine, run again next week

`harden.sh` is for the first ten minutes of a new box: paste it, run it, nothing needs to
be installed on the far end first. The playbook is for the box you now have to keep, and it
answers a question the shell script cannot: **what has drifted since the last time?**

That only works if running it twice changes nothing the second time, which is a property
that has to be proven rather than asserted. CI runs the playbook, checks the machine with
the same verifier, runs it a second time, and fails the build unless the second run reports
`changed=0`:

```
run 1:  ok=20   changed=11
run 2:  ok=19   changed=0
```

The difference of one in `ok` is the `restart ssh` handler. It fired on the first run
because the config changed, and did not fire on the second because nothing did — which is
the behaviour you want on a machine somebody is logged into.

Getting there means using real modules rather than wrapping shell commands in YAML. A
playbook written with `command:` everywhere passes the hardening checks and fails the
idempotency check, because `command:` reports `changed` whether or not anything happened.
The only `command:` here is `sshd -T`, and it carries `changed_when: false`.

Three things the modules give you that the shell script had to do by hand:

- `validate: visudo -cf %s` on the sudoers file — a syntax error there disables `sudo`
  machine-wide, and on a box with root login already off, that is unrecoverable
- `append: true` on the user's groups, so adding `sudo` does not silently drop every other
  group the account was in
- `exclusive: false` on the authorized key, so deploying does not lock out a colleague's
  key that was already installed

The `sshd -T` assertion from bug 1 is carried over intact: the playbook writes
`00-hardening.conf`, then refuses to continue unless sshd resolves to the values it set.

## What only a real server could find

CI runs `harden.sh` on the runner itself. A real server is hardened *over SSH*, and that
one difference surfaced three further bugs.

**3. Restarting sshd killed the script.** `systemctl restart ssh` stops the sshd process
that owns your session, so the script running inside it dies. It died at step 4 — twice —
and the firewall and fail2ban were never installed. Nothing reported an error.

The logs showed sshd stopped for two full minutes with nothing running to start it again.
It came back only because Ubuntu 24.04 enables `ssh.socket`, which listens on port 22 and
starts `ssh.service` on demand; `ssh.service` itself is `disabled` and does not start at
boot. On a host without socket activation that is a permanent lockout.

`reload` is the correct verb: it sends SIGHUP, sshd re-reads its configuration, and every
established connection survives. The script now also makes sure whichever unit owns port
22 is enabled at boot, and the verifier checks it — a hardened box you cannot log into
after a reboot is a brick.

**4. SIGPIPE from an early-exiting pipe consumer.** The fix for bug 1 read the resolved
config with `sshd -T | awk '... {print; exit}'`. `awk` exits as soon as it matches, closing
the pipe while `sshd` is still writing, so `sshd` takes SIGPIPE, `pipefail` sees a failed
pipeline and `set -e` kills the script — exit code 141. Reading to the end and printing in
an `END` block fixes it. The optimisation was what broke it.

**5. The external checker was measuring the network, not the server.** It reported port 25
open when nothing on the machine was listening on it, and it counted `Connection refused`
on ports 80 and 443 as failures.

Refused is correct there: `ufw` allows those ports and no web server is installed yet, so
the kernel sends RST. A port has three states, not two — open, refused (allowed, nothing
listening) and filtered (dropped) — and only the third belongs on a closed port.

Port 25 was the more interesting one. The same probe against `192.0.2.1`, an address
reserved by RFC 5737 that cannot exist, also "connected": an upstream network was
intercepting port 25 wholesale. The checker now runs that control probe before trusting
any positive result, which is the same idea as the mutation suite in
[tenantproof](https://github.com/Vl4dimirz/tenantproof) — a scanner needs a negative
control as much as a test suite does.

## Proof that fail2ban bans

The one check that needs a real, reachable machine. Firing failed logins from a workstation
got that address banned on the sixth attempt, and `/var/log/fail2ban.log` records it
alongside the traffic that arrived on its own:

```
08:12:57  Ban   <workstation>
08:15:19  Ban   85.190.97.128      <- not us
08:17:35  Ban   4.206.92.183       <- not us
08:22:56  Unban <workstation>      <- 600s bantime expired
08:29:19  Ban   <workstation>      <- the deliberate test
08:32:25  Ban   85.190.97.128      <- came back after its ban expired, banned again
```

Thirty failed authentications and five bans in the first ninety minutes of the machine's
life, most of it not ours. That is the ambient state of any address on the public internet,
and it is the argument for step 6 in one screenshot.

Before firing, a rollback was scheduled on the server so the test could not strand anyone:

```bash
sudo systemd-run --on-active=240 --unit=unban-safety \
  /usr/bin/fail2ban-client set sshd unbanip <address>
```

It fired on time and released the address. Arranging the way back before doing something
that can lock you out is the whole technique, and it matters most on hosts with no console.

One detail worth recording: the rule fail2ban installs is
`reject with icmp port-unreachable`, but from a home connection the ban presents as an
eight-second timeout, because the ICMP is filtered somewhere in between. The firewall rule
states an intention; the path decides the outcome. `drop` is the better choice anyway —
it tells a scanner nothing and costs it a full timeout on every attempt.

## The vendor drop-in, caught in the wild

Bug 1 above was found on a GitHub runner. Running the playbook against a Thai VPS
confirmed it is not an artifact of CI:

```
thai-01   /etc/ssh/sshd_config.d/50-cloud-init.conf : PasswordAuthentication yes
thai-01   /etc/ssh/sshd_config.d/00-hardening.conf  : PermitRootLogin no
thai-01   sshd -T                                   : passwordauthentication no
```

The provider's image ships `PasswordAuthentication yes`. Our drop-in sorts ahead of it and
wins, so `sshd -T` resolves to `no`. The original script, which only ran `sed` over the
main file, would have left password login enabled on that host — a box with no provider
console, reachable from the internet, whose only recovery path is a phone call.

The same check on the DigitalOcean droplet raises no warning at all: its cloud-init
drop-in says `no`, because the droplet was created with an SSH key. Two hosts, same
distribution, opposite vendor defaults. Which is the argument for reading `sshd -T`
instead of trusting any assumption about what is in that directory.

## `terraform/` — adopting a server that already exists

Most Terraform material starts from nothing and builds up. Real work rarely does: the
infrastructure is already there, somebody clicked it into being, and the job is to bring it
under management without disturbing it. So this configuration begins with an `import`
block rather than a fresh `create`, which is harder — the code has to match the running
resource exactly, or Terraform proposes to change it.

**The first plan proposed to destroy the server.** One attribute was missing from the
configuration:

```
~ monitoring = true -> false # forces replacement
Plan: 1 to import, 1 to add, 0 to change, 1 to destroy
```

The droplet had monitoring enabled; the config omitted it, so Terraform read the default
`false`, and that attribute cannot be changed in place. Its only route to the declared
state was to delete the machine and build a new one — new IP, empty disk. The command
typed was `plan`, and nothing in it asked for a deletion.

`lifecycle { prevent_destroy = true }` is what stopped it, and it is the reason that line
goes in from the first commit rather than after the first incident. The habit that goes
with it: read the `Plan:` line before every apply, and stop if the destroy count is not
zero.

### Two firewalls, and proof they are independent

The configuration also creates a DigitalOcean Cloud Firewall. It duplicates what `ufw`
already enforces, which sounds redundant until you consider where each one runs: `ufw` is
a process on the droplet, so anyone who takes the droplet can switch it off. The cloud
firewall runs on the provider's network and cannot be reached from inside the machine at
all.

Whether that second layer does anything is testable rather than assumed. Opening 3306 in
`ufw` alone, leaving the cloud firewall closed:

```
3306   ufw closed, cloud closed   -> filtered
3306   ufw OPEN,   cloud closed   -> filtered     <- the network layer is doing the work
80     ufw open,   cloud open     -> refused      <- the packet reached the kernel
```

`filtered` and `refused` are what separate the two layers. A filtered port never reached
the machine; a refused one arrived and found nothing listening. The middle row is the
whole argument for defence in depth, measured rather than asserted.

⚠️ The trap on the way in: a DigitalOcean firewall denies **both directions** by default
the moment it attaches. Omit the outbound rules and the droplet loses the internet — apt,
DNS and unattended upgrades all stop, and the machine looks broken for no visible reason.
`ufw` allows outbound by default, so the habit does not carry across.

### Remote state, and proving the lock

State moved off the disk into a Postgres running on the second machine — a different
provider in a different country from the droplet the state describes. If the state lived
on the same box it manages, it would still disappear with that box, which is one of the
things moving it is supposed to fix.

Postgres rather than object storage, because **the point of remote state is not where the
file sits, it is who is allowed to write to it right now.** Two people running `apply` at
the same time corrupt the file, and Terraform then no longer knows what belongs to it —
it can build duplicates, or delete something still in use. A database already has locking;
S3 traditionally needed DynamoDB bolted on to provide it.

Whether the lock works is testable, so it was tested. Two plans launched a second apart:

```
A finished rc=0        <- took the lock
B finished rc=1        <- refused

Error: Error acquiring the state lock
  ID:        2763dde5-ec5a-50a8-146d-df6a41023695
  Operation: OperationTypePlan
  Who:       deploy@ladder-01
```

It names the holder, which is what makes the message useful at 3am rather than merely
correct.

Then the local state files were moved aside entirely. `terraform state list` still returns
both resources and `plan` reports `No changes`, so the source of truth really did move
rather than being duplicated.

The connection requires SSL and Postgres confirms what it negotiated:

```
ssl | version | cipher
 t  | TLSv1.3 | TLS_AES_256_GCM_SHA384
```

Port 5432 is open to one address, `/32`, with `hostssl ... scram-sha-256` in `pg_hba.conf`.
A database holding the map of everything you manage should not be reachable by anyone else.

⚠️ Two honest gaps. The `pg` backend keeps no version history — S3 with versioning rolls
back every write, and this does not — so `backup-tfstate.sh` runs nightly and keeps
fourteen days, which is the only thing standing in for that. And the database is
self-hosted on a machine with no managed backups of its own. For a team, HCP Terraform or
S3 with versioning is the right answer; this one is honest about being a single-operator
setup that demonstrates the mechanism.

## Status

- **`harden.sh`** — runs on a real Ubuntu VM in CI on every push, and end to end against an
  internet-facing droplet: **23 checks passing, and 23 again after a reboot**. fail2ban
  proven to ban a real address, against real background attack traffic
- ⚠️ Still not proven across days or a provider maintenance window; "survives one reboot" is
  not the same as "survives a month"
- **`ansible/harden.yml`** — same six controls, verified by the same script, and proven
  idempotent against **two real hosts at different providers in different countries**,
  driven over SSH from a control node: `changed=5` and `changed=10` on the first run,
  `changed=0` on both for the second
- **`verify-hardening.sh`** — 23 checks, with a negative control proving it detects an
  unhardened machine, and a check that port 22 will still be served after a reboot
- **`check-from-outside.sh`** — port state, SSH as an outsider sees it, and an opt-in
  fail2ban test, with a control probe against a reserved address so a hijacked path is
  reported as untrustworthy rather than as a finding
- **`terraform/`** — one droplet imported, one cloud firewall created, `prevent_destroy` on
  both. State lives in Postgres on a second machine, over TLS 1.3, with the lock verified
  by two concurrent runs and a nightly dump kept for fourteen days
- **`oci-grab-vm.sh`** — exercised against the live OCI API, never reached a running VM.
  Singapore has had no Always-Free capacity for either shape, and Always Free is locked to
  your home region, so there is nowhere else to try. Payment is not the blocker

The warnings are worth reading rather than clearing: the vendor drop-in that caused bug 1
is still on disk. Our file currently wins on name order, and that is a weaker guarantee
than removing the conflict.

## Roadmap

- [x] R1 write the hardening script
- [x] R1 run it against a real machine, with each control verified afterwards
- [x] Convert `harden.sh` to an Ansible playbook, tested by the same verifier and proven
      idempotent in CI and against two real hosts from one control node
- [x] Run against a real internet-facing VPS and confirm the settings survive a reboot
- [ ] Leave it running for a month and re-verify, to catch drift rather than mistakes
- [x] Terraform for the infrastructure: the existing droplet imported under management,
      plus a cloud firewall proven to filter independently of `ufw`
- [x] Remote state on a separate host, with the lock proven and a nightly backup
- [ ] Move state to versioned object storage, so every write can be rolled back
