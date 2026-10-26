# Threat model: a single macOS laptop

This document states what macaudit defends against, which check covers each threat, and what it deliberately leaves to other controls. The subject is one laptop used by one person, carried between home, office and public networks, and administered without an MDM.

## Assets

| Asset | Why an attacker wants it |
| --- | --- |
| Data on the internal disk | Documents, mail caches, browser profiles, source code |
| Credentials at rest | SSH private keys, tokens typed into shell history, the keychain |
| The unlocked session | Everything the user can reach, with no exploit required |
| The machine as a foothold | A trusted device on a corporate VPN or a home network |
| Backups | A full copy of the disk, often less protected than the original |

## Adversaries

| Adversary | Capability | Typical goal |
| --- | --- | --- |
| Opportunistic thief | Physical possession, no prior access | Resell the device, browse what is readable |
| Commodity malware | Code execution as the user through a download or a malicious installer | Persistence, credential theft, ransomware |
| Network attacker | Same Wi-Fi, same LAN, or an evil twin access point | Reach listening services, intercept traffic |
| Nearby stranger | Bluetooth and AirDrop range | Push unsolicited content, enumerate the device |
| Malicious dependency | Code shipped through a package manager | Execute in every shell and build the user runs |

## Threats and the checks that address them

### Lost or stolen device

| ID | Threat | Checks | Residual risk |
| --- | --- | --- | --- |
| T1 | Disk removed or read in target disk mode | `MA-ENC-01` | Weak login password still allows an offline guess against FileVault |
| T2 | Backup disk lost with the laptop bag | `MA-ENC-02` | Cloud backups are outside scope |
| T3 | Session used before the owner notices | `MA-LGN-01`, `MA-LGN-02`, `MA-LGN-03` | A shoulder-surfed password defeats the lock |
| T4 | Restart hands a session to whoever opens the lid | `MA-LGN-04`, `MA-LGN-05` | None once automatic login and guest are off |

### Malware

| ID | Threat | Checks | Residual risk |
| --- | --- | --- | --- |
| T5 | Unsigned or unnotarised installer runs | `MA-INT-01` | A user can still approve an app in Privacy and Security |
| T6 | Known malware family executes | `MA-INT-04`, `MA-UPD-02` | New families until definitions catch up |
| T7 | Root-level malware modifies the OS to persist | `MA-INT-02`, `MA-INT-03` | Kernel or firmware vulnerabilities |
| T8 | Exploit of a vulnerability already patched upstream | `MA-UPD-01`, `MA-UPD-03`, `MA-UPD-04` | The window between disclosure and patch |
| T9 | Drive-by download opened automatically | `MA-WEB-01`, `MA-WEB-02` | Other browsers are not audited |
| T10 | Planted binary shadows a real command | `MA-SHL-02` | Writable directories owned by the user are allowed by design |
| T11 | Malware reads secrets left in files | `MA-SSH-03`, `MA-SHL-01` | Same-user malware can still read history files |

### Remote access

| ID | Threat | Checks | Residual risk |
| --- | --- | --- | --- |
| T12 | Password spraying against SSH on a hostile network | `MA-SHR-01`, `MA-FW-01` | Services added by third-party software |
| T13 | Interactive takeover through Screen Sharing | `MA-SHR-02` | Remote support tools installed separately |
| T14 | Folders exposed over SMB or printers over CUPS | `MA-SHR-03`, `MA-SHR-04` | |
| T15 | Applications driven remotely through Apple Events | `MA-SHR-05` (root) | Skipped without sudo, reported as skipped |
| T16 | Host discovered and fingerprinted on a shared LAN | `MA-FW-02`, `MA-FW-03` | Bonjour advertisements |

### Proximity and wireless

| ID | Threat | Checks | Residual risk |
| --- | --- | --- | --- |
| T17 | Unsolicited files over AirDrop or Bluetooth | `MA-WL-01`, `MA-WL-02` | Users who switch AirDrop to Everyone temporarily |
| T18 | Automatic join to an evil twin access point | `MA-WL-03` | Any single remembered open network is still joinable |

### Supply chain and trust

| ID | Threat | Checks | Residual risk |
| --- | --- | --- | --- |
| T19 | Vulnerable third-party packages linger | `MA-PKG-01` | A current but malicious package is not detected |
| T20 | One compromised server pivots to others through SSH | `MA-SSH-01`, `MA-SSH-02` | Agent forwarding enabled for a specific host |
| T21 | Credentials stored in an unmanaged place | `MA-ID-01` (inventory only) | Not scored by design |

## Threats against the tool itself

| ID | Threat | Mitigation |
| --- | --- | --- |
| A1 | The audit changes the machine it inspects | Probes only run commands from the reviewed catalogue, without a shell and with stdin closed. The Context exposes no write operation. See [ADR 0003](adr/0003-read-only-never-remediate.md) |
| A2 | The report leaks personal data when shipped to a fleet collector | No hostname, serial or user name is collected. Home paths in evidence become `~`, other `/Users/<name>` paths become `/Users/<user>`. Checks marked `sensitive` drop evidence entirely. Network names and key material are never echoed |
| A3 | A tampered catalogue hides a failing control | The catalogue is versioned with the code and validated against a JSON schema at load time and in CI |
| A4 | A green report gives false comfort | Anything the probe cannot read is `unknown`, never `pass`. Root-only checks run without sudo are `skipped`, never `pass` |
| A5 | Upload token exposed during fleet shipping | The fleet script reads the token from the keychain and passes it to curl on stdin, so it never appears in the process list. Uploads require HTTPS |

## Out of scope

- Firmware and boot chain attacks beyond what SIP and the sealed system volume report.
- Anything an MDM enforces through configuration profiles. A profile-managed setting may read as `unknown` here even though it is enforced.
- Account security in the cloud (iCloud, identity providers, two-factor policy).
- Third-party browsers, VPN clients and endpoint security agents.
