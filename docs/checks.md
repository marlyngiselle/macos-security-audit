# Check catalogue

Generated from [`macaudit/data/catalogue.json`](../macaudit/data/catalogue.json) with
`python3 -m macaudit list --format markdown`. Do not edit by hand. A unit test fails when
this file and the catalogue disagree.

| Area | Checks | Critical | High | Medium | Low | Info | Needs root |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| [Encryption at rest](#encryption) | 2 | 1 | 0 | 1 | 0 | 0 | 0 |
| [Application firewall](#firewall) | 3 | 0 | 1 | 1 | 1 | 0 | 0 |
| [Platform integrity](#integrity) | 4 | 1 | 2 | 1 | 0 | 0 | 0 |
| [Software updates](#updates) | 4 | 0 | 2 | 2 | 0 | 0 | 0 |
| [Screen lock and login](#login) | 5 | 0 | 2 | 3 | 0 | 0 | 0 |
| [Sharing services](#sharing) | 5 | 0 | 2 | 2 | 1 | 0 | 1 |
| [Bluetooth, AirDrop and Wi-Fi](#wireless) | 3 | 0 | 0 | 2 | 1 | 0 | 0 |
| [Safari hygiene](#browser) | 2 | 0 | 0 | 2 | 0 | 0 | 0 |
| [Credentials inventory](#identity) | 1 | 0 | 0 | 0 | 0 | 1 | 0 |
| [SSH client](#ssh) | 3 | 0 | 0 | 3 | 0 | 0 | 0 |
| [Shell environment](#shell) | 2 | 0 | 1 | 0 | 1 | 0 | 0 |
| [Third-party packages](#packages) | 1 | 0 | 0 | 0 | 1 | 0 | 0 |
| Total | 35 | 2 | 10 | 17 | 5 | 1 | 1 |

<a id="encryption"></a>

## Encryption at rest

Data on the internal disk and on backup destinations is unreadable without the owner's credentials.

| ID | Check | Severity | Probe | Expected |
| --- | --- | --- | --- | --- |
| `MA-ENC-01` | FileVault is enabled | critical | `fdesetup status` | fdesetup reports FileVault is On and no decryption is in progress. |
| `MA-ENC-02` | Time Machine destinations are encrypted | medium | `defaults read /Library/Preferences/com.apple.TimeMachine Destinations` | Every configured Time Machine destination reports LastKnownEncryptionState = Encrypted, or no destination is configured. |

<a id="firewall"></a>

## Application firewall

Inbound connections are filtered and the machine does not answer probes it has no reason to answer.

| ID | Check | Severity | Probe | Expected |
| --- | --- | --- | --- | --- |
| `MA-FW-01` | Application firewall is enabled | high | `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` | socketfilterfw reports State = 1 or State = 2. |
| `MA-FW-02` | Firewall stealth mode is enabled | medium | `/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode` | socketfilterfw reports stealth mode on. |
| `MA-FW-03` | Firewall logging is enabled | low | `/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode` | socketfilterfw reports log mode on. |

<a id="integrity"></a>

## Platform integrity

Gatekeeper, System Integrity Protection, the sealed system volume and XProtect are in their protective state.

| ID | Check | Severity | Probe | Expected |
| --- | --- | --- | --- | --- |
| `MA-INT-01` | Gatekeeper is enabled | high | `spctl --status` | spctl reports assessments enabled. |
| `MA-INT-02` | System Integrity Protection is enabled | critical | `csrutil status` | csrutil reports status enabled with no custom configuration. |
| `MA-INT-03` | Sealed system volume is authenticated | high | `csrutil authenticated-root status` | csrutil reports Authenticated Root status enabled. |
| `MA-INT-04` | XProtect definitions are present | medium | `defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString` | The XProtect bundle reports a numeric version. |

<a id="updates"></a>

## Software updates

Security fixes and malware definitions arrive without waiting for a person to click.

| ID | Check | Severity | Probe | Expected |
| --- | --- | --- | --- | --- |
| `MA-UPD-01` | Automatic update checks are enabled | medium | `defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled` | AutomaticCheckEnabled is 1. |
| `MA-UPD-02` | Security responses and system files install automatically | high | `defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall` | ConfigDataInstall is 1. |
| `MA-UPD-03` | Critical updates install automatically | high | `defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall` | CriticalUpdateInstall is 1. |
| `MA-UPD-04` | macOS updates install automatically | medium | `defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates` | AutomaticallyInstallMacOSUpdates is 1. |

<a id="login"></a>

## Screen lock and login

An unattended or stolen session cannot be used without the password.

| ID | Check | Severity | Probe | Expected |
| --- | --- | --- | --- | --- |
| `MA-LGN-01` | Screen lock requires a password | high | `sysadminctl -screenLock status` | sysadminctl reports a screen lock delay rather than screen lock off. |
| `MA-LGN-02` | Screen lock engages within five seconds | medium | `sysadminctl -screenLock status` | sysadminctl reports a delay of immediate or five seconds or less. |
| `MA-LGN-03` | Screen saver starts within 20 minutes of inactivity | medium | `defaults -currentHost read com.apple.screensaver idleTime` | idleTime is between 1 and 1200 seconds. |
| `MA-LGN-04` | Automatic login is disabled | high | `defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser` | No autoLoginUser is configured for the login window. |
| `MA-LGN-05` | Guest account is disabled | medium | `defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled` | GuestEnabled is 0 or not set. |

<a id="sharing"></a>

## Sharing services

No remote access or file service listens unless it was turned on on purpose.

| ID | Check | Severity | Probe | Expected |
| --- | --- | --- | --- | --- |
| `MA-SHR-01` | Remote Login (SSH server) is off | high | `launchctl print-disabled system` | launchd reports com.openssh.sshd as disabled or not overridden. |
| `MA-SHR-02` | Screen Sharing is off | high | `launchctl print-disabled system` | launchd reports com.apple.screensharing as disabled or not overridden. |
| `MA-SHR-03` | File Sharing (SMB server) is off | medium | `launchctl print-disabled system` | launchd reports com.apple.smbd as disabled or not overridden. |
| `MA-SHR-04` | Printer Sharing is off | low | `cupsctl` | cupsctl reports _share_printers=0. |
| `MA-SHR-05` | Remote Apple Events are off | medium | `systemsetup -getremoteappleevents` (root) | systemsetup reports Remote Apple Events: Off. |

<a id="wireless"></a>

## Bluetooth, AirDrop and Wi-Fi

Nearby radios do not expose the machine to strangers.

| ID | Check | Severity | Probe | Expected |
| --- | --- | --- | --- | --- |
| `MA-WL-01` | Bluetooth Sharing is off | medium | `defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled` | PrefKeyServicesEnabled is 0 or not set. |
| `MA-WL-02` | AirDrop is not discoverable by everyone | medium | `defaults read com.apple.sharingd DiscoverableMode` | DiscoverableMode is Contacts Only or Off, or not set. |
| `MA-WL-03` | Remembered Wi-Fi networks stay under 30 | low | `builtin:wifi_known_networks` | The Wi-Fi interface remembers 30 networks or fewer. |

<a id="browser"></a>

## Safari hygiene

The default browser does not open downloads on its own and warns about known phishing sites.

| ID | Check | Severity | Probe | Expected |
| --- | --- | --- | --- | --- |
| `MA-WEB-01` | Safari does not open downloaded files automatically | medium | `defaults read com.apple.Safari AutoOpenSafeDownloads` | AutoOpenSafeDownloads is 0. |
| `MA-WEB-02` | Safari warns about fraudulent websites | medium | `defaults read com.apple.Safari WarnAboutFraudulentWebsites` | WarnAboutFraudulentWebsites is 1. |

<a id="identity"></a>

## Credentials inventory

Inventory facts about credential storage. Recorded for context, never scored.

| ID | Check | Severity | Probe | Expected |
| --- | --- | --- | --- | --- |
| `MA-ID-01` | iCloud Keychain sync is present (inventory) | info | `defaults read MobileMeAccounts Accounts` | The signed-in account lists the keychain sync service as enabled. |

<a id="ssh"></a>

## SSH client

Keys and client configuration do not leak trust to other users or other hosts.

| ID | Check | Severity | Probe | Expected |
| --- | --- | --- | --- | --- |
| `MA-SSH-01` | SSH directory and private keys are private | medium | `builtin:ssh_permissions` | ~/.ssh is 0700, private keys and authorized_keys are not group or world accessible. |
| `MA-SSH-02` | SSH client configuration keeps host verification | medium | `builtin:ssh_config` | ~/.ssh/config does not disable host key checking and does not forward the agent to Host *. |
| `MA-SSH-03` | SSH private keys are protected by a passphrase | medium | `builtin:ssh_unencrypted_keys` | Every private key in ~/.ssh is encrypted. |

<a id="shell"></a>

## Shell environment

Shell history stays private and nothing on PATH can be replaced by another user.

| ID | Check | Severity | Probe | Expected |
| --- | --- | --- | --- | --- |
| `MA-SHL-01` | Shell history files are private | low | `builtin:history_permissions` | History files in the home directory are not group or world readable. |
| `MA-SHL-02` | No writable or relative directories in PATH | high | `builtin:path_writable` | Every PATH entry is absolute and none is world-writable. |

<a id="packages"></a>

## Third-party packages

Package managers outside Apple's update channel are kept current.

| ID | Check | Severity | Probe | Expected |
| --- | --- | --- | --- | --- |
| `MA-PKG-01` | Homebrew packages are mostly current | low | `brew outdated --quiet` | brew outdated lists 10 packages or fewer. |
