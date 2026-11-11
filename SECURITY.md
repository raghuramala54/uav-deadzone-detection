# Security, Privacy & Responsible Use

This project captures wireless signals and device identifiers. Use it responsibly.

## Authorised use only
- Capture **only** on networks you own or are **explicitly, in writing**,
  authorised to assess. Keep your scope and authorisation on record.
- Intercepting, decrypting, or tampering with third-party communications is
  illegal in most jurisdictions.

## What this tool does and does not do
- **Does:** passively read 802.11 management frames (beacons/probes), map RSSI,
  and classify access points.
- **Does not:** associate to networks, inject or deauthenticate frames, crack
  keys, run a man-in-the-middle, or decode user payloads. No such functionality
  is shipped.

## Privacy by design
- MAC/BSSID addresses are personal data. They are **salted-hashed by default**
  (`--keep-mac` opts out and should be used only with authorisation).
- Account for client **MAC randomization** when counting devices.
- Minimise what you retain; delete raw captures when the assessment is complete.

## Flight safety & aviation law
- Comply with local drone regulations: FAA **Remote ID** (14 CFR Part 89),
  India **DGCA Drone Rules 2021** / Digital Sky, and equivalent.
- Fly geofenced, within authorised airspace, within visual line of sight unless
  separately permitted.

## Reporting a vulnerability
Open a private security advisory or email the maintainer. Please do not file
public issues for sensitive findings.
