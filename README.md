# GardenWiFi

GardenWiFi is a macOS Wi-Fi scanner and capture utility written in SwiftUI. It lists nearby networks, shows signal and security details, can capture a short packet trace from a selected access point, and extracts PMKID / EAPOL handshake hashes into `.hc22000` format for use with hashcat-compatible tooling.

## Features

- Nearby Wi-Fi network scan using `CoreWLAN`
- SSID, BSSID, RSSI, noise, channel, band, security, and vendor lookup
- Packet capture to `pcap` using `tcpdump`
- Automatic PMKID and EAPOL handshake extraction
- Exported hashes in `.hc22000` format
- SwiftUI table interface with refresh and capture actions

## Requirements

- macOS 12 or later
- Wi-Fi enabled on the Mac
- Location permission enabled for GardenWiFi so SSIDs can be shown
- Administrator approval for packet capture, because `tcpdump` is launched with elevated privileges

## How It Works

GardenWiFi scans nearby networks, lets you pick a target network, records a short capture from the Wi-Fi interface, and then parses the resulting packet capture for handshake material. If a PMKID or EAPOL handshake is found, the app writes a matching `.hc22000` file next to the `.pcap` capture.

Captured files are saved under:

`~/Desktop/GardenWiFi-Captures/`

## Build

This project is a Swift Package executable target.

```bash
swift build -c release
```

The app target is configured in `Package.swift` and includes `Sources/manuf.txt` as a bundled resource.

## Run

Open the package in Xcode or launch it from the command line after building.

```bash
swift run
```

If you prefer to run the compiled release binary directly:

```bash
.build/release/GardenWiFi
```

## Create a macOS App Bundle

If you want a distributable `.app`, build the release product and copy it into an app bundle structure.

```bash
swift build -c release
```

Then package the release binary into an `.app` bundle or use your preferred macOS packaging workflow. This repository already includes a `GardenWiFi.app` directory in the workspace, so you can use that as the basis for a signed release build if needed.

## Create a DMG

GitHub Releases accepts `.dmg` files as release assets. A simple manual approach on macOS is:

1. Build or prepare the `.app` bundle.
2. Copy the app into a temporary folder.
3. Create a `.dmg` from that folder with `hdiutil`.

Example:

```bash
mkdir -p dist
cp -R GardenWiFi.app dist/
hdiutil create -volname GardenWiFi -srcfolder dist -ov -format UDZO GardenWiFi.dmg
```

If you sign and notarize the app, do that before building the DMG so the final download is ready to distribute.

## Publish on GitHub Releases

1. Go to the repository on GitHub.
2. Open the Releases section.
3. Click Draft a new release.
4. Create a tag such as `v1.0.0`.
5. Add a release title and notes.
6. Upload the `GardenWiFi.dmg` file as a release asset.
7. Publish the release.

After publishing, the DMG will appear in the release assets list and users can download it from the Releases page.

## Suggested GitHub Repository Description

GardenWiFi is a macOS Wi-Fi scanner and capture tool that lists nearby networks, captures traffic from selected access points, and extracts PMKID/EAPOL hashes into `.hc22000` format.

## Suggested GitHub Topics

- macos
- swift
- swiftui
- wifi
- wlan
- corewlan
- packet-capture
- tcpdump
- pcap
- handshake
- pmkid
- eapol
- hashcat
- security-tooling

## Notes

- Only capture traffic from networks you own or are authorized to test.
- SSID visibility depends on macOS location permissions.
- Packet capture depends on `tcpdump` and system-level privileges.
