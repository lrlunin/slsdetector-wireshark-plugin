# SLS detector dissector for Wireshark

[![Linux](https://img.shields.io/github/check-runs/lrlunin/slsdetector-wireshark-plugin/main?nameFilter=Linux&label=Linux)](https://github.com/lrlunin/slsdetector-wireshark-plugin/actions/workflows/release.yml)
[![Windows](https://img.shields.io/github/check-runs/lrlunin/slsdetector-wireshark-plugin/main?nameFilter=Windows&label=Windows)](https://github.com/lrlunin/slsdetector-wireshark-plugin/actions/workflows/release.yml)
[![macOS](https://img.shields.io/github/check-runs/lrlunin/slsdetector-wireshark-plugin/main?nameFilter=macOS&label=macOS)](https://github.com/lrlunin/slsdetector-wireshark-plugin/actions/workflows/release.yml)

Wireshark plugin that decodes the 48-byte `sls_detector_header` of
slsDetectorPackage UDP packets (Jungfrau, Moench, Eiger, Mythen3, ...).

<img width="1477" height="737" alt="slsdet_gui" src="https://github.com/user-attachments/assets/5f1ea381-d258-4ad7-a9b7-c9fab83feafb" />


The plugin shows all header fields, the detector type by name, the payload
size in bytes, and the number of pixels in the payload.
The pixel count uses the detector's bit depth: 16 bit for Jungfrau, Moench and
Gotthard2. Eiger and Mythen3 have a configurable dynamic range, so set it under
*Edit → Preferences → Protocols → SLSDET* (default 16 bit for Eiger, 32 bit for
Mythen3). Matterhorn has 1–4 counters per pixel of 4, 8 or 16 bit each, set
on the same page (default 1 counter, 16 bit); its pixel count is
payload bits / (counters × bits per counter), and a payload other than the
expected 8192 bytes is marked. Chip test board payloads are not plain pixel arrays, so they get no
pixel count.

It decodes packets sent from UDP **source** ports **32410–32420** by default. You
can change the range under *Edit → Preferences → Protocols → SLSDET → UDP source
port(s)*. For other ports, enable the heuristic *slsdet_udp* under
*Analyze → Enabled Protocols*.

Every field can be used as a display filter, for example:

```
slsdet.frame == 2596
slsdet.packet == 16 && slsdet.row == 0
slsdet.dettype == 5
slsdet.pixels == 4096
```

## Install

Download the zip for your Wireshark **major.minor** version (shown under
*Help → About*) and platform from the
[Releases](../../releases) page. Copy `slsdet.so` / `slsdet.dll` from its
`plugins/...` folder into your personal plugin folder:

| Platform | Folder |
|---|---|
| Linux   | `~/.local/lib/wireshark/plugins/<X.Y>/epan/` |
| Windows | `%APPDATA%\Wireshark\plugins\<X.Y>\epan\` |
| macOS   | `~/.local/lib/wireshark/plugins/<X-Y>/epan/` (`2.6` for 2.6, otherwise with a dash: `3-6`, `4-6`) |

Restart Wireshark. The plugin is then listed under *Help → About Wireshark → Plugins*.

## Build

```
ci/build.sh <2.6|3.6|4.6> <linux|windows|macos> [out-dir]
```

The script only needs the GLib headers, `curl`, `tar` and `zip`, and downloads
the matching Wireshark headers itself. On Windows it runs in an MSYS2 MINGW64 shell.

## Release

Push a tag, and GitHub Actions builds all nine variants and publishes a release:

```
git tag v1.0.0
git push origin v1.0.0
```
