# Vavёrka - the fastest network scanner. Indeed.

[![Go Reference](https://img.shields.io/badge/go-reference-blue.svg)](https://pkg.go.dev/github.com/Net-wood/Vaverka)
[![License](https://img.shields.io/github/license/Net-wood/Vaverka.svg)](https://github.com/Net-wood/Vaverka/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Net-wood/Vaverka.svg)](https://github.com/Net-wood/Vaverka/stargazers)

**Vavёrka** is the fastest network scanner, written in Go. It operates in three modes:
1. **Command-line utility**
2. **Server mode**
3**API mode**

---

## Documentation

All documentation resides in the `doc` folder. Here’s the structure:

- [Capabilities](doc/capabilities.md)
- [Usage Examples](doc/examples.md)
- [Security Guidelines](doc/security.md)
- [Architecture and Principles](doc/architecture.md)
- [Scanning Rules Structure](doc/scanning-rules.md)
- [Speed Limiting Configuration](doc/speed-limits.md)
- [Compatibility](doc/compatibility.md)

---

## Description

Vavёrka is an extremely optimized network scanner designed to quickly sweep through large network ranges with minimal overhead. By leveraging vectorized I/O operations, Vavёrka can generate and transmit **tens of millions of packets per second**.

---

## Quickstart

```bash
vaverka <your network address>
```

[GIF PLACEHOLDER]

For more detailed instructions, see the Usage Examples in the documentation.

## How Vavёrka Works

Vavёrka is heavily optimized for performance. It uses vectorized I/O to handle data transmission at scale. You can read more about this in Architecture and Principles.

## Disclaimer

Vavёrka was developed to safely scan large network ranges. However, misuse can cause harm to your computer or the networks you scan.
All responsibility for any damage lies with the user.
For guidelines on safe usage, see the Security Guidelines section of the documentation.

## Support

I’ve invested a lot of time and energy into Vavёrka, and I would greatly appreciate any support or feedback:
 - Star the project on GitHub to show your support.
 - Sponsor the project to help fund further development.
 - Contribute by submitting pull requests or opening issues.

Thank you for using Vavёrka!

