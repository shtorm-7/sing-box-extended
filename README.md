# sing-box-extended

[![license](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![go](https://img.shields.io/badge/go-1.26-00ADD8.svg)](go.mod)
[![codeberg](https://img.shields.io/badge/mirror-codeberg-2185D0.svg)](https://codeberg.org/shtorm-7/sing-box-extended)
[![telegram](https://img.shields.io/badge/telegram-chat-26A5E4.svg?logo=telegram)](https://t.me/sing_box_extended)

Sing-box with extended features.

## 🔥 Features

### Protocols
- **WARP** — Cloudflare WARP integration through WireGuard
- **MASQUE** — Cloudflare MASQUE proxy over QUIC / HTTP-2
- **MTProxy** — Telegram MTProxy server with FakeTLS and domain fronting
- **Mieru** — Secure, hard to classify, hard to probe network protocol
- **OpenVPN** — OpenVPN client with tls-auth, tls-crypt and tls-crypt-v2 support
- **TrustTunnel** — AdGuard's obfuscated VPN protocol, indistinguishable from HTTPS traffic
- **Sudoku** — Traffic obfuscation protocol based on 4×4 Sudoku puzzles with low-entropy fingerprints
- **Snell** — Lightweight encrypted proxy (v1–v5) with TLS / HTTP obfuscation
- **SSH** — SSH client and server with certificate authentication and upstream fallback
- **Call** — Traffic tunneling through video-call platforms (VK, Dion, Telemost, WBStream)
- **VPN** — Routed tunnel over any sing-box protocol
- **Bond** — Link aggregation for increasing throughput
- **Fallback** — Outbound group with priority-based switching
- **Failover** — Automatic outbound switching with session recovery for high availability

### DNS
- **SDNS (DNSCrypt)** — Encrypted DNS queries for enhanced privacy
- **DNS Fallback** — Sequential / parallel queries across upstream resolvers

### Limiters
- **Bandwidth Limiter** — Upload / download / bidirectional rate limiting
- **Connection Limiter** — Concurrent connection control
- **Traffic Limiter** — Per-user traffic quotas
- **Rate Limiter** — Request rate limiting

### Encryption & Obfuscation
- **Amnezia 3.0** — WireGuard traffic obfuscation
- **VLESS encryption** — XRAY encryption for VLESS protocol

### Transports
- **mKCP** — Reliable UDP-based transport
- **XHTTP** — Modern XRAY transport
- **rmux** — Improved smux multiplex protocol

### Services
- **Admin Panel** — Web-based management interface
- **Manager** — Management service for configuring users, nodes, limiters
- **Manager API (HTTP/gRPC)** — HTTP and gRPC API for the Manager
- **Node Manager API** — Service for connecting nodes to remote manager

### Miscellaneous
- **Providers** — Outbound subscriptions from local files, inline lists, or remote URLs (sing-box JSON, Clash YAML, SIP008, share links)
- **Link Parser** — Outbound configured from a share link (VLESS, VMess, Shadowsocks, Trojan, Hysteria, Hysteria2, TUIC, AnyTLS)
- **Extended WireGuard options** — Advanced configuration capabilities
- **Unified Delay** — Unified latency measurement

## 📚 Examples

Configuration examples are available here:

https://github.com/shtorm-7/sing-box-extended/tree/extended/examples

## Support the Project

If you want to support the project, you can donate to the following addresses.

#### Tribute

**[RUB Donate](https://web.tribute.tg/d/JxY)**

**[EUR Donate](https://web.tribute.tg/d/JxZ)**

**[USD Donate](https://web.tribute.tg/d/Jy1)**

#### TRX (Tron)
```
TSWU6VUZ4FcUghYDmbbhK15gRVvhvBgW3F
```
#### TON
```
UQAyD2UuT5kCP6lZQlhFL0hyNibDXNE4nIo_RSLVSYAtD7N1
```
#### Solana
```
CJu8ickwRCwNE71uVFjYf1UveyCkRp9Xo44rhPcQpeFL
```
#### Bitcoin
```
bc1qqx97p8k4dchqkyd47s4vf74hrqdfnmhqvcja7x
```
#### Ethereum
```
0xAcc5919C22F2B3fAa0ec7E8BaD142da5B375FBF6
```

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```
