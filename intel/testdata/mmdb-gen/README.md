# mmdb-gen: MaxMind DB test fixtures for mg-intel

Writes the `.mmdb` files in [`../mmdb/`](../mmdb/) that `mg-intel`'s GeoLite2 tests read ([phase1-spec §7.7](../../../docs/impl/phase1-spec.md#77-测试数据与测试)). It is a standalone Go module (not listed in `go.work`), uses [`github.com/maxmind/mmdbwriter`](https://github.com/maxmind/mmdbwriter), and is **not** run by `make check`: the generated files are committed next to it.

Regenerate after changing the records in `main.go`:

```sh
cd intel/testdata/mmdb-gen
GOWORK=off go run .
```

The output is deterministic (fixed build epoch `1790503200` = 2026-09-27T10:00:00Z, fixed insertion order), so running it without changing `main.go` leaves the files byte-for-byte unchanged.

Only documentation address ranges (RFC 5737 / RFC 3849) and documentation ASNs (RFC 5398) appear; the files contain no real geolocation or routing data.

| File | `database_type` | IP version | Records |
|---|---|---|---|
| `test-asn.mmdb` | `GeoLite2-ASN` | 6 | `192.0.2.0/24` AS64496 "MorphGate Test Network A"; `198.51.100.0/25` AS64511 "MorphGate Test Network B"; `198.51.100.128/25` AS64500 without an organisation; `203.0.113.0/24` ASN 0 (read as NotFound); `2001:db8::/32` AS65536 "MorphGate Test Network V6" |
| `test-country.mmdb` | `GeoLite2-Country` | 6 | `192.0.2.0/24` DE; `198.51.100.0/24` only `registered_country` JP (fallback); `203.0.113.0/25` `country` BR over `registered_country` US; `203.0.113.128/25` no ISO code (NotFound); `2001:db8::/32` AU |
| `test-city.mmdb` | `GeoLite2-City` | 4 | `192.0.2.0/24` NL; `198.51.100.0/24` CA (IPv6 lookups find nothing in an IPv4 tree) |
