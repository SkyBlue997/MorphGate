// Command mmdb-gen writes the small MaxMind DB fixtures that mg-intel's tests
// read (docs/impl/phase1-spec.md §7.7). Every network is a documentation
// range (RFC 5737, RFC 3849) and every ASN is a documentation ASN (RFC 5398),
// so the files carry no real geolocation or routing data.
//
// Run from this directory (it is not part of go.work):
//
//	GOWORK=off go run .
//
// The output is deterministic (fixed build epoch, fixed insertion order), so
// re-running it must leave ../mmdb/*.mmdb byte-for-byte unchanged unless the
// records below change.
package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// buildEpoch is 2026-09-27T10:00:00Z, the generation time of the other
// Phase 1 fixtures (testdata/phase1/README.md).
const buildEpoch = 1790503200

type record struct {
	network string
	value   mmdbtype.Map
}

type database struct {
	file         string
	databaseType string
	ipVersion    int
	records      []record
}

func asn(number uint32, org string) mmdbtype.Map {
	m := mmdbtype.Map{"autonomous_system_number": mmdbtype.Uint32(number)}
	if org != "" {
		m["autonomous_system_organization"] = mmdbtype.String(org)
	}
	return m
}

func iso(code string) mmdbtype.Map {
	return mmdbtype.Map{"iso_code": mmdbtype.String(code)}
}

// databases lists the fixtures. Later records overwrite the overlapping part
// of earlier ones (mmdbwriter's default ReplaceWith inserter), which is how
// the /25 sub-ranges below carve out special cases.
var databases = []database{
	{
		file:         "test-asn.mmdb",
		databaseType: "GeoLite2-ASN",
		ipVersion:    6,
		records: []record{
			{"192.0.2.0/24", asn(64496, "MorphGate Test Network A")},
			{"198.51.100.0/24", asn(64511, "MorphGate Test Network B")},
			// Upper half: an ASN without an organisation name.
			{"198.51.100.128/25", asn(64500, "")},
			// ASN 0 is never a known ASN (spec §7.2): the reader reports NotFound.
			{"203.0.113.0/24", asn(0, "MorphGate Unassigned")},
			{"2001:db8::/32", asn(65536, "MorphGate Test Network V6")},
		},
	},
	{
		file:         "test-country.mmdb",
		databaseType: "GeoLite2-Country",
		ipVersion:    6,
		records: []record{
			{"192.0.2.0/24", mmdbtype.Map{"country": iso("DE"), "registered_country": iso("DE")}},
			// No `country`: the reader falls back to `registered_country`.
			{"198.51.100.0/24", mmdbtype.Map{"registered_country": iso("JP")}},
			// Both present: `country` wins.
			{"203.0.113.0/24", mmdbtype.Map{"country": iso("BR"), "registered_country": iso("US")}},
			// A record without any ISO code: NotFound.
			{"203.0.113.128/25", mmdbtype.Map{"continent": mmdbtype.Map{"code": mmdbtype.String("SA")}}},
			{"2001:db8::/32", mmdbtype.Map{"country": iso("AU"), "registered_country": iso("AU")}},
		},
	},
	{
		// An IPv4-only City database: accepted as a country source (§7.2), and
		// exercises IPv6 lookups against an IPv4 tree.
		file:         "test-city.mmdb",
		databaseType: "GeoLite2-City",
		ipVersion:    4,
		records: []record{
			{"192.0.2.0/24", mmdbtype.Map{
				"city":    mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String("Testville")}},
				"country": iso("NL"),
			}},
			{"198.51.100.0/24", mmdbtype.Map{"country": iso("CA")}},
		},
	},
}

func build(db database) ([]byte, error) {
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		BuildEpoch:              buildEpoch,
		DatabaseType:            db.databaseType,
		Description:             map[string]string{"en": "MorphGate mg-intel test fixture (documentation ranges only)"},
		IncludeReservedNetworks: true,
		IPVersion:               db.ipVersion,
		Languages:               []string{"en"},
		RecordSize:              24,
	})
	if err != nil {
		return nil, err
	}
	for _, r := range db.records {
		_, network, err := net.ParseCIDR(r.network)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.network, err)
		}
		if err := tree.Insert(network, r.value); err != nil {
			return nil, fmt.Errorf("%s: %w", r.network, err)
		}
	}
	var buf bytes.Buffer
	if _, err := tree.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func main() {
	outDir := filepath.Join("..", "mmdb")
	for _, db := range databases {
		data, err := build(db)
		if err != nil {
			log.Fatalf("%s: %v", db.file, err)
		}
		path := filepath.Join(outDir, db.file)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			log.Fatalf("%s: %v", path, err)
		}
		fmt.Printf("wrote %s (%d bytes, %s)\n", path, len(data), db.databaseType)
	}
}
