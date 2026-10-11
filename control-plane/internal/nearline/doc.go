// Package nearline implements the near-line worker behind cmd/mg-nearline:
// mg:ev v1 / v2 entry parsing, the consumer-group loop (XREADGROUP,
// XAUTOCLAIM, XACK), the in-memory windows, the v1 detectors (scanner, token
// sharing, challenge abuse, high rate), verdict writes through mg_verdict_put,
// the configuration file and /metrics (docs/impl/phase2-spec.md §13, D-53).
//
// Phase 2, WP-N1. Only this package and cmd/mg-nearline talk to Valkey from
// Go; mgctl never does.
package nearline

import "github.com/valkey-io/valkey-go"

// The Valkey client was chosen when the Phase 2 contracts landed (spec §0.4):
// github.com/valkey-io/valkey-go, pure Go, Apache-2.0. This reference keeps it
// in go.mod until WP-N1 uses it.
//
// Commands it sends when a connection opens (they matter for the worker's ACL
// user, spec §13.6): HELLO 3 with AUTH <user> <pass> (and SETNAME when
// ClientName is set); CLIENT TRACKING ON OPTIN unless DisableCache;
// CLIENT SETINFO LIB-NAME / LIB-VER unless ClientSetInfo is
// valkey.DisableClientSetInfo; SELECT <n> when SelectDB != 0; and, unless
// ForceSingleClient, a CLUSTER SHARDS / CLUSTER SLOTS probe. Idle connections
// are kept alive with PING. With ForceSingleClient, DisableCache and
// DisableClientSetInfo the handshake is HELLO alone (a server without HELLO
// gets AUTH and HELLO 2 instead).
var _ valkey.ClientOption
