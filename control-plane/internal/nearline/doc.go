// Package nearline implements the near-line worker behind cmd/mg-nearline:
// mg:ev v1 / v2 entry parsing, the consumer-group loop (XREADGROUP,
// XAUTOCLAIM, XACK), the in-memory windows, the v1 detectors (scanner, token
// sharing, challenge abuse, high rate), verdict writes through mg_verdict_put,
// the configuration file and /metrics (docs/impl/phase2-spec.md §13, D-53).
//
// Phase 2, WP-N1. Only this package and cmd/mg-nearline talk to Valkey from
// Go; mgctl never does.
//
// The Valkey client is github.com/valkey-io/valkey-go (pure Go, Apache-2.0;
// chosen when the Phase 2 contracts landed, spec §0.4). The worker connects
// with client-side caching off and as a single (non-cluster) client, so the
// handshake is HELLO 3 with AUTH and SETNAME, then CLIENT SETINFO and, for a
// database other than 0, SELECT: all inside the worker's ACL (spec §13.6;
// acl_test.go runs every operation as that user).
package nearline
