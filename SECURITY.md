# Security policy

MorphGate is a defensive bot-management and traffic-security platform for owner-controlled web properties.

## Security maintainer

[@SkyBlue997](https://github.com/SkyBlue997) is the repository owner and named security maintainer. This role covers private vulnerability triage, coordinating fixes and dependency updates, reviewing security-sensitive changes, and publishing advisories and release guidance. See [MAINTAINERS.md](MAINTAINERS.md) for the project's maintenance responsibilities.

## Report a vulnerability privately

Use [GitHub Private Vulnerability Reporting](https://github.com/SkyBlue997/MorphGate/security/advisories/new) for suspected vulnerabilities in MorphGate. Private reporting is enabled for this repository; reports are received by its maintainers through GitHub. A GitHub account is required.

Please include:

- The affected release or full commit SHA and component.
- The expected behavior, actual behavior and potential security impact.
- Minimal reproduction steps using loopback or an environment you control.
- Relevant configuration and logs with credentials, personal data and production identifiers removed.
- Any proposed fix or workaround, if available.

Do not put undisclosed vulnerabilities, deployment secrets or visitor data in public issues. Public issues are appropriate for ordinary bugs and documentation improvements that do not expose a vulnerability. If the private-report form is unavailable, open an issue asking for a private contact route without including vulnerability details.

## Supported versions

MorphGate is currently in Phase 1 preview. Security fixes are developed on `master` and included in subsequent preview releases. Use the newest preview and consult its release notes before deployment. Older previews have no separate backport commitment; there is no stable or long-term-support release yet.

Reports are handled on a best-effort basis by the maintainer. There is no guaranteed response time or paid bug-bounty program. The maintainer will assess the report, discuss a fix or mitigation, and coordinate public disclosure with the reporter. Please agree on disclosure timing before publishing reproduction details for an unresolved issue.

## Scope and testing

Relevant components include the Rust Edge and decision/challenge libraries, Go operations tools, browser SDK, configuration and key-handling paths, and the Validation Lab's isolation controls. Security-sensitive areas include upstream trust, request routing, signed configuration bundles, clearance and challenge validation, replay state, secret handling and visitor-data minimization. See the [threat model](docs/10-threat-model.md).

Perform testing only on your local instance or systems whose owner has authorized the testing. Keep the Lab target allowlist and network isolation enabled. Do not include third-party websites or shared infrastructure in a reproduction. Report vulnerabilities in upstream dependencies to their respective maintainers as well when appropriate.

The repository deliberately includes public cryptographic test vectors and TLS test private keys under its test directories. They are not deployment credentials. Never reuse them in an operational deployment. See the [installation guide](docs/getting-started.md) for fresh-key generation and configuration requirements.

## Release and acceptance status

See [releases](https://github.com/SkyBlue997/MorphGate/releases) and [Phase 1 status](docs/impl/phase1-status.md) for current fixes, limitations and validation evidence. Passing CI or publishing a preview does not establish completion of the owner-operated Cloudflare monitor period, production latency checks or browser acceptance tests.
