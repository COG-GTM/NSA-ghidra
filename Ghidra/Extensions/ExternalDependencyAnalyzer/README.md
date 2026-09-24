# External Dependency Analyzer

A Ghidra analyzer extension and headless export script that recover an inherited
compiled application's external data-source dependencies from the binary alone:
what it connects to, on which protocol, with what kind of authentication, and
from which functions. The output is a dependency map with code references that a
sustainment team or authorizing official can act on without the original source.

Analysis is static. The target program is never executed.

## What it recovers

Endpoints (kind in parentheses):

- hostnames and fully qualified names (`hostname`), IPv4 and IPv6 literals
  (`ipv4`, `ipv6`), and `host:port` pairs (`host_port`)
- URLs and URIs (`url`), including `http(s)`, `ws(s)`, `ftp`, `ldap(s)`, `grpc`,
  `amqp(s)`, `mqtt(s)`, `kafka`, `redis`, `mongodb` and other service schemes
- database and broker connection strings (`connection_string`): JDBC, ODBC,
  libpq key/value strings, `postgresql://`, `mysql://`, `oracle:thin`, SQL Server
  key/value strings, and comma-separated broker bootstrap lists
- ports passed to `htons()` or stored into a `sockaddr_in` before `connect()`
  (`port`), recovered by PCode constant propagation with an instruction-level
  fallback
- UNC, SMB and NFS paths (`unc_path`)
- HTTP and gRPC path constants (`http_path`), OGC service query fragments and
  other protocol keywords (`service_hint`), `Authorization`, `Bearer` and API key
  header constants (`header_constant`), LDAP distinguished names (`ldap_dn`), and
  Kerberos realms (`kerberos_realm`)

API call sites: every reference to an import or locally defined function whose
name appears in the API table (socket, resolver, HTTP, TLS, database, LDAP,
Kerberos, messaging, RPC, file share and SSH APIs). Where the table names an
argument index, the analyzer resolves constant string or integer arguments at the
call site: the URL passed to `curl_easy_setopt(..., CURLOPT_URL, ...)`, the host
passed to `getaddrinfo`, the connection string passed to `PQconnectdb`, the port
passed to `htons`, or the mode passed to `SSL_CTX_set_verify`.

Linkage: for each endpoint, the defining address, the functions that reference it
(directly or through one level of pointer table), and the nearest network or
authentication call site in those functions or one call away. Links found by the
instruction-level fallback or through the call graph are marked `heuristic`.

Findings (rule identifiers in parentheses):

- credentials embedded in connection strings or header constants
  (`hardcoded_credential`); the secret is replaced with `***` in every output and
  the location is kept
- TLS verification disabled: `SSL_CTX_set_verify` with `SSL_VERIFY_NONE`,
  `CURLOPT_SSL_VERIFYPEER` or `CURLOPT_SSL_VERIFYHOST` set to 0
  (`tls_verification_disabled`)
- plaintext protocols such as `http://`, `ftp://`, `ldap://` and conventionally
  plaintext ports (80, 21, 389, 5432 and others) with no TLS call site in the
  referencing functions (`plaintext_protocol`, `plaintext_port`)
- private or loopback addresses and public addresses embedded in the binary
  (`private_address_embedded`, `public_address_embedded`)
- a function that references several distinct hosts, which usually indicates a
  primary/failover pair or two hostnames for the same role
  (`duplicate_host_constants`)
- endpoint arguments that are not constants and are therefore composed or
  supplied at runtime (`runtime_composed_endpoint`, `runtime_supplied_endpoint`)

Inside Ghidra the analyzer writes bookmarks in the category `External Dependency`,
an end-of-line comment at each defining address and call site, a plate comment
on functions that reference endpoints, and a program property list named
`External Dependency Summary` that holds the counts and the full JSON result
(results larger than 8 MiB are not cached; the property `Result JSON status`
records this and the export script re-runs the scan instead of reusing it).
All analyzer comments start with `[External Dependency]`; lines with that prefix
are removed before each run so a rescan does not leave stale comments behind,
while other comment lines at the same address are kept. The analyzer runs after
Ghidra's string analyzers so that defined strings are available to scan. Each
run scans the whole program rather than only the addresses that changed:
duplicate-host findings, nearest-call linkage and the summary counts are
program-wide, and the cached JSON result is replaced as a unit. Ghidra
coalesces the address sets queued for an analyzer, so a normal auto-analysis
pass triggers one scan.

## What it cannot recover

- hostnames, URLs or ports that are assembled at runtime from fragments,
  environment variables, command-line arguments or configuration files; these
  are reported as `runtime_composed_endpoint` or `runtime_supplied_endpoint`
  findings when a known API is called with a non-constant argument, but the value
  itself is unknown
- strings that are encrypted, encoded or built character by character
- endpoints passed through indirect calls (function pointers, virtual tables) that
  the analyzer cannot resolve to a named API
- dependencies of shared libraries that are loaded at runtime but not present in
  the analyzed program
- the deployed network: an embedded private address says what the build assumed,
  not what the environment provides

String heuristics are conservative. Hostnames require at least two labels and a
recognised top-level label, file names and version strings are rejected, and
short strings are ignored (default minimum length 6). Low-confidence results are
still reported but carry `confidence: "low"` and a note explaining why.

## Installation

Build the extension from the repository root:

```
gradle -I gradle/support/fetchDependencies.gradle
gradle prepDev
gradle :ExternalDependencyAnalyzer:zipExtensions
```

The archive is written to `build/dist/ghidra_<version>_ExternalDependencyAnalyzer.zip`
and contains the compiled jar, `data/`, `ghidra_scripts/`, `samples/` and this
README. Install it in Ghidra with File, Install Extensions, select the archive
and restart.
In a development checkout the module is picked up automatically and no
installation is needed.

The analyzer is enabled by default for ELF, PE, Mach-O and raw programs and runs
late in auto-analysis (low priority), after the string analyzers. It can also be
run once from Analysis, One Shot, External Dependency Analyzer.

Analyzer options:

| Option | Default | Effect |
|---|---|---|
| Recover endpoints | on | hostnames, IP literals, host:port pairs, ports, UNC/NFS paths |
| Recover connection strings | on | URLs and database, broker and directory connection strings |
| Recover protocol hints | on | HTTP paths, header constants, LDAP names, Kerberos realms, service keywords |
| Recover API call sites | on | references to APIs in the table |
| Report findings | on | credential, TLS, plaintext, address and duplicate host findings |
| Recover ports by sockaddr heuristic | on | port constants stored into a sockaddr before `connect` |
| Minimum string length | 6 | strings shorter than this are ignored (clamped to 2 to 256) |
| Custom API table path | empty | path to a JSON file that replaces the bundled API table |
| Write comments | on | EOL and plate comments |
| Write bookmarks | on | bookmarks in category `External Dependency` |

## Headless export

`ghidra_scripts/ExportExternalDependencies.java` runs the analyzer (or reuses a
stored result) and writes `<program>-dependencies.json` and
`<program>-dependencies.md` into the directory given as its first argument. The
program name is reduced to `[A-Za-z0-9._-]` and at most 128 characters when
forming the file names.

```
support/analyzeHeadless <projectDir> <projectName> \
    -import <binary> \
    -scriptPath Ghidra/Extensions/ExternalDependencyAnalyzer/ghidra_scripts \
    -postScript ExportExternalDependencies.java <outputDir> [options]
```

Options after the output directory:

| Option | Effect |
|---|---|
| `--reuse` | use the result stored by a previous analyzer run when present instead of scanning again |
| `--api-table=<path>` | analyst-supplied API table replacing the bundled one |
| `--min-string-length=<n>` | ignore strings shorter than `n` characters (clamped to 2 to 256) |
| `--no-comments` | do not write comments into the program |
| `--no-bookmarks` | do not write bookmarks into the program |

When the extension is installed rather than run from a development checkout,
the script directory is `<extension>/ghidra_scripts` under the Ghidra user
extensions directory.

Both files are sorted deterministically (endpoints by address then kind and
value, call sites by address, findings by severity then address) so two runs on
the same binary produce identical output and two builds of a program can be
compared with an ordinary diff.

`samples/` holds the JSON and Markdown produced from the test fixture in
`ghidra_scripts/ExportExternalDependencies_fixture.c`.

## JSON schema

```
{
  "schemaVersion": 1,
  "program": {
    "name": string,
    "sha256": string,           // digest recorded by Ghidra at import, or "" when unavailable
    "format": string,           // executable format as reported by Ghidra
    "arch": string,             // language id, e.g. "x86:LE:64:default"
    "imageBase": string         // "0x" hex
  },
  "endpoints": [
    {
      "kind": "url" | "connection_string" | "hostname" | "host_port" | "ipv4" |
              "ipv6" | "port" | "unc_path" | "http_path" | "header_constant" |
              "service_hint" | "ldap_dn" | "kerberos_realm",
      "value": string,          // credentials replaced with "***"
      "address": string,        // defining address
      "referencingFunctions": [string],
      "nearestNetworkCall": {
        "api": string,
        "address": string,
        "function": string,
        "heuristic": boolean
      } | null,
      "confidence": "high" | "medium" | "low",
      "protocolHint": string,   // "" when unknown
      "notes": [string]
    }
  ],
  "apiCallSites": [
    {
      "api": string,
      "category": string,       // category from the API table
      "address": string,        // call or reference site
      "function": string,       // containing function, "" when none
      "protocolHint": string,
      "external": boolean,      // true for imports, false for local definitions
      "notes": [string]
    }
  ],
  "findings": [
    {
      "severity": "info" | "low" | "medium" | "high",
      "rule": "hardcoded_credential" | "tls_verification_disabled" |
              "plaintext_protocol" | "plaintext_port" |
              "private_address_embedded" | "public_address_embedded" |
              "duplicate_host_constants" | "runtime_composed_endpoint" |
              "runtime_supplied_endpoint",
      "address": string,
      "function": string,
      "detail": string          // credentials replaced with "***"
    }
  ],
  "summary": {
    "endpointCount": integer,
    "apiCallSiteCount": integer,
    "findingCount": integer,
    "endpointsByKind": { kind: integer },
    "findingsBySeverity": { severity: integer },
    "apiCallSitesByCategory": { category: integer },
    "warnings": [string]
  }
}
```

Addresses are printed as Ghidra prints them for the program's address space.
`DependencyReportReader` in the extension validates a document against this
schema and rejects unknown keys, unknown kinds, severities or confidences, and
summary counts that disagree with the arrays.

## Extending the API table

The bundled table is `data/external_dependency_apis.json`. Analysts can add
entries there or supply a replacement file through the analyzer option or the
`--api-table` script argument; the table is reloaded on every run, so no rebuild
is required.

```
{
  "version": 1,
  "apis": [
    {
      "name": "vendor_connect",
      "category": "database",
      "protocolHint": "vendor-db",
      "hostArgument": 0,
      "notes": "first argument is the connection string"
    },
    {
      "name": "vendor_set_option",
      "category": "http",
      "optionArgument": 1,
      "hostArgument": 2,
      "optionValues": { "7": "VENDOR_OPT_URL" }
    }
  ]
}
```

Fields:

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | symbol name; `[A-Za-z0-9_@.$?]`, at most 255 characters. Leading underscores, `__imp_` prefixes, `@n` decorations, Windows `A`/`W` suffixes and Ghidra `_0` duplicates are stripped from program symbols before matching |
| `category` | no | `[a-z0-9_-]`, at most 32 characters; used for grouping (default `other`) |
| `protocolHint` | no | protocol attributed to endpoints resolved at this call; `[A-Za-z0-9_./+-]`, at most 64 characters |
| `hostArgument` | no | zero-based index of a pointer argument to a string endpoint |
| `portArgument` | no | zero-based index of an integer port argument |
| `optionArgument` | no | zero-based index of an option selector; `hostArgument` is only used when the option name ends in `_URL` or `_PROXY` |
| `optionValues` | no | map from selector value (decimal string) to option name; names are `[A-Za-z0-9_]`, at most 64 characters |
| `verifyModeArgument` | no | zero-based index of a TLS verification mode; 0 is reported as a finding |
| `notes` | no | free text carried into the report; control characters are collapsed to spaces, the text is truncated to 256 characters and passed through the same credential redaction as recovered strings |

Argument indexes must be between 0 and 31 and refer to the program's default
calling convention; register arguments only. A custom table larger than 4 MiB or
containing an invalid entry is rejected with a generic message, the reason is
written to the application log, and the bundled table is used instead.

## Tests

Unit tests (`src/test`) cover the classifier, the redactor, the API table
loader and the report writer and reader. Integration tests (`src/test.slow`)
run the analyzer over a synthetic program and run the headless script against a
fixture compiled at test time from `ghidra_scripts/ExportExternalDependencies_fixture.c`
by `ExportExternalDependencies_build_fixture.py`. The fixture is built with the
system `gcc` for x86-64 ELF; AArch64 (`aarch64-linux-gnu-gcc`) and PE
(`x86_64-w64-mingw32-gcc`) variants are built when those compilers are present
and skipped with a message otherwise. When an optional variant is built, the
headless test also imports it and checks the planted hosts, URL, redacted
connection string and credential finding; when none is built that test is
reported as skipped. No compiled fixture is committed and no fixture is
executed.

```
gradle -p Ghidra/Extensions/ExternalDependencyAnalyzer test integrationTest
```
