# External dependencies: fixture_elf_x86_64

| Field | Value |
|---|---|
| SHA-256 | `1167a44e5c3e8d4c930427f02d4e1138bbc159b04f5b3940a81099837d21e18c` |
| Format | Executable and Linking Format (ELF) |
| Architecture | x86:LE:64:default |
| Image base | 0x400000 |

## Summary

| Metric | Count |
|---|---|
| Endpoints | 7 |
| API call sites | 10 |
| Findings | 9 |

### Endpoints by kind

| Key | Count |
|---|---|
| connection_string | 1 |
| header_constant | 1 |
| hostname | 2 |
| ipv4 | 1 |
| port | 1 |
| url | 1 |

### Findings by severity

| Key | Count |
|---|---|
| high | 4 |
| info | 1 |
| low | 2 |
| medium | 2 |

### API call sites by category

| Key | Count |
|---|---|
| database | 1 |
| http | 3 |
| resolver | 3 |
| socket | 2 |
| tls | 1 |

## Findings

| Severity | Rule | Address | Function | Detail |
|---|---|---|---|---|
| high | `hardcoded_credential` | `00402008` | open_database | credential embedded in connection_string constant (redacted) |
| high | `hardcoded_credential` | `004020c3` | fetch_capabilities | credential embedded in header_constant constant (redacted) |
| high | `tls_verification_disabled` | `00401253` | fetch_capabilities | curl_easy_setopt(CURLOPT_SSL_VERIFYPEER, 0) disables TLS peer verification |
| high | `tls_verification_disabled` | `0040127e` | disable_tls_checks | SSL_CTX_set_verify called with verify mode 0 (SSL_VERIFY_NONE) |
| medium | `plaintext_protocol` | `00402008` | open_database | postgresql:// scheme does not require transport encryption; no TLS call site in referencing functions |
| medium | `plaintext_protocol` | `00402050` | fetch_capabilities | http:// scheme does not require transport encryption; no TLS call site in referencing functions |
| low | `duplicate_host_constants` | `004012e2` | resolve_tile_hosts | function references 2 distinct hosts: tiles-standby.example-geo.internal, tiles.example-geo.internal (possible primary/failover pair) |
| low | `plaintext_port` | `004012af` | open_broker_socket | port 8080 (http-alt) is conventionally plaintext; no TLS call site in referencing functions |
| info | `private_address_embedded` | `004020d9` | open_broker_socket | private or loopback address 10.20.30.40 is embedded; deployment network is fixed at build time |

## Endpoints

| Kind | Value | Address | Referencing functions | Nearest network call | Confidence | Protocol | Notes |
|---|---|---|---|---|---|---|---|
| port | `8080` | `004012af` | open_broker_socket | `htons` @ `004012af` | high | http-alt | argument to htons; conventional service: http-alt |
| connection_string | `postgresql://svc_user:***@db.example-geo.internal:5432/tiles` | `00402008` | open_database | `PQconnectdb` @ `0040121c` | high | postgresql | credential redacted; passed as argument 0 to PQconnectdb at 0040121c |
| url | `http://tiles.example-geo.internal/wms?SERVICE=WMS&REQUEST=GetCapabilities` | `00402050` | fetch_capabilities | `curl_easy_setopt` @ `00401241` | high | ogc/wms | OGC web service request; passed as argument 2 to curl_easy_setopt at 00401241 |
| hostname | `tiles-standby.example-geo.internal` | `004020a0` | resolve_tile_hosts | `getaddrinfo` @ `00401329` | high |  | passed as argument 0 to getaddrinfo at 00401329 |
| header_constant | `Authorization: ***` | `004020c3` | fetch_capabilities | `curl_easy_setopt` @ `00401265` | high | http-auth | HTTP authentication header; credential redacted; passed as argument 2 to curl_easy_setopt at 00401265 |
| ipv4 | `10.20.30.40` | `004020d9` | open_broker_socket | `inet_pton` @ `004012c8` | high |  | passed as argument 1 to inet_pton at 004012c8 |
| hostname | `tiles.example-geo.internal` | `004020eb` | resolve_tile_hosts | `getaddrinfo` @ `00401307` | high |  | passed as argument 0 to getaddrinfo at 00401307 |

## API call sites

| API | Category | Address | Function | Protocol | Linkage | Notes |
|---|---|---|---|---|---|---|
| `PQconnectdb` | database | `0040121c` | open_database | postgresql | internal | statically linked or stub |
| `curl_easy_setopt` | http | `00401241` | fetch_capabilities | http | internal | statically linked or stub; option CURLOPT_URL |
| `curl_easy_setopt` | http | `00401253` | fetch_capabilities | http | internal | statically linked or stub; option CURLOPT_SSL_VERIFYPEER |
| `curl_easy_setopt` | http | `00401265` | fetch_capabilities | http | internal | statically linked or stub |
| `SSL_CTX_set_verify` | tls | `0040127e` | disable_tls_checks | tls | internal | statically linked or stub; verify mode 0 (SSL_VERIFY_NONE) |
| `htons` | socket | `004012af` | open_broker_socket |  | internal | statically linked or stub |
| `inet_pton` | resolver | `004012c8` | open_broker_socket |  | internal | statically linked or stub |
| `connect` | socket | `004012d7` | open_broker_socket | tcp | internal | statically linked or stub |
| `getaddrinfo` | resolver | `00401307` | resolve_tile_hosts | dns | internal | statically linked or stub |
| `getaddrinfo` | resolver | `00401329` | resolve_tile_hosts | dns | internal | statically linked or stub |

