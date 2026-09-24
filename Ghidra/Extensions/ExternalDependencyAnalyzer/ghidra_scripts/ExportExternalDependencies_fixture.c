/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Test fixture for ExportExternalDependencies. Built at test time by
 * ExportExternalDependencies_build_fixture.py; never executed. It stands in for an
 * inherited service that talks to a database, a tile service, a broker and a plain
 * socket, using local stubs instead of real client libraries so that it builds with a
 * bare C toolchain and without linking libcurl, OpenSSL or libpq.
 */
#include <stdint.h>
#include <string.h>

#define CURLOPT_URL 10002
#define CURLOPT_SSL_VERIFYPEER 64
#define SSL_VERIFY_NONE 0
#define SSL_VERIFY_PEER 1

typedef struct curl_handle curl_handle;
typedef struct ssl_ctx ssl_ctx;
typedef struct pg_conn pg_conn;

struct fixture_sockaddr_in {
	uint16_t sin_family;
	uint16_t sin_port;
	uint32_t sin_addr;
	uint8_t sin_zero[8];
};

/* Stubs: opaque, never inlined or analysed across calls, never real network code. */
volatile long fixture_sink;
#define STUB __attribute__((noinline, noipa, used))
STUB int curl_easy_setopt(curl_handle *h, long option, const char *value)
{
	fixture_sink += option + (value ? value[0] : 0) + (h ? 1 : 0);
	return (int) fixture_sink;
}

STUB void SSL_CTX_set_verify(ssl_ctx *ctx, int mode, void *callback)
{
	(void) ctx;
	(void) callback;
	fixture_sink += mode;
}

STUB pg_conn *PQconnectdb(const char *conninfo)
{
	fixture_sink += conninfo[0];
	return (pg_conn *) (uintptr_t) fixture_sink;
}

STUB uint16_t htons(uint16_t v)
{
	fixture_sink += v;
	return (uint16_t) ((v << 8) | (v >> 8));
}

STUB int connect(int fd, const struct fixture_sockaddr_in *addr, unsigned len)
{
	fixture_sink += fd + len + addr->sin_port;
	return (int) fixture_sink;
}

STUB int inet_pton(int af, const char *src, void *dst)
{
	(void) dst;
	fixture_sink += af + src[0];
	return (int) fixture_sink;
}

STUB int getaddrinfo(const char *node, const char *service, void *hints, void **res)
{
	(void) hints;
	*res = NULL;
	fixture_sink += node[0] + service[0];
	return (int) fixture_sink;
}

/* Planted constants. */
static const char *const TILE_HOST = "tiles.example-geo.internal";
static const char *const TILE_HOST_BACKUP = "tiles-standby.example-geo.internal";
static const char *const BROKER_ADDR = "10.20.30.40";
static const char *const DB_URL = "postgresql://svc_user:Tr0ub4dor@db.example-geo.internal:5432/tiles";
static const char *const CAPABILITIES_URL =
	"http://tiles.example-geo.internal/wms?SERVICE=WMS&REQUEST=GetCapabilities";
static const char *const AUTH_HEADER = "Authorization: Bearer";

STUB int open_database(void)
{
	pg_conn *c = PQconnectdb(DB_URL);
	return c != NULL;
}

STUB int fetch_capabilities(curl_handle *h)
{
	curl_easy_setopt(h, CURLOPT_URL, CAPABILITIES_URL);
	curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, (const char *) 0);
	return curl_easy_setopt(h, 10018, AUTH_HEADER);
}

STUB void disable_tls_checks(ssl_ctx *ctx)
{
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
}

STUB int open_broker_socket(int fd)
{
	struct fixture_sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = 2;
	addr.sin_port = htons(8080);
	inet_pton(2, BROKER_ADDR, &addr.sin_addr);
	return connect(fd, &addr, sizeof(addr));
}

STUB int resolve_tile_hosts(void)
{
	void *res = NULL;
	int rc = getaddrinfo(TILE_HOST, "https", NULL, &res);
	if (rc != 0) {
		rc = getaddrinfo(TILE_HOST_BACKUP, "https", NULL, &res);
	}
	return rc;
}

int main(int argc, char **argv)
{
	(void) argv;
	int rc = open_database();
	rc += fetch_capabilities(NULL);
	disable_tls_checks(NULL);
	rc += open_broker_socket(argc);
	rc += resolve_tile_hosts();
	return rc;
}
