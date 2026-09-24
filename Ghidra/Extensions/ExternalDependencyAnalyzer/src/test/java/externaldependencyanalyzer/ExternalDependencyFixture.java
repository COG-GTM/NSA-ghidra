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
package externaldependencyanalyzer;

import java.nio.charset.StandardCharsets;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.ToyProgramBuilder;

public class ExternalDependencyFixture {

	public static final String CONNECT_DB_ADDRESS = "0x1004";
	public static final String CALL_API_ADDRESS = "0x1044";
	public static final String SEND_QUEUE_ADDRESS = "0x1084";
	public static final String TLS_HELPER_ADDRESS = "0x10c4";
	public static final String TLS_THUNK_ADDRESS = "0x1104";
	public static final String SSL_CONNECT_SECOND_ADDRESS = "0x10c8";
	public static final String SSL_CONNECT_THUNK_CALL_ADDRESS = "0x105c";
	public static final String HTTP_URL_INTERIOR_ADDRESS = "0x1094";

	public static final String DB_HOST_ADDRESS = "0x2000";
	public static final String MQ_HOST_ADDRESS = "0x2080";
	public static final String HTTP_URL_ADDRESS = "0x2100";
	public static final String PORT_5432_ADDRESS = "0x2180";
	public static final String PORT_8443_ADDRESS = "0x2200";
	public static final String PORT_5672_ADDRESS = "0x2280";
	public static final String JDBC_ADDRESS = "0x2300";
	public static final String AUTHORIZATION_ADDRESS = "0x2380";
	public static final String API_KEY_ADDRESS = "0x2400";
	public static final String IPV4_ADDRESS = "0x2480";
	public static final String AMQPS_ADDRESS = "0x2500";
	public static final String UNUSED_ADDRESS = "0x2580";

	public static final String DB_HOST = "db.internal.example.com";
	public static final String MQ_HOST = "mq.example.com";
	public static final String HTTP_URL = "https://api.example.com/v1/orders";
	public static final String PORT_5432 = ":5432";
	public static final String PORT_8443 = ":8443";
	public static final String PORT_5672 = ":5672";
	public static final String JDBC =
		"jdbc:postgresql://db.internal.example.com:5432/appdb?user=svc&password=REDACTME";
	public static final String AUTHORIZATION = "Authorization: Bearer FAKE-TOKEN-0000";
	public static final String API_KEY = "X-Api-Key: FAKE-API-KEY-0000";
	public static final String IPV4 = "192.0.2.10:8443";
	public static final String AMQPS = "amqps://mq.example.com:5672/vhost";
	public static final String UNUSED = "unused.example.com";

	private final ToyProgramBuilder builder;
	private final Program program;

	public ExternalDependencyFixture() throws Exception {
		builder = new ToyProgramBuilder("ExternalDependencyFixture", true);
		program = builder.getProgram();
		build();
	}

	private void build() throws Exception {
		builder.createMemory(".text", "0x1000", 0x1000);
		builder.createMemory(".data", "0x2000", 0x1000);
		Function tlsHelper = builder.createEmptyFunction("tls_helper", "0x10c0", 0x20, null);
		builder.createEmptyFunction("connect_db", "0x1000", 0x40, null);
		builder.createEmptyFunction("call_api", "0x1040", 0x40, null);
		builder.createEmptyFunction("send_queue", "0x1080", 0x40, null);
		builder.tx(() -> program.getFunctionManager().createThunkFunction("tls_thunk",
			program.getGlobalNamespace(), builder.addr("0x1100"),
			new AddressSet(builder.addr("0x1100"), builder.addr("0x110f")), tlsHelper,
			SourceType.USER_DEFINED));

		builder.createString(DB_HOST_ADDRESS, DB_HOST, StandardCharsets.US_ASCII, true,
			StringDataType.dataType);
		builder.createString(MQ_HOST_ADDRESS, MQ_HOST, StandardCharsets.US_ASCII, true,
			StringDataType.dataType);
		builder.createString(HTTP_URL_ADDRESS, HTTP_URL, StandardCharsets.US_ASCII, true,
			StringDataType.dataType);
		builder.createString(PORT_5432_ADDRESS, PORT_5432, StandardCharsets.US_ASCII, true,
			StringDataType.dataType);
		builder.createString(PORT_8443_ADDRESS, PORT_8443, StandardCharsets.US_ASCII, true,
			StringDataType.dataType);
		builder.createString(PORT_5672_ADDRESS, PORT_5672, StandardCharsets.US_ASCII, true,
			StringDataType.dataType);
		builder.createString(JDBC_ADDRESS, JDBC, StandardCharsets.US_ASCII, true,
			StringDataType.dataType);
		builder.createString(AUTHORIZATION_ADDRESS, AUTHORIZATION, StandardCharsets.US_ASCII, true,
			StringDataType.dataType);
		builder.createString(API_KEY_ADDRESS, API_KEY, StandardCharsets.US_ASCII, true,
			StringDataType.dataType);
		builder.createString(IPV4_ADDRESS, IPV4, StandardCharsets.US_ASCII, true,
			StringDataType.dataType);
		builder.createString(AMQPS_ADDRESS, AMQPS, StandardCharsets.US_ASCII, true,
			StringDataType.dataType);
		builder.createString(UNUSED_ADDRESS, UNUSED, StandardCharsets.US_ASCII, true,
			StringDataType.dataType);

		builder.createMemoryReadReference("0x1004", JDBC_ADDRESS);
		builder.createMemoryReadReference("0x1008", DB_HOST_ADDRESS);
		builder.createMemoryReadReference("0x100c", PORT_5432_ADDRESS);
		builder.createMemoryReadReference("0x1044", HTTP_URL_ADDRESS);
		builder.createMemoryReadReference("0x1048", AUTHORIZATION_ADDRESS);
		builder.createMemoryReadReference("0x104c", API_KEY_ADDRESS);
		builder.createMemoryReadReference("0x1050", PORT_8443_ADDRESS);
		builder.createMemoryReadReference("0x1054", IPV4_ADDRESS);
		builder.createMemoryReadReference("0x1084", MQ_HOST_ADDRESS);
		builder.createMemoryReadReference("0x1088", PORT_5672_ADDRESS);
		builder.createMemoryReadReference("0x108c", AMQPS_ADDRESS);
		builder.createMemoryReadReference("0x1090", HTTP_URL_ADDRESS);
		builder.createMemoryReadReference(HTTP_URL_INTERIOR_ADDRESS, "0x2108");
		builder.createMemoryReadReference("0x1104", AUTHORIZATION_ADDRESS);

		ExternalLocation sslConnectExtLoc =
			builder.createExternalFunction(null, "libssl.so.3", "SSL_connect");
		builder.createExternalFunction(null, "libssl.so.3", "SSL_CTX_new");
		builder.createExternalFunction(null, "libpq.so.5", "db_connect_renamed", "PQconnectdb");
		builder.createExternalFunction(null, "libc.so.6", "getaddrinfo");
		builder.tx(() -> program.getFunctionManager().createThunkFunction(null,
			program.getGlobalNamespace(), builder.addr("0x1110"),
			new AddressSet(builder.addr("0x1110"), builder.addr("0x111f")),
			sslConnectExtLoc.getFunction(), SourceType.IMPORTED));
		builder.createExternalReference("0x10c4", "libssl.so.3", "SSL_connect", 0);
		builder.createExternalReference("0x1108", "libssl.so.3", "SSL_CTX_new", 0);
		builder.createExternalReference("0x1010", "libpq.so.5", "db_connect_renamed", 0);
		builder.createExternalReference("0x1058", "libc.so.6", "getaddrinfo", 0);
		builder.createExternalReference("0x10c8", "libssl.so.3", "SSL_connect", 0);
		builder.createMemoryCallReference(SSL_CONNECT_THUNK_CALL_ADDRESS, "0x1110");
	}

	public Program getProgram() {
		return program;
	}

	public ToyProgramBuilder getBuilder() {
		return builder;
	}

	public void dispose() {
		builder.dispose();
	}
}
