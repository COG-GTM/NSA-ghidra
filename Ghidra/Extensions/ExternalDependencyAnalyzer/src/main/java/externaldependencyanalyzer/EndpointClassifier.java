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

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import externaldependencyanalyzer.DependencyModel.Confidence;
import externaldependencyanalyzer.DependencyModel.EndpointKind;

/**
 * Pure-function classification of string constants into endpoint candidates. Has no Ghidra
 * dependencies so it can be unit tested directly.
 */
public final class EndpointClassifier {

	/** Classification of one string. {@code host} and {@code port} are parsed for later analysis. */
	public record Candidate(EndpointKind kind, String value, String protocolHint,
			Confidence confidence, List<String> notes, String host, int port, String scheme) {
	}

	public static final int MAX_STRING_LENGTH = 2048;

	private static final Pattern URL = Pattern.compile(
		"^(?<scheme>[A-Za-z][A-Za-z0-9+.-]{1,15})://(?<rest>[^\\s\"'<>]{1,1024})$");
	private static final Pattern URL_AUTHORITY = Pattern.compile(
		"^(?:[^@/?#]*@)?(?<host>\\[[0-9A-Fa-f:.]+\\]|[^:/?#\\s]+)(?::(?<port>\\d{1,5}))?(?<path>[/?#].*)?$");
	private static final Pattern JDBC =
		Pattern.compile("(?i)^jdbc:(?<sub>[a-z0-9]+):(?<rest>.*)");
	private static final Pattern ORACLE_THIN = Pattern.compile(
		"(?i)^(jdbc:)?oracle:(thin|oci):@(//)?(?<host>[A-Za-z0-9.-]+)(:(?<port>\\d{1,5}))?[:/]?(?<sid>[A-Za-z0-9_.-]*)");
	private static final Pattern IPV4 = Pattern.compile(
		"^(?<ip>(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})(:(?<port>\\d{1,5}))?$");
	private static final Pattern IPV6 = Pattern.compile(
		"^\\[?(?<ip>(?=.*:.*:)[0-9A-Fa-f:]{2,39}(\\.\\d{1,3}){0,3})\\]?(:(?<port>\\d{1,5}))?$");
	private static final Pattern HOSTNAME = Pattern.compile(
		"(?i)^(?<host>(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?<tld>[a-z][a-z0-9-]{1,23}))\\.?(:(?<port>\\d{1,5}))?$");
	private static final Pattern HOST_PORT_LIST = Pattern.compile(
		"^(?<first>[A-Za-z0-9.-]+:\\d{1,5})(,[A-Za-z0-9.-]+:\\d{1,5})+$");
	private static final Pattern UNC = Pattern.compile(
		"^\\\\\\\\(?<host>[A-Za-z0-9._-]+)\\\\(?<share>[^\\\\\\s]+)(\\\\[^\\s]*)?$");
	private static final Pattern NFS_EXPORT = Pattern.compile(
		"^(?<host>(?:[A-Za-z0-9-]+\\.)+[A-Za-z]{2,}|\\d{1,3}(\\.\\d{1,3}){3}):(?<path>/[^\\s:]*)$");
	private static final Pattern UNIX_SHARE = Pattern.compile(
		"^//(?<host>(?:[A-Za-z0-9-]+\\.)+[A-Za-z]{2,}|\\d{1,3}(\\.\\d{1,3}){3})/(?<path>[^\\s]+)$");
	private static final Pattern KEY_VALUE_CONN =
		Pattern.compile("(?i)\\b(host|hostaddr|server|data source|addr|address|hostname)\\s*=\\s*(?<host>[^;\\s,]+)");
	private static final Pattern KEY_VALUE_PORT = Pattern.compile("(?i)\\bport\\s*=\\s*(?<port>\\d{1,5})");
	private static final Pattern KEY_VALUE_DB =
		Pattern.compile("(?i)\\b(dbname|database|initial catalog|db|service_name|sid)\\s*=\\s*[^;\\s,]+");
	private static final Pattern KEY_VALUE_DRIVER = Pattern.compile("(?i)\\bdriver\\s*=\\s*\\{?[^;]+");
	private static final Pattern HTTP_PATH = Pattern.compile(
		"^/(?<first>[A-Za-z0-9_.-]+)(/[A-Za-z0-9_.{}:%-]*)*(\\?[^\\s]*)?$");
	private static final Pattern GRPC_PATH = Pattern.compile(
		"^/[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)*\\.[A-Z][A-Za-z0-9_]*/[A-Z][A-Za-z0-9_]*$");
	private static final Pattern OGC_QUERY = Pattern.compile(
		"(?i)(service=(wms|wfs|wmts|wcs|csw)|request=(GetCapabilities|GetMap|GetFeature|GetTile|GetFeatureInfo|DescribeFeatureType))");
	private static final Pattern LDAP_DN = Pattern.compile(
		"(?i)^(cn|ou|dc|uid|o|c|l|st|dn)=[^,=]{1,128}(,(cn|ou|dc|uid|o|c|l|st)=[^,=]{1,128})+$");
	private static final Pattern REALM = Pattern.compile(
		"^(?<realm>[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+)$");
	private static final Pattern PRINCIPAL = Pattern.compile(
		"^[A-Za-z0-9._/-]{1,64}@(?<realm>[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+)$");
	private static final Pattern HEADER = Pattern.compile(
		"(?i)^(?<name>Authorization|Proxy-Authorization|WWW-Authenticate|X-Api-Key|X-Auth-Token|Api-Key|ApiKey|X-Amz-Security-Token|X-Amz-Date|Ocp-Apim-Subscription-Key|X-Access-Token|X-Client-Secret|X-Auth-Key)(\\s*:\\s*.*)?$");
	private static final Pattern AUTH_SCHEME = Pattern.compile(
		"(?i)^(?<name>Bearer|Basic|Digest|Negotiate|NTLM|ApiKey|Token|AWS4-HMAC-SHA256)(\\s+[^\\s]+)?\\s*$");

	private static final Set<String> CONNECTION_SCHEMES = Set.of("postgresql", "postgres", "pgsql",
		"mysql", "mariadb", "mssql", "sqlserver", "oracle", "mongodb", "mongodb+srv", "redis",
		"rediss", "amqp", "amqps", "mqtt", "mqtts", "kafka", "ssl+kafka", "nats", "tcp", "ssl",
		"zmq", "cassandra", "couchbase", "influxdb", "memcached", "jdbc", "odbc", "sqlite",
		"db2", "informix", "hive", "presto", "trino", "snowflake", "elasticsearch", "neo4j",
		"bolt", "ldap", "ldaps", "ldapi", "grpc", "grpcs", "dns", "smb", "cifs", "nfs", "ftp",
		"ftps", "sftp", "ssh", "telnet", "tftp", "smtp", "smtps", "imap", "imaps", "pop3",
		"pop3s", "ws", "wss", "rtsp", "rtmp", "stomp", "opc.tcp", "modbus", "wms", "wfs");

	private static final Set<String> KNOWN_TLDS = Set.of("com", "net", "org", "gov", "mil",
		"edu", "int", "arpa", "info", "biz", "name", "pro", "io", "co", "ai", "app", "dev",
		"cloud", "tech", "online", "site", "xyz", "us", "uk", "eu", "de", "fr", "ca", "au",
		"jp", "kr", "cn", "in", "br", "mx", "nl", "se", "no", "fi", "dk", "it", "es", "pl",
		"ru", "ch", "at", "be", "ie", "nz", "za", "il", "sg", "hk", "tw", "local", "localhost",
		"localdomain", "internal", "intranet", "lan", "corp", "home", "private", "test",
		"example", "invalid", "onion", "svc", "cluster", "consul", "mesh");

	private static final Set<String> FILE_EXTENSIONS = Set.of("so", "o", "a", "h", "c", "cc",
		"cpp", "cxx", "hpp", "hh", "py", "pyc", "pyd", "js", "ts", "mjs", "md", "rs", "go", "sh",
		"rb", "cs", "txt", "log", "dat", "cfg", "ini", "exe", "dll", "sys", "json", "xml", "yaml",
		"yml", "csv", "pdf", "png", "jpg", "jpeg", "gif", "svg", "ico", "pem", "crt", "cer", "key",
		"der", "p12", "pfx", "jks", "zip", "gz", "tgz", "tar", "bz2", "xz", "zst", "bin", "html",
		"htm", "css", "conf", "lock", "tmp", "bak", "db", "sqlite", "sqlite3", "jar", "class",
		"war", "java", "kt", "gradle", "properties", "toml", "lib", "obj", "def", "map", "inc",
		"in", "out", "err", "pid", "sock", "service", "target", "mo", "po", "ttf", "otf", "woff",
		"woff2", "mp3", "mp4", "wav", "bmp", "tif", "tiff", "dylib", "framework", "plist",
		"desktop", "ninja", "mk", "cmake", "pc", "la", "lo", "s", "asm", "d", "pas", "f90",
		"bat", "cmd", "ps1", "vbs", "reg", "msi", "cab", "hlp", "chm", "rtf", "doc", "docx",
		"xls", "xlsx", "ppt", "pptx", "odt", "ods", "tex", "sty", "bib", "el", "vim", "swp",
		"orig", "rej", "patch", "diff", "asc", "sig", "sum", "md5", "sha1", "sha256", "gpg",
		"pub", "ppk", "cur", "ani", "fon", "scr", "ocx", "drv", "vxd", "cpl", "mui", "manifest",
		"res", "rc", "idl", "tlb", "pdb", "ilk", "exp", "ncb", "sln", "vcxproj", "csproj",
		"proto", "fbs", "thrift", "avsc", "graphql", "gql", "wasm", "wat", "ll", "bc");

	private static final Set<String> FILESYSTEM_ROOTS = Set.of("usr", "etc", "proc", "dev",
		"tmp", "var", "home", "opt", "bin", "sbin", "lib", "lib64", "lib32", "sys", "run", "mnt",
		"media", "srv", "boot", "root", "snap", "System", "Library", "Applications", "Users",
		"private", "Volumes", "cygdrive", "data", "sdcard", "storage", "vendor", "system");

	private static final Set<String> API_PATH_PREFIXES = Set.of("api", "rest", "graphql", "rpc",
		"services", "service", "ws", "wms", "wfs", "wmts", "wcs", "ows", "geoserver", "arcgis",
		"health", "healthz", "readyz", "metrics", "oauth", "oauth2", "token", "login", "auth",
		"authenticate", "connect", "openid-connect", "realms", "tiles", "tile", "mapserver",
		"cgi-bin", "soap", "xmlrpc", "jsonrpc", "swagger", "openapi", "actuator", "status",
		"ping", "version", "_search", "_cluster", "_cat", "solr", "kibana", "grafana",
		"prometheus", "v", "mapbox", "maps", "geocode", "reverse", "featureserver",
		"imageserver");

	private static final Set<String> PLAINTEXT_SCHEMES = Set.of("http", "ftp", "ldap", "telnet",
		"tftp", "ws", "smtp", "pop3", "imap", "mqtt", "amqp", "tcp", "redis", "mongodb", "mysql",
		"postgresql", "postgres", "pgsql", "kafka", "rtsp", "stomp", "nats", "zmq", "modbus",
		"opc.tcp", "grpc", "nfs", "smb", "cifs");

	private static final Set<String> SERVICE_TOKENS = Set.of("getcapabilities", "getmap",
		"getfeature", "getfeatureinfo", "gettile", "describefeaturetype", "describelayer",
		"getlegendgraphic", "bootstrap.servers", "sasl.mechanism", "security.protocol",
		"sasl.jaas.config", "application/grpc", "application/grpc+proto", "grpc-status",
		"grpc-message", "krb5ccname", "krb5_ktname", "krb5.conf", "spnego", "gssapi",
		"sasl_ssl", "sasl_plaintext", "plaintext", "ssl_verify_none", "curlopt_url",
		"curlopt_ssl_verifypeer", "mqtt", "amqp", "kafka", "oracle:thin", "odbc", "jdbc",
		"libpq", "wms", "wfs", "wmts", "ogc", "x-www-form-urlencoded", "application/json",
		"application/soap+xml", "text/xml; charset=utf-8", "soapaction", "oauth2", "openid",
		"client_credentials", "grant_type", "refresh_token", "id_token", "access_token",
		"api_key", "apikey", "x-api-key");

	private static final Map<String, String> SCHEME_ALIASES = Map.ofEntries(
		Map.entry("postgres", "postgresql"), Map.entry("pgsql", "postgresql"),
		Map.entry("mariadb", "mysql"), Map.entry("rediss", "redis"),
		Map.entry("mongodb+srv", "mongodb"), Map.entry("ssl+kafka", "kafka"),
		Map.entry("cifs", "smb"), Map.entry("sqlserver", "mssql"));

	private EndpointClassifier() {
	}

	/**
	 * Classifies a string constant. Returns an empty list when the string does not look like an
	 * external endpoint or protocol hint. The returned {@code value} is already redacted.
	 */
	public static List<Candidate> classify(String raw, int minLength) {
		if (raw == null) {
			return List.of();
		}
		String s = raw.strip();
		if (s.length() < Math.max(minLength, 2) || s.length() > MAX_STRING_LENGTH) {
			return List.of();
		}
		if (s.chars().anyMatch(ch -> ch < 0x20 || ch == 0x7f)) {
			return List.of();
		}
		Candidate c = classifyOne(s);
		return c == null ? List.of() : List.of(c);
	}

	private static Candidate classifyOne(String s) {
		Candidate c = classifyUrl(s);
		if (c != null) {
			return c;
		}
		c = classifyOracleThin(s);
		if (c != null) {
			return c;
		}
		c = classifyKeyValueConnection(s);
		if (c != null) {
			return c;
		}
		c = classifyUnc(s);
		if (c != null) {
			return c;
		}
		c = classifyIp(s);
		if (c != null) {
			return c;
		}
		c = classifyHostPortList(s);
		if (c != null) {
			return c;
		}
		c = classifyLdapDn(s);
		if (c != null) {
			return c;
		}
		c = classifyRealm(s);
		if (c != null) {
			return c;
		}
		c = classifyHostname(s);
		if (c != null) {
			return c;
		}
		c = classifyHeader(s);
		if (c != null) {
			return c;
		}
		c = classifyHttpPath(s);
		if (c != null) {
			return c;
		}
		return classifyServiceHint(s);
	}

	private static Candidate classifyUrl(String s) {
		Matcher m = URL.matcher(s);
		if (!m.matches()) {
			Matcher j = JDBC.matcher(s);
			if (j.matches()) {
				String sub = j.group("sub").toLowerCase(Locale.ROOT);
				if (sub.equals("oracle")) {
					return null;
				}
				String hint = "jdbc/" + SCHEME_ALIASES.getOrDefault(sub, sub);
				String jhost = null;
				int jport = -1;
				String jrest = j.group("rest");
				if (jrest.startsWith("//")) {
					String authority = jrest.substring(2).split(";", 2)[0];
					Matcher a = URL_AUTHORITY.matcher(authority);
					if (a.matches()) {
						jhost = a.group("host");
						jport = parsePort(a.group("port"));
					}
				}
				return make(EndpointKind.CONNECTION_STRING, s, hint, Confidence.HIGH,
					List.of("JDBC URL"), jhost, jport, "jdbc");
			}
			return null;
		}
		String scheme = m.group("scheme").toLowerCase(Locale.ROOT);
		String rest = m.group("rest");
		String host = null;
		int port = -1;
		String path = null;
		Matcher a = URL_AUTHORITY.matcher(rest);
		if (a.matches()) {
			host = a.group("host");
			port = parsePort(a.group("port"));
			path = a.group("path");
		}
		if (scheme.equals("file")) {
			if (host == null || host.isEmpty() || host.equals("localhost")) {
				return null;
			}
			return make(EndpointKind.UNC_PATH, s, "smb", Confidence.MEDIUM,
				List.of("file URL with remote host"), host, port, scheme);
		}
		if (host == null || host.isEmpty() || host.startsWith("%") || host.startsWith("{") ||
			host.startsWith("$")) {
			return make(EndpointKind.URL, s, scheme, Confidence.LOW,
				List.of("host portion is a format placeholder; built at runtime"), null, -1,
				scheme);
		}
		String hint = SCHEME_ALIASES.getOrDefault(scheme, scheme);
		List<String> notes = new ArrayList<>();
		if (rest.contains("%s") || rest.contains("%d") || rest.contains("{}") ||
			rest.contains("{0}")) {
			notes.add("contains format placeholder; part of the endpoint is built at runtime");
		}
		if (path != null && OGC_QUERY.matcher(path).find()) {
			hint = ogcHint(path, hint);
			notes.add("OGC web service request");
		}
		if (scheme.startsWith("jdbc")) {
			return make(EndpointKind.CONNECTION_STRING, s, "jdbc/" + hint, Confidence.HIGH,
				notes, host, port, scheme);
		}
		if (CONNECTION_SCHEMES.contains(scheme) && !scheme.equals("ftp") &&
			!scheme.equals("ftps") && !scheme.equals("sftp") && !scheme.equals("ws") &&
			!scheme.equals("wss") && !scheme.equals("smb") && !scheme.equals("cifs") &&
			!scheme.equals("nfs")) {
			return make(EndpointKind.CONNECTION_STRING, s, hint, Confidence.HIGH, notes, host,
				port, scheme);
		}
		if (scheme.equals("smb") || scheme.equals("cifs") || scheme.equals("nfs")) {
			return make(EndpointKind.UNC_PATH, s, hint, Confidence.HIGH, notes, host, port,
				scheme);
		}
		return make(EndpointKind.URL, s, hint, Confidence.HIGH, notes, host, port, scheme);
	}

	private static String ogcHint(String path, String dflt) {
		String p = path.toLowerCase(Locale.ROOT);
		for (String svc : new String[] { "wmts", "wms", "wfs", "wcs", "csw" }) {
			if (p.contains("service=" + svc)) {
				return "ogc/" + svc;
			}
		}
		return "ogc/" + dflt;
	}

	private static Candidate classifyOracleThin(String s) {
		Matcher m = ORACLE_THIN.matcher(s);
		if (!m.find()) {
			return null;
		}
		return make(EndpointKind.CONNECTION_STRING, s, "oracle", Confidence.HIGH,
			List.of("Oracle thin/OCI descriptor"), m.group("host"), parsePort(m.group("port")),
			"oracle");
	}

	private static Candidate classifyKeyValueConnection(String s) {
		if (!s.contains("=")) {
			return null;
		}
		Matcher h = KEY_VALUE_CONN.matcher(s);
		boolean hasHost = h.find();
		boolean hasDb = KEY_VALUE_DB.matcher(s).find();
		boolean hasDriver = KEY_VALUE_DRIVER.matcher(s).find();
		boolean hasPort = KEY_VALUE_PORT.matcher(s).find();
		int score = (hasHost ? 1 : 0) + (hasDb ? 1 : 0) + (hasDriver ? 1 : 0) + (hasPort ? 1 : 0);
		if (score < 2) {
			return null;
		}
		String host = hasHost ? h.group("host") : null;
		int port = -1;
		Matcher p = KEY_VALUE_PORT.matcher(s);
		if (p.find()) {
			port = parsePort(p.group("port"));
		}
		String hint = hasDriver || s.contains(";") ? "odbc" : "libpq";
		if (s.toLowerCase(Locale.ROOT).contains("bootstrap.servers")) {
			hint = "kafka";
		}
		return make(EndpointKind.CONNECTION_STRING, s, hint, Confidence.MEDIUM,
			List.of("key=value connection string"), host, port, hint);
	}

	private static Candidate classifyUnc(String s) {
		Matcher m = UNC.matcher(s);
		if (m.matches()) {
			String host = m.group("host");
			if (host.equals("?") || host.equals(".")) {
				return null;
			}
			return make(EndpointKind.UNC_PATH, s, "smb", Confidence.HIGH, List.of("UNC path"),
				host, -1, "smb");
		}
		m = NFS_EXPORT.matcher(s);
		if (m.matches()) {
			return make(EndpointKind.UNC_PATH, s, "nfs", Confidence.MEDIUM,
				List.of("host:/export form"), m.group("host"), -1, "nfs");
		}
		m = UNIX_SHARE.matcher(s);
		if (m.matches()) {
			return make(EndpointKind.UNC_PATH, s, "smb", Confidence.MEDIUM,
				List.of("//host/share form"), m.group("host"), -1, "smb");
		}
		return null;
	}

	private static Candidate classifyIp(String s) {
		Matcher m = IPV4.matcher(s);
		if (m.matches()) {
			String ip = m.group("ip");
			int port = parsePort(m.group("port"));
			List<String> notes = new ArrayList<>();
			Confidence conf = Confidence.HIGH;
			if (ip.equals("0.0.0.0")) {
				notes.add("wildcard address");
				conf = Confidence.LOW;
			}
			else if (looksLikeVersion(ip)) {
				notes.add("all octets small; may be a version string");
				conf = Confidence.LOW;
			}
			if (port >= 0) {
				return make(EndpointKind.HOST_PORT, s, WellKnownPorts.protocolHint(port), conf,
					notes, ip, port, null);
			}
			return make(EndpointKind.IPV4, s, "", conf, notes, ip, -1, null);
		}
		m = IPV6.matcher(s);
		if (m.matches() && isPlausibleIpv6(m.group("ip"))) {
			String ip = m.group("ip");
			int port = s.startsWith("[") ? parsePort(m.group("port")) : -1;
			List<String> notes = new ArrayList<>();
			Confidence conf = Confidence.MEDIUM;
			if (ip.equals("::") || ip.equals("::1") || ip.equals("0:0:0:0:0:0:0:0") ||
				ip.equals("0:0:0:0:0:0:0:1")) {
				notes.add("loopback or wildcard address");
				conf = Confidence.LOW;
			}
			if (port >= 0) {
				return make(EndpointKind.HOST_PORT, s, WellKnownPorts.protocolHint(port), conf,
					notes, "[" + ip + "]", port, null);
			}
			return make(EndpointKind.IPV6, s, "", conf, notes, ip, -1, null);
		}
		return null;
	}

	private static boolean looksLikeVersion(String ip) {
		for (String o : ip.split("\\.")) {
			if (Integer.parseInt(o) > 9) {
				return false;
			}
		}
		return true;
	}

	static boolean isPlausibleIpv6(String ip) {
		int doubleColon = ip.indexOf("::");
		if (doubleColon >= 0 && ip.indexOf("::", doubleColon + 1) >= 0) {
			return false;
		}
		String[] groups = ip.split(":", -1);
		if (groups.length < 3 || groups.length > 8) {
			return false;
		}
		int nonEmpty = 0;
		for (String g : groups) {
			if (g.isEmpty()) {
				continue;
			}
			nonEmpty++;
			if (g.contains(".")) {
				continue;
			}
			if (g.length() > 4 || !g.chars().allMatch(ch -> Character.digit(ch, 16) >= 0)) {
				return false;
			}
		}
		if (doubleColon < 0 && groups.length != 8) {
			return false;
		}
		return nonEmpty >= 1;
	}

	private static Candidate classifyHostPortList(String s) {
		Matcher m = HOST_PORT_LIST.matcher(s);
		if (!m.matches()) {
			return null;
		}
		String first = m.group("first");
		int colon = first.lastIndexOf(':');
		return make(EndpointKind.CONNECTION_STRING, s, "kafka", Confidence.MEDIUM,
			List.of("comma-separated host:port list (broker bootstrap form)"),
			first.substring(0, colon), parsePort(first.substring(colon + 1)), "kafka");
	}

	private static Candidate classifyHostname(String s) {
		Matcher m = HOSTNAME.matcher(s);
		if (!m.matches()) {
			if (s.equalsIgnoreCase("localhost")) {
				return make(EndpointKind.HOSTNAME, s, "", Confidence.LOW,
					List.of("loopback name"), s, -1, null);
			}
			return null;
		}
		String host = m.group("host");
		String tld = m.group("tld").toLowerCase(Locale.ROOT);
		if (FILE_EXTENSIONS.contains(tld)) {
			return null;
		}
		String[] labels = host.split("\\.");
		if (labels.length < 2 || host.length() > 253) {
			return null;
		}
		boolean allNumericExceptTld = true;
		for (int i = 0; i < labels.length - 1; i++) {
			if (!labels[i].chars().allMatch(Character::isDigit)) {
				allNumericExceptTld = false;
				break;
			}
		}
		if (allNumericExceptTld) {
			return null;
		}
		Confidence conf;
		List<String> notes = new ArrayList<>();
		if (KNOWN_TLDS.contains(tld)) {
			conf = labels.length >= 3 ? Confidence.HIGH : Confidence.MEDIUM;
		}
		else if (tld.length() == 2 && labels.length >= 3) {
			conf = Confidence.MEDIUM;
			notes.add("two-letter top-level label");
		}
		else if (labels.length >= 3 && !host.matches("(?i)^(com|org|net|io|java|javax|sun|jdk|android|kotlin|scala|google|apache|microsoft)\\..*")) {
			conf = Confidence.LOW;
			notes.add("unrecognised top-level label");
		}
		else {
			return null;
		}
		if (host.toLowerCase(Locale.ROOT).startsWith("www.")) {
			notes.add("web host");
		}
		int port = parsePort(m.group("port"));
		if (port >= 0) {
			return make(EndpointKind.HOST_PORT, s, WellKnownPorts.protocolHint(port), conf, notes,
				host, port, null);
		}
		return make(EndpointKind.HOSTNAME, s, "", conf, notes, host, -1, null);
	}

	private static Candidate classifyLdapDn(String s) {
		if (!LDAP_DN.matcher(s).matches()) {
			return null;
		}
		return make(EndpointKind.LDAP_DN, s, "ldap", Confidence.MEDIUM,
			List.of("LDAP distinguished name"), null, -1, "ldap");
	}

	private static Candidate classifyRealm(String s) {
		Matcher m = PRINCIPAL.matcher(s);
		if (m.matches()) {
			return make(EndpointKind.KERBEROS_REALM, s, "kerberos", Confidence.MEDIUM,
				List.of("principal with upper-case realm"), m.group("realm"), -1, "kerberos");
		}
		m = REALM.matcher(s);
		if (m.matches()) {
			String realm = m.group("realm");
			String tld = realm.substring(realm.lastIndexOf('.') + 1).toLowerCase(Locale.ROOT);
			if (FILE_EXTENSIONS.contains(tld) || !KNOWN_TLDS.contains(tld) ||
				realm.chars().noneMatch(Character::isLetter)) {
				return null;
			}
			return make(EndpointKind.KERBEROS_REALM, s, "kerberos", Confidence.LOW,
				List.of("upper-case domain literal; may also be a hostname"), realm, -1,
				"kerberos");
		}
		return null;
	}

	private static Candidate classifyHeader(String s) {
		Matcher m = HEADER.matcher(s);
		if (m.matches()) {
			return make(EndpointKind.HEADER_CONSTANT, s, "http-auth", Confidence.HIGH,
				List.of("HTTP authentication header"), null, -1, null);
		}
		m = AUTH_SCHEME.matcher(s);
		if (m.matches()) {
			return make(EndpointKind.HEADER_CONSTANT, s, "http-auth", Confidence.MEDIUM,
				List.of("HTTP authentication scheme"), null, -1, null);
		}
		return null;
	}

	private static Candidate classifyHttpPath(String s) {
		if (GRPC_PATH.matcher(s).matches()) {
			return make(EndpointKind.HTTP_PATH, s, "grpc", Confidence.MEDIUM,
				List.of("gRPC method path"), null, -1, null);
		}
		Matcher m = HTTP_PATH.matcher(s);
		if (!m.matches()) {
			return null;
		}
		String first = m.group("first");
		if (FILESYSTEM_ROOTS.contains(first)) {
			return null;
		}
		String lower = first.toLowerCase(Locale.ROOT);
		boolean ogc = OGC_QUERY.matcher(s).find();
		boolean versioned = lower.matches("v\\d{1,3}(\\.\\d{1,3})*");
		if (ogc) {
			return make(EndpointKind.HTTP_PATH, s, ogcHint(s, "http"), Confidence.MEDIUM,
				List.of("OGC web service request path"), null, -1, null);
		}
		if (API_PATH_PREFIXES.contains(lower) || versioned) {
			return make(EndpointKind.HTTP_PATH, s, "http", Confidence.LOW,
				List.of("HTTP path constant; host is supplied elsewhere"), null, -1, null);
		}
		return null;
	}

	private static Candidate classifyServiceHint(String s) {
		String lower = s.toLowerCase(Locale.ROOT);
		if (SERVICE_TOKENS.contains(lower)) {
			return make(EndpointKind.SERVICE_HINT, s, serviceHintProtocol(lower),
				Confidence.LOW, List.of("protocol keyword"), null, -1, null);
		}
		if (lower.startsWith("bootstrap.servers=") || lower.startsWith("sasl.") ||
			lower.startsWith("security.protocol=")) {
			return make(EndpointKind.SERVICE_HINT, s, "kafka", Confidence.MEDIUM,
				List.of("Kafka client property"), null, -1, null);
		}
		if (lower.startsWith("driver={") || lower.startsWith("dsn=")) {
			return make(EndpointKind.SERVICE_HINT, s, "odbc", Confidence.MEDIUM,
				List.of("ODBC connection attribute"), null, -1, null);
		}
		if (s.contains("=") && OGC_QUERY.matcher(s).find()) {
			return make(EndpointKind.SERVICE_HINT, s, ogcHint(s, "ogc"), Confidence.MEDIUM,
				List.of("OGC web service query fragment"), null, -1, null);
		}
		return null;
	}

	private static String serviceHintProtocol(String token) {
		if (token.startsWith("get") || token.startsWith("describe") || token.equals("wms") ||
			token.equals("wfs") || token.equals("wmts") || token.equals("ogc")) {
			return "ogc";
		}
		if (token.contains("grpc")) {
			return "grpc";
		}
		if (token.contains("krb") || token.equals("spnego") || token.equals("gssapi")) {
			return "kerberos";
		}
		if (token.contains("sasl") || token.equals("bootstrap.servers") ||
			token.equals("kafka") || token.equals("plaintext")) {
			return "kafka";
		}
		if (token.equals("mqtt") || token.equals("amqp")) {
			return token;
		}
		if (token.contains("oracle") || token.equals("odbc") || token.equals("jdbc") ||
			token.equals("libpq")) {
			return token.contains("oracle") ? "oracle" : token;
		}
		if (token.contains("ssl") || token.contains("curlopt")) {
			return "tls";
		}
		if (token.contains("soap")) {
			return "soap";
		}
		return "http-auth";
	}

	private static Candidate make(EndpointKind kind, String value, String hint,
			Confidence confidence, List<String> notes, String host, int port, String scheme) {
		Redactor.Result r = Redactor.redact(value);
		List<String> n = new ArrayList<>(notes);
		if (r.redacted()) {
			n.add("credential redacted");
		}
		return new Candidate(kind, r.text(), hint == null ? "" : hint, confidence,
			Collections.unmodifiableList(n), host, port, scheme);
	}

	static int parsePort(String s) {
		if (s == null || s.isEmpty()) {
			return -1;
		}
		try {
			int p = Integer.parseInt(s);
			return p >= 0 && p <= 65535 ? p : -1;
		}
		catch (NumberFormatException e) {
			return -1;
		}
	}

	/** True for schemes that carry data without transport encryption. */
	public static boolean isPlaintextScheme(String scheme) {
		return scheme != null && PLAINTEXT_SCHEMES.contains(scheme.toLowerCase(Locale.ROOT));
	}

	/** RFC 1918, loopback, link-local and CGNAT ranges. */
	public static boolean isPrivateIpv4(String ip) {
		if (ip == null || !IPV4.matcher(ip).matches()) {
			return false;
		}
		String[] o = ip.split("\\.");
		int a = Integer.parseInt(o[0]);
		int b = Integer.parseInt(o[1]);
		return a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) ||
			a == 127 || (a == 169 && b == 254) || (a == 100 && b >= 64 && b <= 127) || a == 0;
	}

	public static boolean isIpv4Literal(String s) {
		return s != null && IPV4.matcher(s).matches() && !s.contains(":");
	}
}
