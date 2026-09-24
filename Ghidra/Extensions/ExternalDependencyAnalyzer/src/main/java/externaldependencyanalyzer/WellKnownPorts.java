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

import java.util.Map;
import java.util.Set;

/** Conventional service names for TCP ports, and the subset that is plaintext by convention. */
public final class WellKnownPorts {

	public static final Set<Integer> PLAINTEXT = Set.of(21, 23, 25, 80, 110, 139, 143, 389, 445,
		1433, 1521, 1883, 2049, 3306, 5432, 5672, 6379, 8080, 9092, 27017);

	public static final Map<Integer, String> NAMES = Map.ofEntries(Map.entry(20, "ftp-data"),
		Map.entry(21, "ftp"), Map.entry(22, "ssh"), Map.entry(23, "telnet"), Map.entry(25, "smtp"),
		Map.entry(53, "dns"), Map.entry(69, "tftp"), Map.entry(80, "http"), Map.entry(88, "kerberos"),
		Map.entry(110, "pop3"), Map.entry(123, "ntp"), Map.entry(135, "msrpc"),
		Map.entry(137, "netbios"), Map.entry(139, "netbios-ssn"), Map.entry(143, "imap"),
		Map.entry(161, "snmp"), Map.entry(389, "ldap"), Map.entry(443, "https"),
		Map.entry(445, "smb"), Map.entry(464, "kpasswd"), Map.entry(465, "smtps"),
		Map.entry(514, "syslog"), Map.entry(554, "rtsp"), Map.entry(587, "submission"),
		Map.entry(636, "ldaps"), Map.entry(749, "kadmin"), Map.entry(873, "rsync"),
		Map.entry(989, "ftps-data"), Map.entry(990, "ftps"), Map.entry(993, "imaps"),
		Map.entry(995, "pop3s"), Map.entry(1080, "socks"), Map.entry(1433, "mssql"),
		Map.entry(1521, "oracle"), Map.entry(1883, "mqtt"), Map.entry(2049, "nfs"),
		Map.entry(2181, "zookeeper"), Map.entry(2379, "etcd"), Map.entry(3128, "http-proxy"),
		Map.entry(3268, "ldap-gc"), Map.entry(3269, "ldaps-gc"), Map.entry(3306, "mysql"),
		Map.entry(3389, "rdp"), Map.entry(4443, "https-alt"), Map.entry(5000, "http-alt"),
		Map.entry(5044, "beats"), Map.entry(5432, "postgresql"), Map.entry(5601, "kibana"),
		Map.entry(5671, "amqps"), Map.entry(5672, "amqp"), Map.entry(5900, "vnc"),
		Map.entry(5984, "couchdb"), Map.entry(5985, "winrm"), Map.entry(5986, "winrm-https"),
		Map.entry(6379, "redis"), Map.entry(6443, "kube-api"), Map.entry(8000, "http-alt"),
		Map.entry(8008, "http-alt"), Map.entry(8080, "http-alt"), Map.entry(8081, "http-alt"),
		Map.entry(8086, "influxdb"), Map.entry(8088, "http-alt"), Map.entry(8443, "https-alt"),
		Map.entry(8500, "consul"), Map.entry(8883, "mqtts"), Map.entry(8888, "http-alt"),
		Map.entry(9000, "http-alt"), Map.entry(9042, "cassandra"), Map.entry(9090, "http-alt"),
		Map.entry(9092, "kafka"), Map.entry(9093, "kafka-tls"), Map.entry(9200, "elasticsearch"),
		Map.entry(9300, "elasticsearch-transport"), Map.entry(9418, "git"),
		Map.entry(9443, "https-alt"), Map.entry(11211, "memcached"), Map.entry(15672, "rabbitmq-mgmt"),
		Map.entry(27017, "mongodb"), Map.entry(50000, "db2"), Map.entry(61616, "activemq"));

	private WellKnownPorts() {
	}

	/** Protocol hint for a port, or an empty string when the port has no conventional service. */
	public static String protocolHint(int port) {
		return NAMES.getOrDefault(port, "");
	}
}
