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
import java.util.*;

import externaldependencyanalyzer.ApiTable.ApiEntry;
import externaldependencyanalyzer.DependencyModel.*;
import externaldependencyanalyzer.EndpointClassifier.Candidate;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Read-only recovery of external dependencies from a program. Produces a sorted
 * {@link ScanResult}; writing bookmarks, comments and reports is done elsewhere.
 */
public final class DependencyScanner {
	private static final int MAX_RAW_STRING = 1024;
	private static final int MAX_INDIRECTION = 3;

	private final Program program;
	private final ScanOptions options;
	private final TaskMonitor monitor;
	private final Listing listing;
	private final ReferenceManager refMgr;
	private final FunctionManager funcMgr;
	private final Memory memory;
	private final List<String> warnings = new ArrayList<>();

	private ApiTable apiTable;
	private ArgumentResolver resolver;

	private final Map<Address, CallSiteInfo> callSites = new TreeMap<>();
	private final Map<Address, Set<Address>> callSitesByFunction = new HashMap<>();
	private final Map<Address, EndpointBuilder> endpoints = new TreeMap<>();
	private final List<Finding> findings = new ArrayList<>();

	private record CallSiteInfo(Address address, Function function, ApiEntry api,
			boolean external, List<String> notes) {
	}

	private static final class EndpointBuilder {
		final Address address;
		final Candidate candidate;
		final Set<Address> referencingFunctions = new TreeSet<>();
		final List<String> notes = new ArrayList<>();
		final Map<Address, Address> referenceSites = new TreeMap<>();
		final Map<Address, NetworkCallLink> directLinks = new TreeMap<>();
		NetworkCallLink link;
		Confidence confidence;

		EndpointBuilder(Address address, Candidate candidate) {
			this.address = address;
			this.candidate = candidate;
			this.confidence = candidate.confidence();
			this.notes.addAll(candidate.notes());
		}
	}

	public DependencyScanner(Program program, ScanOptions options, TaskMonitor monitor) {
		this.program = program;
		this.options = options;
		this.monitor = monitor == null ? TaskMonitor.DUMMY : monitor;
		this.listing = program.getListing();
		this.refMgr = program.getReferenceManager();
		this.funcMgr = program.getFunctionManager();
		this.memory = program.getMemory();
	}

	public ScanResult scan() throws CancelledException {
		apiTable = ApiTable.loadOrDefault(options.apiTablePath(), warnings);
		resolver = new ArgumentResolver(program, monitor);
		if (!resolver.supportsRegisterArguments()) {
			warnings.add(
				"Calling convention passes arguments on the stack; argument constants were not recovered");
		}

		monitor.setMessage("External dependencies: API call sites");
		collectApiCallSites();
		monitor.setMessage("External dependencies: strings");
		collectStringEndpoints();
		monitor.setMessage("External dependencies: call arguments");
		recoverCallArguments();
		monitor.setMessage("External dependencies: ports");
		recoverSockaddrPorts();
		monitor.setMessage("External dependencies: linkage");
		linkEndpointsToCalls();
		monitor.setMessage("External dependencies: findings");
		buildFindings();
		return assemble();
	}

	// ---------------------------------------------------------------- API call sites

	private void collectApiCallSites() throws CancelledException {
		if (!options.apiCallSites() || apiTable.size() == 0) {
			return;
		}
		SymbolTable symTab = program.getSymbolTable();
		SymbolIterator externals = symTab.getExternalSymbols();
		while (externals.hasNext()) {
			monitor.checkCancelled();
			Symbol sym = externals.next();
			ApiEntry api = apiTable.lookup(sym.getName());
			if (api == null) {
				continue;
			}
			followReferences(sym.getAddress(), api, true, 0, new HashSet<>());
			if (sym.getObject() instanceof Function f) {
				Address[] thunks = f.getFunctionThunkAddresses(true);
				if (thunks != null) {
					for (Address thunk : thunks) {
						followReferences(thunk, api, true, 0, new HashSet<>());
					}
				}
			}
		}
		FunctionIterator funcs = funcMgr.getFunctions(true);
		while (funcs.hasNext()) {
			monitor.checkCancelled();
			Function f = funcs.next();
			if (f.isExternal()) {
				continue;
			}
			ApiEntry api = apiTable.lookup(f.getName());
			if (api == null) {
				continue;
			}
			if (f.isThunk()) {
				Function thunked = f.getThunkedFunction(true);
				if (thunked != null && thunked.isExternal()) {
					continue;
				}
			}
			followReferences(f.getEntryPoint(), api, false, 0, new HashSet<>());
		}
	}

	private void followReferences(Address target, ApiEntry api, boolean external, int depth,
			Set<Address> visited) throws CancelledException {
		if (depth > MAX_INDIRECTION || !visited.add(target)) {
			return;
		}
		ReferenceIterator it = refMgr.getReferencesTo(target);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Reference ref = it.next();
			Address from = ref.getFromAddress();
			if (!from.isMemoryAddress()) {
				continue;
			}
			Instruction instr = listing.getInstructionAt(from);
			if (instr == null) {
				followReferences(from, api, external, depth + 1, visited);
				continue;
			}
			Function func = funcMgr.getFunctionContaining(from);
			if (func != null && func.isThunk() && func.getEntryPoint().equals(from)) {
				followReferences(func.getEntryPoint(), api, external, depth + 1, visited);
				continue;
			}
			if (func != null && func.isThunk()) {
				followReferences(func.getEntryPoint(), api, external, depth + 1, visited);
				continue;
			}
			List<String> notes = new ArrayList<>();
			RefType type = ref.getReferenceType();
			if (!type.isCall()) {
				if (type.isJump()) {
					notes.add("tail call");
				}
				else if (type.isData() || type.isRead()) {
					notes.add("address taken; call is indirect");
				}
				else {
					continue;
				}
			}
			if (external) {
				notes.add("imported");
			}
			else {
				notes.add("statically linked or stub");
			}
			if (!api.notes().isEmpty()) {
				notes.add(api.notes());
			}
			CallSiteInfo existing = callSites.get(from);
			if (existing == null) {
				callSites.put(from, new CallSiteInfo(from, func, api, external, notes));
				if (func != null) {
					callSitesByFunction.computeIfAbsent(func.getEntryPoint(), k -> new TreeSet<>())
							.add(from);
				}
			}
		}
	}

	// ---------------------------------------------------------------- strings

	private void collectStringEndpoints() throws CancelledException {
		if (!options.endpoints() && !options.connectionStrings() && !options.protocolHints()) {
			return;
		}
		DataIterator data = listing.getDefinedData(true);
		while (data.hasNext()) {
			monitor.checkCancelled();
			Data d = data.next();
			if (!StringDataInstance.isString(d)) {
				continue;
			}
			String value;
			try {
				value = StringDataInstance.getStringDataInstance(d).getStringValue();
			}
			catch (RuntimeException e) {
				continue;
			}
			addStringEndpoint(d.getAddress(), value, null);
		}
	}

	private EndpointBuilder addStringEndpoint(Address addr, String value, String extraNote) {
		if (value == null) {
			return null;
		}
		EndpointBuilder existing = endpoints.get(addr);
		if (existing != null) {
			if (extraNote != null && !existing.notes.contains(extraNote)) {
				existing.notes.add(extraNote);
			}
			return existing;
		}
		List<Candidate> cands = EndpointClassifier.classify(value, options.minStringLength());
		if (cands.isEmpty()) {
			return null;
		}
		Candidate c = cands.get(0);
		if (!categoryEnabled(c.kind())) {
			return null;
		}
		EndpointBuilder b = new EndpointBuilder(addr, c);
		if (extraNote != null) {
			b.notes.add(extraNote);
		}
		collectReferencingFunctions(b, addr, 0, new HashSet<>(), null);
		endpoints.put(addr, b);
		return b;
	}

	private boolean categoryEnabled(EndpointKind kind) {
		switch (kind.category()) {
			case "endpoints":
				return options.endpoints();
			case "connection strings":
				return options.connectionStrings();
			default:
				return options.protocolHints();
		}
	}

	private void collectReferencingFunctions(EndpointBuilder b, Address target, int depth,
			Set<Address> visited, String viaNote) {
		if (depth > MAX_INDIRECTION || !visited.add(target)) {
			return;
		}
		ReferenceIterator it = refMgr.getReferencesTo(target);
		while (it.hasNext()) {
			Reference ref = it.next();
			Address from = ref.getFromAddress();
			if (!from.isMemoryAddress()) {
				continue;
			}
			Function func = funcMgr.getFunctionContaining(from);
			if (listing.getInstructionAt(from) != null) {
				if (func != null) {
					b.referencingFunctions.add(func.getEntryPoint());
					b.referenceSites.putIfAbsent(from, func.getEntryPoint());
					if (viaNote != null && !b.notes.contains(viaNote)) {
						b.notes.add(viaNote);
					}
				}
				continue;
			}
			Data containing = listing.getDataContaining(from);
			String note = "referenced through pointer table at " + from;
			collectReferencingFunctions(b, from, depth + 1, visited, note);
			if (containing != null && !containing.getAddress().equals(from)) {
				collectReferencingFunctions(b, containing.getAddress(), depth + 1, visited, note);
			}
		}
	}

	// ---------------------------------------------------------------- call arguments

	private void recoverCallArguments() throws CancelledException {
		for (CallSiteInfo cs : new ArrayList<>(callSites.values())) {
			monitor.checkCancelled();
			Instruction instr = listing.getInstructionAt(cs.address());
			if (instr == null || cs.function() == null) {
				continue;
			}
			ApiEntry api = cs.api();
			String optionName = null;
			if (api.hasOptionArgument()) {
				ArgumentResolver.Resolved opt = resolver.resolve(instr, cs.function(),
					api.optionArgument());
				if (opt != null) {
					optionName = api.optionValues().get(opt.value());
					if (optionName != null) {
						cs.notes().add("option " + optionName);
					}
				}
			}
			if (api.hasHostArgument()) {
				boolean urlOption = optionName == null || optionName.endsWith("_URL") ||
					optionName.endsWith("_PROXY");
				if (!api.hasOptionArgument() || urlOption) {
					ArgumentResolver.Resolved host = resolver.resolve(instr, cs.function(),
						api.hostArgument());
					Address strAddr = host == null ? null : toMemoryAddress(host.value());
					String s = strAddr == null ? null : readString(strAddr);
					if (s != null) {
						EndpointBuilder b = addStringEndpoint(strAddr, s,
							"passed as argument " + api.hostArgument() + " to " + api.name() +
								" at " + cs.address());
						if (b != null) {
							b.referencingFunctions.add(cs.function().getEntryPoint());
							b.referenceSites.putIfAbsent(cs.address(), cs.function().getEntryPoint());
							b.directLinks.put(cs.address(), new NetworkCallLink(api.name(),
								cs.address().toString(), functionName(cs.function()), !host.pcode()));
							b.confidence = Confidence.HIGH;
						}
					}
					else if (options.findings()) {
						cs.notes().add("endpoint argument not a constant");
					}
				}
				if (optionName != null && (optionName.contains("SSL_VERIFYPEER") ||
					optionName.contains("SSL_VERIFYHOST"))) {
					ArgumentResolver.Resolved v = resolver.resolve(instr, cs.function(),
						api.hostArgument());
					if (v != null && v.value() == 0) {
						addFinding(Severity.HIGH, Rule.TLS_VERIFICATION_DISABLED, cs.address(),
							cs.function(), api.name() + "(" + optionName + ", 0) disables TLS peer verification");
					}
				}
			}
			if (api.hasPortArgument()) {
				ArgumentResolver.Resolved port = resolver.resolve(instr, cs.function(),
					api.portArgument());
				if (port != null && port.value() > 0 && port.value() <= 65535) {
					addPortEndpoint(cs.address(), (int) port.value(), cs.function(),
						"argument to " + api.name(), port.pcode() ? Confidence.HIGH : Confidence.MEDIUM,
						new NetworkCallLink(api.name(), cs.address().toString(),
							functionName(cs.function()), false));
				}
			}
			if (api.hasVerifyModeArgument()) {
				ArgumentResolver.Resolved mode = resolver.resolve(instr, cs.function(),
					api.verifyModeArgument());
				if (mode == null) {
					cs.notes().add("verify mode not a constant");
				}
				else if (mode.value() == 0) {
					cs.notes().add("verify mode 0 (SSL_VERIFY_NONE)");
					addFinding(Severity.HIGH, Rule.TLS_VERIFICATION_DISABLED, cs.address(),
						cs.function(), api.name() + " called with verify mode 0 (SSL_VERIFY_NONE)" +
							(mode.pcode() ? "" : "; recovered by instruction heuristic"));
				}
				else {
					cs.notes().add("verify mode " + mode.value());
				}
			}
		}
	}

	private void addPortEndpoint(Address addr, int port, Function func, String note,
			Confidence confidence, NetworkCallLink link) {
		if (!options.endpoints()) {
			return;
		}
		EndpointBuilder existing = endpoints.get(addr);
		if (existing != null) {
			return;
		}
		String service = WellKnownPorts.NAMES.get(port);
		List<String> notes = new ArrayList<>();
		notes.add(note);
		if (service != null) {
			notes.add("conventional service: " + service);
		}
		Candidate c = new Candidate(EndpointKind.PORT, Integer.toString(port),
			service == null ? "" : service, confidence, notes, null, port, null);
		EndpointBuilder b = new EndpointBuilder(addr, c);
		if (func != null) {
			b.referencingFunctions.add(func.getEntryPoint());
			b.referenceSites.put(addr, func.getEntryPoint());
		}
		b.link = link;
		endpoints.put(addr, b);
	}

	private void recoverSockaddrPorts() throws CancelledException {
		if (!options.endpoints() || !options.portHeuristics()) {
			return;
		}
		Map<Address, CallSiteInfo> sockaddrFunctions = new TreeMap<>();
		for (CallSiteInfo cs : callSites.values()) {
			if (cs.function() != null && cs.api().sockaddr()) {
				sockaddrFunctions.putIfAbsent(cs.function().getEntryPoint(), cs);
			}
		}
		boolean bigEndian = program.getLanguage().isBigEndian();
		for (Map.Entry<Address, CallSiteInfo> fe : sockaddrFunctions.entrySet()) {
			monitor.checkCancelled();
			Address entry = fe.getKey();
			Function func = funcMgr.getFunctionAt(entry);
			if (func == null) {
				continue;
			}
			CallSiteInfo sockaddrCall = fe.getValue();
			NetworkCallLink link = new NetworkCallLink(sockaddrCall.api().name(),
				sockaddrCall.address().toString(), functionName(func), true);
			String apis = apiNamesIn(entry);
			ConstantTracker constants = new ConstantTracker();
			InstructionIterator it = listing.getInstructions(func.getBody(), true);
			while (it.hasNext()) {
				Instruction instr = it.next();
				if (instr.getFlowType().isCall() || instr.getFlowType().isJump()) {
					constants.clear();
					continue;
				}
				constants.nextInstruction();
				for (PcodeOp op : instr.getPcode()) {
					if (op.getOpcode() == PcodeOp.STORE) {
						Varnode stored = op.getInput(2);
						Long value = stored.getSize() == 2 ? constants.valueOf(stored) : null;
						if (value == null) {
							continue;
						}
						long v = value & 0xffff;
						int port = bigEndian ? (int) v : (int) (((v & 0xff) << 8) | (v >> 8));
						if ((bigEndian || v > 0xff) && WellKnownPorts.NAMES.containsKey(port)) {
							addPortEndpoint(instr.getAddress(), port, func,
								"16-bit constant stored in network byte order in a function that calls " +
									apis + " (sockaddr heuristic)",
								Confidence.LOW, link);
						}
						continue;
					}
					constants.apply(op);
				}
			}
		}
	}

	/** Forward propagation of constants through COPY, extension and SUBPIECE PCode within a basic block. */
	private static final class ConstantTracker {
		private final Map<String, Long> registers = new HashMap<>();
		private final Map<String, Long> temporaries = new HashMap<>();

		void clear() {
			registers.clear();
			temporaries.clear();
		}

		void nextInstruction() {
			temporaries.clear();
		}

		Long valueOf(Varnode v) {
			if (v.isConstant()) {
				return v.getOffset();
			}
			return (v.isUnique() ? temporaries : registers).get(key(v));
		}

		void apply(PcodeOp op) {
			Varnode out = op.getOutput();
			if (out == null) {
				return;
			}
			Map<String, Long> target = out.isUnique() ? temporaries : registers;
			Long value = propagated(op);
			if (value == null) {
				target.remove(key(out));
			}
			else {
				target.put(key(out), value);
			}
		}

		private Long propagated(PcodeOp op) {
			int opcode = op.getOpcode();
			if (opcode != PcodeOp.COPY && opcode != PcodeOp.INT_ZEXT &&
				opcode != PcodeOp.INT_SEXT && opcode != PcodeOp.SUBPIECE) {
				return null;
			}
			Long value = valueOf(op.getInput(0));
			if (value == null) {
				return null;
			}
			if (opcode == PcodeOp.SUBPIECE) {
				value = value >>> (8 * op.getInput(1).getOffset());
			}
			int bits = op.getOutput().getSize() * 8;
			return bits >= 64 ? value : value & ((1L << bits) - 1);
		}

		private static String key(Varnode v) {
			return v.getSpace() + ":" + Long.toHexString(v.getOffset());
		}
	}

	private String apiNamesIn(Address functionEntry) {
		Set<String> names = new TreeSet<>();
		for (Address a : callSitesByFunction.getOrDefault(functionEntry, Set.of())) {
			CallSiteInfo cs = callSites.get(a);
			if (cs != null && cs.api().sockaddr()) {
				names.add(cs.api().name());
			}
		}
		return String.join("/", names);
	}

	private static NetworkCallLink chooseDirectLink(Map<Address, NetworkCallLink> candidates) {
		NetworkCallLink first = null;
		for (NetworkCallLink link : candidates.values()) {
			if (!link.heuristic()) {
				return link;
			}
			if (first == null) {
				first = link;
			}
		}
		return first;
	}

	// ---------------------------------------------------------------- linkage

	private void linkEndpointsToCalls() throws CancelledException {
		for (EndpointBuilder b : endpoints.values()) {
			monitor.checkCancelled();
			if (b.link == null && !b.directLinks.isEmpty()) {
				b.link = chooseDirectLink(b.directLinks);
				if (b.directLinks.size() > 1) {
					b.notes.add("passed to " + b.directLinks.size() +
						" call sites; the link shows the first by address");
				}
			}
			if (b.link != null) {
				continue;
			}
			if (b.referencingFunctions.isEmpty()) {
				b.notes.add("no code references");
				b.confidence = lower(b.confidence);
				continue;
			}
			NetworkCallLink best = null;
			long bestDistance = Long.MAX_VALUE;
			for (Map.Entry<Address, Address> site : b.referenceSites.entrySet()) {
				Address refFrom = site.getKey();
				for (Address callAddr : callSitesByFunction.getOrDefault(site.getValue(),
					Set.of())) {
					CallSiteInfo cs = callSites.get(callAddr);
					long distance = Math.abs(callAddr.subtract(refFrom));
					if (callAddr.compareTo(refFrom) < 0) {
						distance += 0x10000;
					}
					if (distance < bestDistance) {
						bestDistance = distance;
						best = new NetworkCallLink(cs.api().name(), callAddr.toString(),
							functionName(cs.function()), true);
					}
				}
			}
			if (best != null) {
				b.link = best;
				b.notes.add("nearest call in same function (heuristic)");
				b.confidence = raise(b.confidence);
				continue;
			}
			for (Address fEntry : b.referencingFunctions) {
				Function f = funcMgr.getFunctionAt(fEntry);
				if (f == null) {
					continue;
				}
				List<Function> callees = new ArrayList<>(f.getCalledFunctions(monitor));
				callees.sort(Comparator.comparing(Function::getEntryPoint));
				for (Function callee : callees) {
					Set<Address> sites = callSitesByFunction.get(callee.getEntryPoint());
					if (sites == null || sites.isEmpty()) {
						continue;
					}
					Address callAddr = sites.iterator().next();
					CallSiteInfo cs = callSites.get(callAddr);
					b.link = new NetworkCallLink(cs.api().name(), callAddr.toString(),
						functionName(cs.function()), true);
					b.notes.add("one hop: " + functionName(f) + " calls " + functionName(callee) +
						" (heuristic)");
					break;
				}
				if (b.link != null) {
					break;
				}
			}
		}
	}

	// ---------------------------------------------------------------- findings

	private void buildFindings() throws CancelledException {
		if (!options.findings()) {
			return;
		}
		Map<String, List<EndpointBuilder>> roles = new TreeMap<>();
		Map<Address, Set<String>> hostsPerFunction = new TreeMap<>();

		for (EndpointBuilder b : endpoints.values()) {
			monitor.checkCancelled();
			Candidate c = b.candidate;
			Function fn = firstFunction(b);
			boolean tlsNearby = hasCallCategoryNearby(b, "tls") || hasProtocolHintNearby(b, "https") ||
				hasProtocolHintNearby(b, "ldaps") || hasProtocolHintNearby(b, "amqps") ||
				hasProtocolHintNearby(b, "mqtts");

			if (b.notes.contains("credential redacted")) {
				addFinding(Severity.HIGH, Rule.HARDCODED_CREDENTIAL, b.address, fn,
					"credential embedded in " + c.kind().jsonName() + " constant (redacted)");
			}
			if (c.scheme() != null && EndpointClassifier.isPlaintextScheme(c.scheme()) &&
				!declaresTls(c.value())) {
				Severity sev = tlsNearby ? Severity.LOW : Severity.MEDIUM;
				addFinding(sev, Rule.PLAINTEXT_PROTOCOL, b.address, fn,
					c.scheme() + ":// scheme does not require transport encryption" +
						(tlsNearby ? "; TLS call site nearby, verify wrapping" : "; no TLS call site in referencing functions"));
			}
			if ((c.kind() == EndpointKind.PORT || c.kind() == EndpointKind.HOST_PORT) &&
				WellKnownPorts.PLAINTEXT.contains(c.port()) && !tlsNearby) {
				addFinding(Severity.LOW, Rule.PLAINTEXT_PORT, b.address, fn,
					"port " + c.port() + " (" + WellKnownPorts.NAMES.getOrDefault(c.port(), "unknown") +
						") is conventionally plaintext; no TLS call site in referencing functions");
			}
			if (c.host() != null && EndpointClassifier.isIpv4Literal(c.host())) {
				if (EndpointClassifier.isPrivateIpv4(c.host())) {
					addFinding(Severity.INFO, Rule.PRIVATE_ADDRESS_EMBEDDED, b.address, fn,
						"private or loopback address " + c.host() +
							" is embedded; deployment network is fixed at build time");
				}
				else {
					addFinding(Severity.LOW, Rule.PUBLIC_ADDRESS_EMBEDDED, b.address, fn,
						"public address " + c.host() + " is embedded; change requires rebuild");
				}
			}
			for (String n : b.notes) {
				if (n.contains("format placeholder")) {
					addFinding(Severity.INFO, Rule.RUNTIME_COMPOSED_ENDPOINT, b.address, fn,
						"endpoint contains a format placeholder; final value is composed at runtime");
					break;
				}
			}
			if (c.host() != null) {
				String roleKey = roleKey(b);
				if (roleKey != null) {
					roles.computeIfAbsent(roleKey, k -> new ArrayList<>()).add(b);
				}
				if (c.kind() == EndpointKind.HOSTNAME || c.kind() == EndpointKind.IPV4 ||
					c.kind() == EndpointKind.IPV6 || c.kind() == EndpointKind.HOST_PORT) {
					for (Address f : b.referencingFunctions) {
						hostsPerFunction.computeIfAbsent(f, k -> new TreeSet<>())
								.add(c.host().toLowerCase(Locale.ROOT));
					}
				}
			}
		}

		for (Map.Entry<String, List<EndpointBuilder>> role : roles.entrySet()) {
			Set<String> hosts = new TreeSet<>();
			for (EndpointBuilder b : role.getValue()) {
				hosts.add(b.candidate.host().toLowerCase(Locale.ROOT));
			}
			if (hosts.size() > 1) {
				EndpointBuilder first = role.getValue().get(0);
				addFinding(Severity.LOW, Rule.DUPLICATE_HOST_CONSTANTS, first.address,
					firstFunction(first), hosts.size() + " host constants share role \"" +
						role.getKey() + "\": " + String.join(", ", hosts) +
						" (possible primary/failover pair or stale endpoint)");
			}
		}
		for (Map.Entry<Address, Set<String>> e : hostsPerFunction.entrySet()) {
			if (e.getValue().size() > 1) {
				Function f = funcMgr.getFunctionAt(e.getKey());
				addFinding(Severity.LOW, Rule.DUPLICATE_HOST_CONSTANTS, e.getKey(), f,
					"function references " + e.getValue().size() + " distinct hosts: " +
						String.join(", ", e.getValue()) + " (possible primary/failover pair)");
			}
		}
		for (CallSiteInfo cs : callSites.values()) {
			if (cs.notes().contains("endpoint argument not a constant")) {
				addFinding(Severity.INFO, Rule.RUNTIME_SUPPLIED_ENDPOINT, cs.address(), cs.function(),
					cs.api().name() + " endpoint argument is not a constant; supplied at runtime (configuration or computed)");
			}
		}
	}

	private static boolean declaresTls(String value) {
		String v = value.toLowerCase(Locale.ROOT);
		return v.contains("sslmode=require") || v.contains("sslmode=verify") ||
			v.contains("ssl=true") || v.contains("usessl=true") || v.contains("tls=true") ||
			v.contains("encrypt=true") || v.contains("security.protocol=ssl") ||
			v.contains("security.protocol=sasl_ssl");
	}

	private String roleKey(EndpointBuilder b) {
		Candidate c = b.candidate;
		if (c.kind() != EndpointKind.URL && c.kind() != EndpointKind.CONNECTION_STRING &&
			c.kind() != EndpointKind.UNC_PATH) {
			return null;
		}
		String v = c.value();
		String tail = "";
		int hostIdx = v.indexOf(c.host());
		if (hostIdx >= 0) {
			String after = v.substring(hostIdx + c.host().length());
			int slash = after.indexOf('/');
			if (slash >= 0) {
				String path = after.substring(slash + 1);
				int end = path.indexOf('?');
				if (end >= 0) {
					path = path.substring(0, end);
				}
				int seg = path.indexOf('/');
				tail = seg >= 0 ? path.substring(0, seg) : path;
			}
		}
		if (tail.isEmpty() && c.port() < 0) {
			return null;
		}
		return c.protocolHint() + "|" + (c.port() < 0 ? "-" : Integer.toString(c.port())) + "|" +
			tail.toLowerCase(Locale.ROOT);
	}

	private boolean hasCallCategoryNearby(EndpointBuilder b, String category)
			throws CancelledException {
		for (Address fEntry : b.referencingFunctions) {
			if (functionHasCategory(fEntry, category)) {
				return true;
			}
			Function f = funcMgr.getFunctionAt(fEntry);
			if (f == null) {
				continue;
			}
			for (Function callee : f.getCalledFunctions(monitor)) {
				if (functionHasCategory(callee.getEntryPoint(), category)) {
					return true;
				}
			}
		}
		return false;
	}

	private boolean functionHasCategory(Address fEntry, String category) {
		for (Address a : callSitesByFunction.getOrDefault(fEntry, Set.of())) {
			CallSiteInfo cs = callSites.get(a);
			if (cs != null && cs.api().category().equals(category)) {
				return true;
			}
		}
		return false;
	}

	private boolean hasProtocolHintNearby(EndpointBuilder b, String hint) {
		for (Address fEntry : b.referencingFunctions) {
			for (Address a : callSitesByFunction.getOrDefault(fEntry, Set.of())) {
				CallSiteInfo cs = callSites.get(a);
				if (cs != null && cs.api().protocolHint().equals(hint)) {
					return true;
				}
			}
		}
		return false;
	}

	private Function firstFunction(EndpointBuilder b) {
		if (b.referencingFunctions.isEmpty()) {
			return null;
		}
		return funcMgr.getFunctionAt(b.referencingFunctions.iterator().next());
	}

	private void addFinding(Severity sev, Rule rule, Address addr, Function fn, String detail) {
		Finding f = new Finding(sev, rule.jsonName(), addr.toString(), fn == null ? "" : functionName(fn),
			Redactor.redact(detail).text());
		if (!findings.contains(f)) {
			findings.add(f);
		}
	}

	// ---------------------------------------------------------------- assembly

	private ScanResult assemble() {
		List<Endpoint> eps = new ArrayList<>();
		for (EndpointBuilder b : endpoints.values()) {
			List<String> funcs = new ArrayList<>();
			for (Address a : b.referencingFunctions) {
				Function f = funcMgr.getFunctionAt(a);
				if (f != null) {
					funcs.add(functionName(f));
				}
			}
			Collections.sort(funcs);
			List<String> notes = new ArrayList<>(new LinkedHashSet<>(b.notes));
			eps.add(new Endpoint(b.candidate.kind(), b.candidate.value(), b.address.toString(),
				Collections.unmodifiableList(funcs), b.link, b.confidence,
				b.candidate.protocolHint(), Collections.unmodifiableList(notes)));
		}
		eps.sort(Endpoint.ORDER);

		List<ApiCallSite> sites = new ArrayList<>();
		for (CallSiteInfo cs : callSites.values()) {
			List<String> notes = new ArrayList<>(new LinkedHashSet<>(cs.notes()));
			sites.add(new ApiCallSite(cs.api().name(), cs.api().category(),
				cs.address().toString(), cs.function() == null ? "" : functionName(cs.function()),
				cs.api().protocolHint(), cs.external(), Collections.unmodifiableList(notes)));
		}
		sites.sort(ApiCallSite.ORDER);

		List<Finding> fs = new ArrayList<>(findings);
		fs.sort(Finding.ORDER);

		List<String> ws = new ArrayList<>(new TreeSet<>(warnings));
		return new ScanResult(programInfo(), Collections.unmodifiableList(eps),
			Collections.unmodifiableList(sites), Collections.unmodifiableList(fs),
			Collections.unmodifiableList(ws));
	}

	private ProgramInfo programInfo() {
		String sha = program.getExecutableSHA256();
		String format = program.getExecutableFormat();
		Address base = program.getImageBase();
		return new ProgramInfo(program.getName(), sha == null ? "" : sha,
			format == null ? "" : format, program.getLanguageID().getIdAsString(),
			base == null ? "" : "0x" + Long.toHexString(base.getOffset()));
	}

	// ---------------------------------------------------------------- helpers

	private static String functionName(Function f) {
		return f.getName(true);
	}

	private Address toMemoryAddress(long value) {
		try {
			AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
			Address a = space.getAddress(value);
			MemoryBlock block = memory.getBlock(a);
			if (block == null || !block.isInitialized()) {
				return null;
			}
			return a;
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	private String readString(Address addr) {
		Data d = listing.getDataContaining(addr);
		if (d != null && StringDataInstance.isString(d) && d.getAddress().equals(addr)) {
			try {
				return StringDataInstance.getStringDataInstance(d).getStringValue();
			}
			catch (RuntimeException e) {
				return null;
			}
		}
		byte[] buf = new byte[MAX_RAW_STRING];
		int n;
		try {
			n = memory.getBytes(addr, buf);
		}
		catch (MemoryAccessException e) {
			return null;
		}
		int len = 0;
		while (len < n && buf[len] != 0) {
			if (buf[len] < 0x20 || buf[len] > 0x7e) {
				return null;
			}
			len++;
		}
		if (len == 0 || len >= n) {
			return null;
		}
		return new String(buf, 0, len, StandardCharsets.US_ASCII);
	}

	private static Confidence lower(Confidence c) {
		switch (c) {
			case HIGH:
				return Confidence.MEDIUM;
			default:
				return Confidence.LOW;
		}
	}

	private static Confidence raise(Confidence c) {
		switch (c) {
			case LOW:
				return Confidence.MEDIUM;
			default:
				return Confidence.HIGH;
		}
	}

	public List<String> getWarnings() {
		return Collections.unmodifiableList(warnings);
	}
}
