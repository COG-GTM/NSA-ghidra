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

/** Analyzer options as a plain value so the scanner can run outside the analyzer framework. */
public record ScanOptions(boolean endpoints, boolean connectionStrings, boolean protocolHints,
		boolean apiCallSites, boolean findings, boolean portHeuristics, int minStringLength,
		String apiTablePath, boolean writeComments, boolean writeBookmarks) {

	public static final int DEFAULT_MIN_STRING_LENGTH = 6;

	public static ScanOptions defaults() {
		return new ScanOptions(true, true, true, true, true, true, DEFAULT_MIN_STRING_LENGTH, "",
			true, true);
	}

	public ScanOptions withMinStringLength(int n) {
		return new ScanOptions(endpoints, connectionStrings, protocolHints, apiCallSites, findings,
			portHeuristics, n, apiTablePath, writeComments, writeBookmarks);
	}

	public ScanOptions withApiTablePath(String path) {
		return new ScanOptions(endpoints, connectionStrings, protocolHints, apiCallSites, findings,
			portHeuristics, minStringLength, path, writeComments, writeBookmarks);
	}

	public ScanOptions withWriteComments(boolean v) {
		return new ScanOptions(endpoints, connectionStrings, protocolHints, apiCallSites, findings,
			portHeuristics, minStringLength, apiTablePath, v, writeBookmarks);
	}

	public ScanOptions withWriteBookmarks(boolean v) {
		return new ScanOptions(endpoints, connectionStrings, protocolHints, apiCallSites, findings,
			portHeuristics, minStringLength, apiTablePath, writeComments, v);
	}

	public ScanOptions withCategories(boolean endpointsOn, boolean connectionStringsOn,
			boolean protocolHintsOn, boolean apiCallSitesOn, boolean findingsOn) {
		return new ScanOptions(endpointsOn, connectionStringsOn, protocolHintsOn, apiCallSitesOn,
			findingsOn, portHeuristics, minStringLength, apiTablePath, writeComments,
			writeBookmarks);
	}
}
