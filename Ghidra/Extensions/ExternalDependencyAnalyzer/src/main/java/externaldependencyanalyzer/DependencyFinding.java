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

import java.util.Objects;

import ghidra.program.model.address.Address;

public final class DependencyFinding implements Comparable<DependencyFinding> {

	private final DependencyCategory category;
	private final String kind;
	private final String matchedValue;
	private final String library;
	private final Address indicatorAddress;
	private final Address fromAddress;
	private final String functionName;
	private final boolean viaThunk;

	public DependencyFinding(DependencyCategory category, String kind, String matchedValue, String library,
			Address indicatorAddress, Address fromAddress, String functionName, boolean viaThunk) {
		this.category = category;
		this.kind = kind;
		this.matchedValue = matchedValue;
		this.library = library;
		this.indicatorAddress = indicatorAddress;
		this.fromAddress = fromAddress;
		this.functionName = functionName;
		this.viaThunk = viaThunk;
	}

	public DependencyCategory getCategory() {
		return category;
	}

	public String getKind() {
		return kind;
	}

	public String getMatchedValue() {
		return matchedValue;
	}

	public String getLibrary() {
		return library;
	}

	public Address getIndicatorAddress() {
		return indicatorAddress;
	}

	public Address getFromAddress() {
		return fromAddress;
	}

	public String getFunctionName() {
		return functionName;
	}

	public boolean isViaThunk() {
		return viaThunk;
	}

	@Override
	public int compareTo(DependencyFinding other) {
		int result = fromAddress.compareTo(other.fromAddress);
		if (result != 0) {
			return result;
		}
		result = category.getId().compareTo(other.category.getId());
		if (result != 0) {
			return result;
		}
		result = matchedValue.compareTo(other.matchedValue);
		if (result != 0) {
			return result;
		}
		result = kind.compareTo(other.kind);
		if (result != 0) {
			return result;
		}
		result = indicatorAddress.compareTo(other.indicatorAddress);
		if (result != 0) {
			return result;
		}
		result = compareNullable(library, other.library);
		if (result != 0) {
			return result;
		}
		result = compareNullable(functionName, other.functionName);
		if (result != 0) {
			return result;
		}
		return Boolean.compare(viaThunk, other.viaThunk);
	}

	private static int compareNullable(String left, String right) {
		if (left == null) {
			return right == null ? 0 : -1;
		}
		if (right == null) {
			return 1;
		}
		return left.compareTo(right);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof DependencyFinding other)) {
			return false;
		}
		return viaThunk == other.viaThunk && category == other.category &&
			Objects.equals(kind, other.kind) && Objects.equals(matchedValue, other.matchedValue) &&
			Objects.equals(library, other.library) &&
			Objects.equals(indicatorAddress, other.indicatorAddress) &&
			Objects.equals(fromAddress, other.fromAddress) &&
			Objects.equals(functionName, other.functionName);
	}

	@Override
	public int hashCode() {
		return Objects.hash(category, kind, matchedValue, library, indicatorAddress, fromAddress,
			functionName, viaThunk);
	}
}
