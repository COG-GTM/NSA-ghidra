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
package ghidra.formalverification.core;

/**
 * Enumeration of security property types that can be formally verified.
 * Each type represents a category of security guarantees that can be
 * mathematically proven using the Z3 theorem prover.
 */
public enum PropertyType {

	/**
	 * Memory safety properties ensure that all memory accesses are within
	 * valid bounds. This includes buffer overflow detection, use-after-free
	 * prevention, and null pointer dereference detection.
	 */
	MEMORY_SAFETY("Memory Safety",
		"Verifies that all memory accesses are within valid bounds"),

	/**
	 * Type safety properties ensure that values are used according to their
	 * declared types. This includes type confusion detection and improper
	 * cast detection.
	 */
	TYPE_SAFETY("Type Safety",
		"Verifies that values are used according to their declared types"),

	/**
	 * Control flow integrity properties ensure that program execution follows
	 * only valid control flow paths. This includes indirect call target
	 * validation and return address integrity.
	 */
	CONTROL_FLOW_INTEGRITY("Control Flow Integrity",
		"Verifies that control flow follows only valid paths"),

	/**
	 * Arithmetic safety properties ensure that arithmetic operations do not
	 * result in undefined behavior. This includes integer overflow detection,
	 * division by zero prevention, and signed overflow detection.
	 */
	ARITHMETIC_SAFETY("Arithmetic Safety",
		"Verifies that arithmetic operations do not cause undefined behavior");

	private final String displayName;
	private final String description;

	PropertyType(String displayName, String description) {
		this.displayName = displayName;
		this.description = description;
	}

	/**
	 * Gets the human-readable display name for this property type.
	 *
	 * @return the display name
	 */
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * Gets the description of this property type.
	 *
	 * @return the description
	 */
	public String getDescription() {
		return description;
	}

	@Override
	public String toString() {
		return displayName;
	}
}
