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
package ghidra.formalverification.property;

import java.util.List;

import ghidra.formalverification.core.PropertyType;
import ghidra.formalverification.core.VerificationCondition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Abstract base class for security properties that can be formally verified.
 * Each security property defines a specific class of vulnerabilities or
 * security guarantees that can be mathematically proven using the Z3 theorem prover.
 * 
 * Subclasses implement specific property types such as buffer overflow detection,
 * control flow integrity, or arithmetic safety.
 */
public abstract class SecurityProperty {

	protected final String name;
	protected final String description;
	protected final PropertyType propertyType;
	protected final Program program;

	/**
	 * Creates a new security property.
	 *
	 * @param name the name of this property
	 * @param description a human-readable description
	 * @param propertyType the type of property
	 * @param program the program to analyze
	 */
	protected SecurityProperty(String name, String description, PropertyType propertyType,
			Program program) {
		this.name = name;
		this.description = description;
		this.propertyType = propertyType;
		this.program = program;
	}

	/**
	 * Gets the name of this security property.
	 *
	 * @return the property name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Gets the description of this security property.
	 *
	 * @return the property description
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Gets the type of this security property.
	 *
	 * @return the property type
	 */
	public PropertyType getPropertyType() {
		return propertyType;
	}

	/**
	 * Gets the program being analyzed.
	 *
	 * @return the program
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Generates verification conditions for the specified function.
	 * This method analyzes the function's P-code and generates Z3 constraints
	 * that, when satisfied, prove the security property holds.
	 *
	 * @param function the function to analyze
	 * @return list of verification conditions for this property
	 */
	public abstract List<VerificationCondition> generateConditions(Function function);

	/**
	 * Checks if this property is applicable to the given function.
	 * Some properties may only apply to certain types of functions
	 * (e.g., functions with memory operations, functions with indirect calls).
	 *
	 * @param function the function to check
	 * @return true if this property can be verified for the function
	 */
	public abstract boolean isApplicable(Function function);

	/**
	 * Gets the priority of this property for verification ordering.
	 * Higher priority properties are verified first.
	 *
	 * @return the priority value (higher = more important)
	 */
	public int getPriority() {
		return 0;
	}

	@Override
	public String toString() {
		return String.format("SecurityProperty[%s: %s]", name, propertyType.getDisplayName());
	}
}
