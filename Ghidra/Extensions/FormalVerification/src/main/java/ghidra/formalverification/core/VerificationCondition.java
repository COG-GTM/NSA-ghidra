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

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Context;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

/**
 * Represents a verification condition that can be checked using Z3.
 * A verification condition is a logical formula that, when proven valid,
 * guarantees that a specific security property holds for a function.
 */
public class VerificationCondition {

	private final String name;
	private final String description;
	private final Function function;
	private final Address location;
	private final String z3Expression;
	private final PropertyType propertyType;

	/**
	 * Creates a new verification condition.
	 *
	 * @param name the name of this condition
	 * @param description a human-readable description
	 * @param function the function this condition applies to
	 * @param location the specific address within the function
	 * @param z3Expression the Z3 SMT-LIB2 expression representing the condition
	 * @param propertyType the type of security property being verified
	 */
	public VerificationCondition(String name, String description, Function function,
			Address location, String z3Expression, PropertyType propertyType) {
		this.name = name;
		this.description = description;
		this.function = function;
		this.location = location;
		this.z3Expression = z3Expression;
		this.propertyType = propertyType;
	}

	/**
	 * Gets the name of this verification condition.
	 *
	 * @return the condition name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Gets the description of this verification condition.
	 *
	 * @return the condition description
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Gets the function this condition applies to.
	 *
	 * @return the function
	 */
	public Function getFunction() {
		return function;
	}

	/**
	 * Gets the specific location within the function.
	 *
	 * @return the address location
	 */
	public Address getLocation() {
		return location;
	}

	/**
	 * Gets the Z3 SMT-LIB2 expression.
	 *
	 * @return the Z3 expression string
	 */
	public String getZ3Expression() {
		return z3Expression;
	}

	/**
	 * Gets the property type being verified.
	 *
	 * @return the property type
	 */
	public PropertyType getPropertyType() {
		return propertyType;
	}

	/**
	 * Converts this condition to a Z3 BoolExpr for verification.
	 *
	 * @param ctx the Z3 context
	 * @return the Z3 boolean expression
	 */
	public BoolExpr toZ3BoolExpr(Context ctx) {
		if (z3Expression == null || z3Expression.isEmpty()) {
			return ctx.mkTrue();
		}
		try {
			BoolExpr[] exprs = ctx.parseSMTLIB2String(z3Expression, null, null, null, null);
			if (exprs.length > 0) {
				return exprs[0];
			}
			return ctx.mkTrue();
		}
		catch (Exception e) {
			return ctx.mkTrue();
		}
	}

	@Override
	public String toString() {
		return String.format("VerificationCondition[%s @ %s: %s]",
			name, location != null ? location.toString() : "N/A", description);
	}
}
