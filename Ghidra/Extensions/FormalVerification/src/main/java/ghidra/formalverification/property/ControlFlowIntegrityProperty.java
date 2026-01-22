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

import java.util.*;

import ghidra.formalverification.core.PropertyType;
import ghidra.formalverification.core.VerificationCondition;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;

/**
 * Security property for verifying control flow integrity.
 * Ensures that indirect calls and branches target only valid addresses.
 */
public class ControlFlowIntegrityProperty extends SecurityProperty {

	private static final String NAME = "Control Flow Integrity";
	private static final String DESCRIPTION = 
		"Verifies that all indirect control flow transfers target valid addresses, " +
		"preventing control flow hijacking attacks.";

	private final ControlFlowIntegrityVerifier verifier;

	/**
	 * Creates a new control flow integrity property.
	 *
	 * @param program the program to analyze
	 */
	public ControlFlowIntegrityProperty(Program program) {
		super(NAME, DESCRIPTION, PropertyType.CONTROL_FLOW_INTEGRITY, program);
		this.verifier = new ControlFlowIntegrityVerifier(program);
	}

	@Override
	public List<VerificationCondition> generateConditions(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		conditions.addAll(verifier.verifyIndirectCalls(function));
		conditions.addAll(verifier.verifyIndirectBranches(function));
		conditions.addAll(verifier.verifyReturnAddressIntegrity(function));
		
		return conditions;
	}

	@Override
	public boolean isApplicable(Function function) {
		if (function == null || function.isThunk()) {
			return false;
		}
		
		InstructionIterator instructions = program.getListing()
			.getInstructions(function.getBody(), true);
		
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			PcodeOp[] pcodeOps = instruction.getPcode();
			
			for (PcodeOp op : pcodeOps) {
				int opcode = op.getOpcode();
				if (opcode == PcodeOp.CALLIND || opcode == PcodeOp.BRANCHIND ||
					opcode == PcodeOp.RETURN) {
					return true;
				}
			}
		}
		
		return false;
	}

	@Override
	public int getPriority() {
		return 90;
	}
}
