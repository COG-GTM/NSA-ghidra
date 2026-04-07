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
package yararulegenerator;

import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger.SleighDebugMode;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.util.ProgramSelection;

import java.util.*;

/**
 * Extracts byte sequences from selected regions, inserting {@code ??} wildcards
 * for variable operands and relocatable addresses.
 *
 * <p>For code (instructions): Uses {@link SleighDebugLogger} to obtain instruction
 * masks and operand value masks, following the same approach as
 * {@code MaskGenerator.java}. The mask bytes indicate which bits are fixed
 * (opcode) vs variable (operands). Convert mask+value pairs to YARA hex
 * strings where masked-out bytes become {@code ??}.
 *
 * <p>For data regions: Reads raw bytes via {@code program.getMemory().getBytes()}.
 * Checks {@code program.getRelocationTable().hasRelocation(addr)} for each
 * pointer-sized chunk; if a relocation exists at that address, those bytes are
 * replaced with {@code ??} wildcards.
 */
public class YaraBytePatternExtractor {

	private Program program;
	private Memory memory;
	private RelocationTable relocationTable;
	private Listing listing;

	public YaraBytePatternExtractor(Program program) {
		this.program = program;
		this.memory = program.getMemory();
		this.relocationTable = program.getRelocationTable();
		this.listing = program.getListing();
	}

	/**
	 * Extract YARA hex pattern strings from each address range in the selection.
	 *
	 * @param selection the program selection containing one or more address ranges
	 * @return list of YARA hex pattern strings
	 */
	public List<String> extractPatterns(ProgramSelection selection) {
		List<String> patterns = new ArrayList<>();
		for (AddressRange range : selection) {
			String pattern = extractPatternFromRange(range);
			if (pattern != null && !pattern.isBlank()) {
				patterns.add(pattern);
			}
		}
		return patterns;
	}

	private String extractPatternFromRange(AddressRange range) {
		StringBuilder hexPattern = new StringBuilder();
		Address addr = range.getMinAddress();
		Address end = range.getMaxAddress();

		while (addr != null && addr.compareTo(end) <= 0) {
			Instruction instr = listing.getInstructionAt(addr);
			if (instr != null) {
				processInstruction(hexPattern, instr, addr);
				addr = addr.add(instr.getLength());
			}
			else {
				// Data region: read raw bytes, wildcard relocations
				appendRawByteOrWildcard(hexPattern, addr);
				try {
					addr = addr.addNoWrap(1);
				}
				catch (AddressOverflowException e) {
					break;
				}
			}
		}
		return hexPattern.toString().trim();
	}

	private void processInstruction(StringBuilder hexPattern, Instruction instr,
			Address addr) {

		SleighDebugLogger logger =
			new SleighDebugLogger(program, addr, SleighDebugMode.VERBOSE);
		if (logger.parseFailed()) {
			// Fallback: read raw byte
			appendRawByteOrWildcard(hexPattern, addr);
			return;
		}

		byte[] instrMask = logger.getInstructionMask();
		byte[] rawBytes = new byte[instr.getLength()];
		try {
			memory.getBytes(addr, rawBytes);
		}
		catch (MemoryAccessException e) {
			return;
		}

		// Combine instruction mask with operand masks.
		// For each operand, get its value mask and OR it into the combined mask,
		// but only if the operand is NOT an address reference (since addresses
		// are position-dependent and should be wildcarded).
		byte[] combinedMask = Arrays.copyOf(instrMask, instrMask.length);
		for (int op = 0; op < logger.getNumOperands(); op++) {
			byte[] opMask = logger.getOperandValueMask(op);
			if (opMask != null) {
				CodeUnit cu = listing.getCodeUnitAt(addr);
				if (cu != null && cu.getAddress(op) == null &&
					!hasRelocationInRange(addr, instr.getLength())) {
					for (int i = 0; i < opMask.length && i < combinedMask.length; i++) {
						combinedMask[i] |= opMask[i];
					}
				}
			}
		}

		// Convert to YARA hex string
		for (int i = 0; i < rawBytes.length; i++) {
			if (i < combinedMask.length && combinedMask[i] == (byte) 0xFF) {
				hexPattern.append(String.format("%02X ", rawBytes[i] & 0xFF));
			}
			else if (i < combinedMask.length && combinedMask[i] == 0) {
				hexPattern.append("?? ");
			}
			else {
				// Partial mask - use full wildcard for simplicity in YARA
				hexPattern.append("?? ");
			}
		}
	}

	private void appendRawByteOrWildcard(StringBuilder sb, Address addr) {
		if (relocationTable.hasRelocation(addr)) {
			sb.append("?? ");
		}
		else {
			try {
				byte b = memory.getByte(addr);
				sb.append(String.format("%02X ", b & 0xFF));
			}
			catch (MemoryAccessException e) {
				sb.append("?? ");
			}
		}
	}

	private boolean hasRelocationInRange(Address instrAddr, int instrLen) {
		for (int i = 0; i < instrLen; i++) {
			try {
				if (relocationTable.hasRelocation(instrAddr.addNoWrap(i))) {
					return true;
				}
			}
			catch (AddressOverflowException e) {
				break;
			}
		}
		return false;
	}
}
