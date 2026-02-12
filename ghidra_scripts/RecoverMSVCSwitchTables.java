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
// Recovers MSVC-style switch tables on PowerPC (Xbox 360).
//
// MSVC uses 16-bit relative offset tables with lhzx, unlike GCC/Clang which
// use 32-bit absolute address tables with lwzx. Ghidra's built-in
// PowerPCAddressAnalyzer fails to recover these because:
//   1. SwitchEvaluator.allowAccess() returns false, blocking table reads
//   2. branchSet only walks 1 predecessor level (MSVC needs 2-3)
//   3. Zero-valued table entries are silently dropped by VarnodeContext
//
// Usage: Select a bctr instruction (or run without selection to scan all).
// The script will find MSVC switch patterns, diagnose why the analyzer
// failed, recover targets, and fix function bodies.
//
//@category PowerPC
//@keybinding
//@menupath Analysis.Recover MSVC Switch Tables
//@toolbar

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.util.exception.CancelledException;
import ghidra.app.plugin.core.disassembler.AddressTable;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class RecoverMSVCSwitchTables extends GhidraScript {

	private int totalRecovered = 0;
	private int totalSkipped = 0;

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("No program open.");
			return;
		}

		Memory memory = currentProgram.getMemory();
		Listing listing = currentProgram.getListing();

		// If user has selected a specific address, just process that one bctr
		Instruction selectedInstr = listing.getInstructionAt(currentAddress);
		if (selectedInstr != null && isBctr(selectedInstr)) {
			println("=== Processing selected bctr at " + currentAddress + " ===");
			processBctr(selectedInstr, memory, listing);
			println("\n=== Done. Recovered: " + totalRecovered +
				", Skipped (already done or no pattern): " + totalSkipped + " ===");
			return;
		}

		// Otherwise scan the entire program
		println("=== Scanning all instructions for unrecovered MSVC switch tables ===\n");

		InstructionIterator instrIter = listing.getInstructions(true);
		int candidateCount = 0;

		while (instrIter.hasNext() && !monitor.isCancelled()) {
			Instruction instr = instrIter.next();
			if (!isBctr(instr)) {
				continue;
			}

			// Check if this bctr already has computed jump references
			if (hasComputedJumpRefs(instr)) {
				continue;
			}

			candidateCount++;
			println("--- Candidate #" + candidateCount + ": bctr at " +
				instr.getMinAddress() + " ---");
			processBctr(instr, memory, listing);
			println("");
		}

		println("=== Scan complete. Candidates found: " + candidateCount +
			", Recovered: " + totalRecovered +
			", Skipped: " + totalSkipped + " ===");
	}

	private boolean isBctr(Instruction instr) {
		String mnemonic = instr.getMnemonicString();
		// bctr is "branch to count register" - the indirect jump used for switches
		return "bctr".equalsIgnoreCase(mnemonic) || "bcctr".equalsIgnoreCase(mnemonic);
	}

	private boolean hasComputedJumpRefs(Instruction instr) {
		Reference[] refs =
			currentProgram.getReferenceManager().getReferencesFrom(instr.getMinAddress());
		int jumpCount = 0;
		for (Reference ref : refs) {
			if (ref.getReferenceType().isComputed() || ref.getReferenceType().isJump()) {
				jumpCount++;
			}
		}
		// More than 1 jump ref means it's already been recovered
		return jumpCount > 1;
	}

	/**
	 * Process a single bctr instruction: detect pattern, diagnose, recover.
	 */
	private void processBctr(Instruction bctrInstr, Memory memory, Listing listing)
			throws Exception {

		Address bctrAddr = bctrInstr.getMinAddress();

		// Walk backwards to find the MSVC switch pattern
		MSVCSwitchPattern pattern = detectPattern(bctrInstr, listing);

		if (pattern == null) {
			totalSkipped++;
			println("  No MSVC switch pattern detected (no lhzx found).");
			return;
		}

		if (pattern.isGccPattern) {
			totalSkipped++;
			println("  GCC/Clang pattern (lwzx) - skipping (analyzer should handle).");
			return;
		}

		println("  MSVC pattern found:");
		println("    Table base:  " + pattern.tableBase);
		println("    Code base:   " + pattern.codeBase);
		println("    Table size:  " + pattern.tableSize + " entries");
		println("    Entry size:  " + pattern.entrySize + " bytes (halfword)");
		println("    lhzx at:    " + pattern.lhzxAddr);

		// Diagnose memory properties
		diagnoseMemory(pattern, bctrAddr, memory);

		// Recover switch targets
		List<Address> targets = recoverTargets(pattern, memory);

		if (targets.isEmpty()) {
			println("  WARNING: No valid targets recovered!");
			totalSkipped++;
			return;
		}

		println("  Recovered " + targets.size() + " switch targets:");
		for (int i = 0; i < targets.size(); i++) {
			Function targetFunc =
				currentProgram.getFunctionManager().getFunctionContaining(targets.get(i));
			String funcName = (targetFunc != null) ? " in " + targetFunc.getName() : "";
			println("    case " + i + " -> " + targets.get(i) + funcName);
		}

		// Add COMPUTED_JUMP references from bctr to each target
		addReferences(bctrAddr, targets);

		// Fix up the function body
		fixupFunction(bctrInstr, targets);

		totalRecovered++;
		println("  SUCCESS: Switch table recovered at " + bctrAddr);
	}

	/**
	 * Detect the MSVC switch pattern by walking backwards from bctr.
	 *
	 * MSVC Xbox 360 pattern:
	 *   cmplwi  crN, rX, <size-1>    ; bounds check
	 *   bgt     crN, default          ; guard branch
	 *   slwi    r0, rX, 1            ; index * 2 (halfword entries)
	 *   lis     r12, tableHi          ; table address high
	 *   addi    r12, r12, tableLo     ; table address low
	 *   lhzx    r0, r12, r0           ; load 16-bit offset from table
	 *   lis     r12, codeHi           ; code base high
	 *   addi    r12, r12, codeLo      ; code base low
	 *   add     r12, r12, r0          ; target = codeBase + offset
	 *   mtctr   r12                   ; move to CTR
	 *   bctr                          ; branch indirect
	 *
	 * The order can vary slightly. We look for the key instructions.
	 */
	private MSVCSwitchPattern detectPattern(Instruction bctrInstr, Listing listing) {
		Address bctrAddr = bctrInstr.getMinAddress();
		MSVCSwitchPattern pattern = new MSVCSwitchPattern();

		// Walk backwards up to 20 instructions
		Instruction instr = bctrInstr;
		int maxWalk = 20;

		// Collect instructions in reverse order
		List<Instruction> window = new ArrayList<>();
		for (int i = 0; i < maxWalk; i++) {
			instr = listing.getInstructionBefore(instr.getMinAddress());
			if (instr == null) {
				break;
			}
			window.add(instr);
		}

		// Look for lhzx (MSVC 16-bit) vs lwzx (GCC 32-bit)
		boolean foundLhzx = false;
		boolean foundLwzx = false;

		for (Instruction w : window) {
			String mn = w.getMnemonicString().toLowerCase();
			if (mn.equals("lhzx")) {
				foundLhzx = true;
				pattern.lhzxAddr = w.getMinAddress();
				pattern.entrySize = 2;
			}
			if (mn.equals("lwzx")) {
				foundLwzx = true;
			}
		}

		if (foundLwzx && !foundLhzx) {
			pattern.isGccPattern = true;
			return pattern;
		}

		if (!foundLhzx) {
			return null;
		}

		// Now extract the lis/addi pairs and cmplwi
		// We need two lis/addi pairs: one for table base, one for code base
		// The first pair (before lhzx) is the table base
		// The second pair (after lhzx) is the code base
		List<LisAddiPair> pairs = findLisAddiPairs(window);

		// Also look for lis/ori pairs (alternate encoding)
		List<LisAddiPair> oriPairs = findLisOriPairs(window);
		pairs.addAll(oriPairs);

		if (pairs.size() < 2) {
			println("  WARNING: Found lhzx but only " + pairs.size() +
				" lis/addi pairs (need 2). Pattern may be non-standard.");
			if (pairs.isEmpty()) {
				return null;
			}
		}

		// Classify pairs relative to lhzx position
		LisAddiPair tableBasePair = null;
		LisAddiPair codeBasePair = null;

		for (LisAddiPair pair : pairs) {
			if (pair.lisAddr.compareTo(pattern.lhzxAddr) < 0) {
				// Before lhzx -> table base (take the closest one)
				if (tableBasePair == null ||
					pair.lisAddr.compareTo(tableBasePair.lisAddr) > 0) {
					tableBasePair = pair;
				}
			}
			else {
				// After lhzx -> code base (take the closest one)
				if (codeBasePair == null ||
					pair.lisAddr.compareTo(codeBasePair.lisAddr) < 0) {
					codeBasePair = pair;
				}
			}
		}

		if (tableBasePair != null) {
			pattern.tableBase = toAddr(tableBasePair.value);
		}
		if (codeBasePair != null) {
			pattern.codeBase = toAddr(codeBasePair.value);
		}

		if (pattern.tableBase == null || pattern.codeBase == null) {
			println("  WARNING: Could not determine both table base and code base.");
			println("    Table base: " + pattern.tableBase);
			println("    Code base:  " + pattern.codeBase);
			println("    Pairs found: " + pairs.size());
			for (LisAddiPair p : pairs) {
				println("      lis at " + p.lisAddr + " -> 0x" +
					Long.toHexString(p.value));
			}
			return null;
		}

		// Find cmplwi for table size
		for (Instruction w : window) {
			String mn = w.getMnemonicString().toLowerCase();
			if (mn.equals("cmplwi") || mn.equals("cmpli") ||
				mn.equals("cmpwi") || mn.equals("cmpi")) {
				// Get the immediate operand (last operand)
				int numOps = w.getNumOperands();
				if (numOps >= 2) {
					Object scalar = w.getScalar(numOps - 1);
					if (scalar != null) {
						long val =
							((ghidra.program.model.scalar.Scalar) scalar).getUnsignedValue();
						pattern.tableSize = (int) val + 1;
						println("    Guard compare: " + mn + " with immediate " + val +
							" -> table size " + pattern.tableSize);
						break;
					}
				}
			}
		}

		if (pattern.tableSize <= 0) {
			// Default to a reasonable scan size
			pattern.tableSize = 64;
			println("    WARNING: No cmplwi found, defaulting to max table size " +
				pattern.tableSize);
		}

		return pattern;
	}

	/**
	 * Find lis/addi pairs that form 32-bit addresses.
	 * lis rX, high -> addi rX, rX, low  =>  (high << 16) + low
	 */
	private List<LisAddiPair> findLisAddiPairs(List<Instruction> window) {
		List<LisAddiPair> pairs = new ArrayList<>();

		for (int i = 0; i < window.size(); i++) {
			Instruction instr = window.get(i);
			String mn = instr.getMnemonicString().toLowerCase();

			if (!mn.equals("lis")) {
				continue;
			}

			// Get the destination register and immediate value
			String lisReg = getRegisterName(instr, 0);
			long lisImm = getImmediateValue(instr, 1);
			if (lisReg == null) {
				continue;
			}

			// Look for matching addi in remaining instructions
			// Note: window is in reverse order (closest to bctr first),
			// but lis comes before addi in program order, so lis has higher
			// index in the reversed window. Look backwards (lower indices).
			for (int j = i - 1; j >= 0; j--) {
				Instruction addi = window.get(j);
				String addiMn = addi.getMnemonicString().toLowerCase();
				if (!addiMn.equals("addi")) {
					continue;
				}

				// Check that addi uses the same register as source and dest
				String addiDst = getRegisterName(addi, 0);
				String addiSrc = getRegisterName(addi, 1);
				if (lisReg.equals(addiDst) && lisReg.equals(addiSrc)) {
					long addiImm = getImmediateValue(addi, 2);
					// Sign-extend the addi immediate (it's signed 16-bit)
					if (addiImm > 0x7FFF) {
						addiImm = addiImm - 0x10000;
					}
					long fullAddr = (lisImm << 16) + addiImm;

					LisAddiPair pair = new LisAddiPair();
					pair.lisAddr = instr.getMinAddress();
					pair.addiAddr = addi.getMinAddress();
					pair.value = fullAddr & 0xFFFFFFFFL;
					pairs.add(pair);
					break;
				}
			}
		}
		return pairs;
	}

	/**
	 * Find lis/ori pairs that form 32-bit addresses.
	 * lis rX, high -> ori rX, rX, low  =>  (high << 16) | low
	 */
	private List<LisAddiPair> findLisOriPairs(List<Instruction> window) {
		List<LisAddiPair> pairs = new ArrayList<>();

		for (int i = 0; i < window.size(); i++) {
			Instruction instr = window.get(i);
			String mn = instr.getMnemonicString().toLowerCase();

			if (!mn.equals("lis")) {
				continue;
			}

			String lisReg = getRegisterName(instr, 0);
			long lisImm = getImmediateValue(instr, 1);
			if (lisReg == null) {
				continue;
			}

			for (int j = i - 1; j >= 0; j--) {
				Instruction ori = window.get(j);
				String oriMn = ori.getMnemonicString().toLowerCase();
				if (!oriMn.equals("ori")) {
					continue;
				}

				String oriDst = getRegisterName(ori, 0);
				String oriSrc = getRegisterName(ori, 1);
				if (lisReg.equals(oriDst) && lisReg.equals(oriSrc)) {
					long oriImm = getImmediateValue(ori, 2);
					long fullAddr = (lisImm << 16) | oriImm;

					LisAddiPair pair = new LisAddiPair();
					pair.lisAddr = instr.getMinAddress();
					pair.addiAddr = ori.getMinAddress();
					pair.value = fullAddr & 0xFFFFFFFFL;
					pairs.add(pair);
					break;
				}
			}
		}
		return pairs;
	}

	private String getRegisterName(Instruction instr, int opIndex) {
		if (opIndex >= instr.getNumOperands()) {
			return null;
		}
		Object[] opObjs = instr.getOpObjects(opIndex);
		for (Object obj : opObjs) {
			if (obj instanceof ghidra.program.model.lang.Register) {
				return ((ghidra.program.model.lang.Register) obj).getName();
			}
		}
		return null;
	}

	private long getImmediateValue(Instruction instr, int opIndex) {
		if (opIndex >= instr.getNumOperands()) {
			return 0;
		}
		Object[] opObjs = instr.getOpObjects(opIndex);
		for (Object obj : opObjs) {
			if (obj instanceof ghidra.program.model.scalar.Scalar) {
				return ((ghidra.program.model.scalar.Scalar) obj).getUnsignedValue();
			}
		}
		return 0;
	}

	/**
	 * Diagnose why the built-in analyzer failed for this switch table.
	 */
	private void diagnoseMemory(MSVCSwitchPattern pattern, Address bctrAddr, Memory memory) {
		println("\n  === Diagnostic: Why did the analyzer fail? ===");

		// Check table base memory block
		MemoryBlock tableBlock = memory.getBlock(pattern.tableBase);
		if (tableBlock == null) {
			println("  [DIAG] Table base " + pattern.tableBase +
				" is NOT in any memory block!");
			return;
		}

		println("  [DIAG] Table is in block '" + tableBlock.getName() + "'" +
			" (start=" + tableBlock.getStart() + ", end=" + tableBlock.getEnd() + ")");
		println("  [DIAG]   Read=" + tableBlock.isRead() +
			" Write=" + tableBlock.isWrite() +
			" Execute=" + tableBlock.isExecute());

		// Check distance from lhzx (relevant for VarnodeContext allowAccess gate)
		if (pattern.lhzxAddr != null) {
			long distance = Math.abs(pattern.tableBase.getOffset() -
				pattern.lhzxAddr.getOffset());
			println("  [DIAG] Distance from lhzx to table: " + distance +
				" bytes (0x" + Long.toHexString(distance) + ")");

			if (tableBlock.isWrite()) {
				if (distance > 4096) {
					println("  [DIAG] ** BLOCKER: Writable memory, distance > 4096 **");
					println("  [DIAG]   VarnodeContext.allowAccess() gate fires at line 534");
					println("  [DIAG]   SwitchEvaluator.allowAccess() returns false (line 526)");
					println("  [DIAG]   -> Memory read is BLOCKED by the analyzer");
				}
				else {
					println("  [DIAG] Writable but within 4096 - allowAccess not the issue");
				}
			}
			else {
				println("  [DIAG] Read-only memory - allowAccess gate is bypassed");
			}
		}

		// Check if table region has instructions (readExecutable issue)
		Instruction instrInTable =
			currentProgram.getListing().getInstructionContaining(pattern.tableBase);
		if (instrInTable != null) {
			println("  [DIAG] ** BLOCKER: Table address contains instructions **");
			println("  [DIAG]   VarnodeContext sets hitDest=true (line 515-517)");
			println("  [DIAG]   symEval.readExecutable() returns true -> breaks loop");
		}
		else {
			println("  [DIAG] No instructions at table address (good)");
		}

		// Check for zero-valued entries
		try {
			int zeroCount = 0;
			for (int i = 0; i < Math.min(pattern.tableSize, 10); i++) {
				Address entryAddr = pattern.tableBase.add(i * pattern.entrySize);
				int value = memory.getShort(entryAddr) & 0xFFFF;
				if (value == 0) {
					zeroCount++;
				}
			}
			if (zeroCount > 0) {
				println("  [DIAG] ** ISSUE: " + zeroCount +
					" zero-valued entries in first " +
					Math.min(pattern.tableSize, 10) + " entries **");
				println("  [DIAG]   VarnodeContext returns null for zero values (line 563)");
				println("  [DIAG]   These cases would be silently dropped by the analyzer");
			}
			else {
				println("  [DIAG] No zero entries in sample (good)");
			}
		}
		catch (MemoryAccessException e) {
			println("  [DIAG] ** ERROR: Cannot read table memory: " + e.getMessage() + " **");
		}

		// Check branchSet issue (always applicable for MSVC)
		println("  [DIAG] branchSet depth: Analyzer only walks 1 predecessor level");
		println("  [DIAG]   MSVC pattern typically spans 2-3 basic blocks");
		println("  [DIAG]   -> Symbolic execution may not see the full pattern\n");
	}

	/**
	 * Read the switch table and compute target addresses.
	 */
	private List<Address> recoverTargets(MSVCSwitchPattern pattern, Memory memory) {
		List<Address> targets = new ArrayList<>();

		for (int i = 0; i < pattern.tableSize; i++) {
			monitor.setMessage("Reading switch entry " + i + "/" + pattern.tableSize);
			if (monitor.isCancelled()) {
				break;
			}

			try {
				Address entryAddr = pattern.tableBase.add(i * pattern.entrySize);
				int offset = memory.getShort(entryAddr) & 0xFFFF;

				// Compute target = codeBase + offset
				Address target = pattern.codeBase.add(offset);

				// Validate: target should be in executable memory
				MemoryBlock targetBlock = memory.getBlock(target);
				if (targetBlock == null || !targetBlock.isExecute()) {
					println("  WARNING: entry " + i + " -> " + target +
						" is not in executable memory, stopping.");
					break;
				}

				// Validate: target should contain an instruction (or be disassemblable)
				Instruction targetInstr =
					currentProgram.getListing().getInstructionContaining(target);
				if (targetInstr == null) {
					println("  WARNING: entry " + i + " -> " + target +
						" has no instruction (may need disassembly).");
				}

				targets.add(target);
			}
			catch (MemoryAccessException e) {
				println("  Table read failed at entry " + i + ": " + e.getMessage());
				break;
			}
			catch (Exception e) {
				println("  Error at entry " + i + ": " + e.getMessage());
				break;
			}
		}

		return targets;
	}

	/**
	 * Add COMPUTED_JUMP references from bctr to each switch target.
	 */
	private void addReferences(Address bctrAddr, List<Address> targets) {
		for (Address target : targets) {
			currentProgram.getReferenceManager().addMemoryReference(
				bctrAddr, target, RefType.COMPUTED_JUMP, SourceType.USER_DEFINED, 0);
		}
		println("  Added " + targets.size() + " COMPUTED_JUMP references from " + bctrAddr);
	}

	/**
	 * Fix up the function body to include newly-discovered switch targets.
	 */
	private void fixupFunction(Instruction bctrInstr, List<Address> targets) {
		Address bctrAddr = bctrInstr.getMinAddress();

		if (targets.size() > 1) {
			AddressTable table = new AddressTable(bctrAddr,
				targets.toArray(new Address[0]),
				currentProgram.getDefaultPointerSize(), 0, false);
			table.fixupFunctionBody(currentProgram, bctrInstr, monitor);
			println("  Fixed up function body via AddressTable.fixupFunctionBody()");
		}
		else if (targets.size() == 1) {
			Function func =
				currentProgram.getFunctionManager().getFunctionContaining(bctrAddr);
			if (func != null) {
				try {
					CreateFunctionCmd.fixupFunctionBody(currentProgram, func, monitor);
					println("  Fixed up function body via CreateFunctionCmd.fixupFunctionBody()");
				}
				catch (CancelledException e) {
					println("  fixupFunctionBody cancelled");
				}
			}
		}
	}

	// --- Helper classes ---

	private static class MSVCSwitchPattern {
		Address tableBase;
		Address codeBase;
		Address lhzxAddr;
		int tableSize = -1;
		int entrySize = 2;
		boolean isGccPattern = false;
	}

	private static class LisAddiPair {
		Address lisAddr;
		Address addiAddr;
		long value;
	}
}
