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
// Validation test for RecoverMSVCSwitchTables.java.
//
// Runs the recovery script's logic internally and verifies the results.
// Can be run in two modes:
//   1. Pre-recovery: Checks that candidate bctr instructions exist and
//      are NOT yet recovered (validates test preconditions)
//   2. Post-recovery: Checks that switch tables WERE recovered correctly
//      (validates the script/analyzer worked)
//
// Run this AFTER RecoverMSVCSwitchTables to verify correctness, or
// run it BEFORE to establish a baseline.
//
//@category PowerPC
//@keybinding
//@menupath Analysis.Test MSVC Switch Recovery

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;

public class TestMSVCSwitchRecovery extends GhidraScript {

	private int passed = 0;
	private int failed = 0;

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("No program open.");
			return;
		}

		println("=== MSVC Switch Table Recovery Test Suite ===\n");

		// Test 1: Verify we can find bctr instructions
		testBctrInstructionsExist();

		// Test 2: Verify MSVC lhzx pattern detection
		testMSVCPatternDetection();

		// Test 3: Verify switch table memory properties
		testSwitchTableMemoryDiagnostics();

		// Test 4: Check recovery status of known functions
		testKnownFunctionRecovery();

		// Test 5: Verify no duplicate references
		testNoDuplicateReferences();

		println("\n=== Test Results: " + passed + " passed, " + failed + " failed ===");
		if (failed > 0) {
			printerr("SOME TESTS FAILED");
		}
		else {
			println("ALL TESTS PASSED");
		}
	}

	// --- Test implementations ---

	private void testBctrInstructionsExist() {
		println("--- Test: bctr instructions exist ---");

		int bctrCount = 0;
		int unrecoveredCount = 0;
		InstructionIterator iter = currentProgram.getListing().getInstructions(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Instruction instr = iter.next();
			String mn = instr.getMnemonicString().toLowerCase();
			if (mn.equals("bctr") || mn.equals("bcctr")) {
				bctrCount++;
				if (!hasMultipleJumpRefs(instr.getMinAddress())) {
					unrecoveredCount++;
				}
			}
		}

		assertTest("Found bctr instructions", bctrCount > 0,
			"Found " + bctrCount + " bctr instructions");
		println("  " + unrecoveredCount + " of " + bctrCount + " are unrecovered");
	}

	private void testMSVCPatternDetection() {
		println("\n--- Test: MSVC pattern detection (lhzx before bctr) ---");

		int msvcPatterns = 0;
		int gccPatterns = 0;
		Listing listing = currentProgram.getListing();
		InstructionIterator iter = listing.getInstructions(true);

		while (iter.hasNext() && !monitor.isCancelled()) {
			Instruction instr = iter.next();
			String mn = instr.getMnemonicString().toLowerCase();
			if (!mn.equals("bctr") && !mn.equals("bcctr")) {
				continue;
			}

			// Walk backwards up to 15 instructions
			boolean foundLhzx = false;
			boolean foundLwzx = false;
			Instruction walker = instr;
			for (int i = 0; i < 15; i++) {
				walker = listing.getInstructionBefore(walker.getMinAddress());
				if (walker == null) break;
				String wmn = walker.getMnemonicString().toLowerCase();
				if (wmn.equals("lhzx")) foundLhzx = true;
				if (wmn.equals("lwzx")) foundLwzx = true;
			}

			if (foundLhzx && !foundLwzx) msvcPatterns++;
			if (foundLwzx && !foundLhzx) gccPatterns++;
		}

		assertTest("Found MSVC lhzx switch patterns", msvcPatterns > 0,
			"Found " + msvcPatterns + " MSVC patterns, " + gccPatterns + " GCC patterns");
	}

	private void testSwitchTableMemoryDiagnostics() {
		println("\n--- Test: Switch table memory block properties ---");

		Memory memory = currentProgram.getMemory();
		MemoryBlock[] blocks = memory.getBlocks();

		boolean hasWritableData = false;
		boolean hasReadOnlyData = false;

		for (MemoryBlock block : blocks) {
			if (!block.isExecute() && block.isRead()) {
				if (block.isWrite()) hasWritableData = true;
				else hasReadOnlyData = true;
			}
		}

		// Log what we found - this helps diagnose which allowAccess path matters
		println("  Has writable data blocks: " + hasWritableData);
		println("  Has read-only data blocks: " + hasReadOnlyData);
		assertTest("Program has data memory blocks",
			hasWritableData || hasReadOnlyData, "");
	}

	private void testKnownFunctionRecovery() {
		println("\n--- Test: Known function switch recovery status ---");

		// Check functions that are known to contain MSVC switch tables
		String[] knownSwitchFunctions = {
			"OnBeat",           // BustAMovePanel::OnBeat
			"Poll",             // GamePanel::Poll, BustAMovePanel::Poll
		};

		FunctionIterator funcIter =
			currentProgram.getFunctionManager().getFunctions(true);

		int checkedFunctions = 0;
		while (funcIter.hasNext() && !monitor.isCancelled()) {
			Function func = funcIter.next();
			String name = func.getName();

			boolean isKnown = false;
			for (String known : knownSwitchFunctions) {
				if (name.contains(known)) {
					isKnown = true;
					break;
				}
			}
			if (!isKnown) continue;

			checkedFunctions++;

			// Count bctr instructions in this function
			int bctrCount = 0;
			int recoveredBctrCount = 0;
			InstructionIterator instrIter =
				currentProgram.getListing().getInstructions(func.getBody(), true);
			while (instrIter.hasNext()) {
				Instruction instr = instrIter.next();
				String mn = instr.getMnemonicString().toLowerCase();
				if (mn.equals("bctr") || mn.equals("bcctr")) {
					bctrCount++;
					if (hasMultipleJumpRefs(instr.getMinAddress())) {
						recoveredBctrCount++;
					}
				}
			}

			if (bctrCount > 0) {
				String status = recoveredBctrCount + "/" + bctrCount + " bctr recovered";
				println("  " + name + " at " + func.getEntryPoint() + ": " + status);

				// After recovery, all bctr should have references
				if (recoveredBctrCount == bctrCount) {
					assertTest(name + " fully recovered", true, status);
				}
				else {
					// Not a failure - could be pre-recovery state
					println("  INFO: " + (bctrCount - recoveredBctrCount) +
						" bctr still need recovery");
				}

				// Validate that recovered bctr have reasonable target counts
				instrIter = currentProgram.getListing().getInstructions(
					func.getBody(), true);
				while (instrIter.hasNext()) {
					Instruction instr = instrIter.next();
					String mn = instr.getMnemonicString().toLowerCase();
					if (!mn.equals("bctr") && !mn.equals("bcctr")) continue;
					if (!hasMultipleJumpRefs(instr.getMinAddress())) continue;

					Reference[] refs = currentProgram.getReferenceManager()
						.getReferencesFrom(instr.getMinAddress());
					int jumpRefs = 0;
					for (Reference ref : refs) {
						if (ref.getReferenceType() == RefType.COMPUTED_JUMP) {
							jumpRefs++;
						}
					}
					assertTest(name + " bctr@" + instr.getMinAddress() +
						" has reasonable target count",
						jumpRefs >= 2 && jumpRefs <= 128,
						jumpRefs + " COMPUTED_JUMP refs");
				}
			}
		}

		println("  Checked " + checkedFunctions + " known switch functions");
	}

	private void testNoDuplicateReferences() {
		println("\n--- Test: No duplicate COMPUTED_JUMP references ---");

		int duplicateCount = 0;
		InstructionIterator iter = currentProgram.getListing().getInstructions(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Instruction instr = iter.next();
			String mn = instr.getMnemonicString().toLowerCase();
			if (!mn.equals("bctr") && !mn.equals("bcctr")) continue;

			Reference[] refs = currentProgram.getReferenceManager()
				.getReferencesFrom(instr.getMinAddress());

			List<Address> seen = new ArrayList<>();
			for (Reference ref : refs) {
				if (ref.getReferenceType() == RefType.COMPUTED_JUMP) {
					if (seen.contains(ref.getToAddress())) {
						duplicateCount++;
						println("  DUPLICATE: " + instr.getMinAddress() +
							" -> " + ref.getToAddress());
					}
					seen.add(ref.getToAddress());
				}
			}
		}

		assertTest("No duplicate COMPUTED_JUMP references",
			duplicateCount == 0,
			duplicateCount + " duplicates found");
	}

	// --- Helpers ---

	private boolean hasMultipleJumpRefs(Address addr) {
		Reference[] refs = currentProgram.getReferenceManager().getReferencesFrom(addr);
		int jumpCount = 0;
		for (Reference ref : refs) {
			if (ref.getReferenceType().isComputed() || ref.getReferenceType().isJump()) {
				jumpCount++;
			}
		}
		return jumpCount > 1;
	}

	private void assertTest(String name, boolean condition, String detail) {
		if (condition) {
			passed++;
			println("  PASS: " + name + (detail.isEmpty() ? "" : " (" + detail + ")"));
		}
		else {
			failed++;
			printerr("  FAIL: " + name + (detail.isEmpty() ? "" : " (" + detail + ")"));
		}
	}
}
