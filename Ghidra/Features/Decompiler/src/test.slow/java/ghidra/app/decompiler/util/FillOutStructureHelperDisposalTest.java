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
package ghidra.app.decompiler.util;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitor;

public class FillOutStructureHelperDisposalTest extends AbstractGhidraHeadedIntegrationTest {

	private ToyProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		builder = new ToyProgramBuilder("fill_out_structure_disposal", true);
		builder.createMemory("test", "0x0", 2);
		builder.addBytesReturn(0x0);
		builder.createFunction("0x0");
		program = builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		if (builder != null) {
			builder.dispose();
		}
	}

	@Test
	public void testSetUpDecompilerLifecycle() throws Exception {
		FillOutStructureHelper helper = new FillOutStructureHelper(program, TaskMonitor.DUMMY);
		DecompInterface decomplib = helper.setUpDecompiler(new DecompileOptions());
		assertNotNull(decomplib);
		decomplib.dispose();

		// a second interface can be set up and disposed independently
		DecompInterface decomplib2 = helper.setUpDecompiler(new DecompileOptions());
		assertNotNull(decomplib2);
		decomplib2.dispose();
	}
}
