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
package ghidra.app.util.viewer.field;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.util.SystemUtilities;

public class ExecutableTaskStringHandlerTest {

	private ExecutableTaskStringHandler handler = new ExecutableTaskStringHandler();

	@Test
	public void testCreateCommand_ExecutableOnly() {
		List<String> command =
			ExecutableTaskStringHandler.createCommand(new String[] { "execute", "/bin/echo" });
		assertEquals(List.of("/bin/echo"), command);
	}

	@Test
	public void testCreateCommand_ExecutableAndArguments() {
		List<String> command = ExecutableTaskStringHandler
				.createCommand(new String[] { "execute", "/bin/echo", "hi  there", "Display" });
		assertEquals(List.of("/bin/echo", "hi", "there"), command);
	}

	@Test
	public void testCreateCommand_NoExecutable() {
		assertTrue(
			ExecutableTaskStringHandler.createCommand(new String[] { "execute" }).isEmpty());
		assertTrue(
			ExecutableTaskStringHandler.createCommand(new String[] { "execute", "  " }).isEmpty());
	}

	@Test
	public void testHandleMouseClick_HeadlessDoesNotExecute() {
		//
		// Nothing may be launched without the user seeing and confirming the command, which is
		// not possible when there is no GUI.
		//
		String original = System.getProperty(SystemUtilities.HEADLESS_PROPERTY);
		System.setProperty(SystemUtilities.HEADLESS_PROPERTY, Boolean.TRUE.toString());
		try {
			assertFalse(handler.handleMouseClick(new String[] { "execute", "/bin/echo", "hi" },
				null, new ServiceProviderStub()));
		}
		finally {
			if (original == null) {
				System.clearProperty(SystemUtilities.HEADLESS_PROPERTY);
			}
			else {
				System.setProperty(SystemUtilities.HEADLESS_PROPERTY, original);
			}
		}
	}
}
