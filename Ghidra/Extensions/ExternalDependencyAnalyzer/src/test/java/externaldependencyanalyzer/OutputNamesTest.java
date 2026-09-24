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

import static org.junit.Assert.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class OutputNamesTest extends AbstractGenericTest {

	@Test
	public void testCleanNamesAreUnchanged() {
		assertEquals("fixture", OutputNames.safeName("fixture"));
		assertEquals("svc_a-1.2.exe", OutputNames.safeName("svc_a-1.2.exe"));
	}

	@Test
	public void testAlteredNamesAreAsciiBoundedAndDistinct() {
		List<String> names = List.of("svc a", "svc/a", "svc:a", "svc_a", "svc\u00e4", "svc\u00f6",
			"..hidden", "hidden", "   ", "", "a".repeat(200) + "x", "a".repeat(200) + "y",
			"a".repeat(128), "a".repeat(129));
		Set<String> seen = new HashSet<>();
		for (String n : names) {
			String s = OutputNames.safeName(n);
			assertTrue(s, s.matches("[A-Za-z0-9_-][A-Za-z0-9._-]*"));
			assertTrue(s, s.length() <= OutputNames.MAX_LENGTH);
			assertEquals(s, OutputNames.safeName(n));
			assertTrue("collision on " + s, seen.add(s));
		}
		assertEquals("a".repeat(128), OutputNames.safeName("a".repeat(128)));
		assertTrue(OutputNames.safeName("").startsWith("program-"));
	}
}
