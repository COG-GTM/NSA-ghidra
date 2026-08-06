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
package ghidra.util;

import static org.junit.Assert.*;

import java.io.*;

import org.junit.Before;
import org.junit.Test;

public class ObjectStorageStreamAdapterTest {

	/**
	 * Stand-in for a deserialization gadget: records whether its readObject method
	 * was ever invoked during stream deserialization.
	 */
	private static class Canary implements Serializable {
		private static final long serialVersionUID = 1L;
		static volatile boolean deserialized = false;

		private void readObject(ObjectInputStream in)
				throws IOException, ClassNotFoundException {
			deserialized = true;
			in.defaultReadObject();
		}
	}

	@Before
	public void setUp() {
		Canary.deserialized = false;
	}

	private ObjectStorageStreamAdapter reader(byte[] bytes) throws IOException {
		return new ObjectStorageStreamAdapter(
			new ObjectInputStream(new ByteArrayInputStream(bytes)));
	}

	@Test
	public void testSaveRestoreStrings() throws IOException {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		try (ObjectOutputStream objStream = new ObjectOutputStream(os)) {
			ObjectStorageStreamAdapter writer = new ObjectStorageStreamAdapter(objStream);
			writer.putString("hello");
			writer.putStrings(new String[] { "a", "b" });
			writer.putInt(42);
		}

		ObjectStorageStreamAdapter adapter = reader(os.toByteArray());
		assertEquals("hello", adapter.getString());
		assertArrayEquals(new String[] { "a", "b" }, adapter.getStrings());
		assertEquals(42, adapter.getInt());
	}

	@Test
	public void testGetStringRejectsNonStringObjects() throws IOException {
		// Simulate a maliciously-crafted stream containing a serialized non-String object;
		// the input filter must reject it before its readObject method can run
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		try (ObjectOutputStream objStream = new ObjectOutputStream(os)) {
			objStream.writeObject(new Canary());
		}

		ObjectStorageStreamAdapter adapter = reader(os.toByteArray());
		assertNull(adapter.getString());
		assertFalse(Canary.deserialized);
	}

	@Test
	public void testGetStringsRejectsNonStringObjects() throws IOException {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		try (ObjectOutputStream objStream = new ObjectOutputStream(os)) {
			objStream.writeInt(1);
			objStream.writeObject(new Canary());
		}

		ObjectStorageStreamAdapter adapter = reader(os.toByteArray());
		assertArrayEquals(new String[0], adapter.getStrings());
		assertFalse(Canary.deserialized);
	}
}
