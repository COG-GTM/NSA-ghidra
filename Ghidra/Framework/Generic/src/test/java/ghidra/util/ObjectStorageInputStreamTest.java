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

import org.junit.Test;

public class ObjectStorageInputStreamTest {

	/**
	 * Stands in for a deserialization gadget: it runs code from its own readObject
	 */
	@SuppressWarnings("serial")
	public static class Gadget implements Serializable {
		static boolean detonated = false;

		private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
			in.defaultReadObject();
			detonated = true;
		}
	}

	private static byte[] serialize(Object... objects) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try (ObjectOutputStream out = new ObjectOutputStream(baos)) {
			for (Object obj : objects) {
				out.writeObject(obj);
			}
		}
		return baos.toByteArray();
	}

	@Test
	public void testStringsAreRead() throws Exception {
		byte[] enc = serialize("Hello", "World");
		try (ObjectStorageInputStream in =
			new ObjectStorageInputStream(new ByteArrayInputStream(enc))) {
			ObjectStorage storage = new ObjectStorageStreamAdapter(in);
			assertEquals("Hello", storage.getString());
			assertEquals("World", storage.getString());
		}
	}

	@Test
	public void testGadgetIsRejected() throws Exception {
		byte[] enc = serialize(new Gadget());
		try (ObjectStorageInputStream in =
			new ObjectStorageInputStream(new ByteArrayInputStream(enc))) {
			in.readObject();
			fail("Expected deserialization of " + Gadget.class.getName() + " to be rejected");
		}
		catch (InvalidClassException e) {
			// expected
		}
		assertFalse("Gadget was deserialized", Gadget.detonated);
	}

	@Test
	public void testGadgetIsRejectedViaStorageAdapter() throws Exception {
		byte[] enc = serialize(new Gadget());
		try (ObjectStorageInputStream in =
			new ObjectStorageInputStream(new ByteArrayInputStream(enc))) {
			ObjectStorage storage = new ObjectStorageStreamAdapter(in);
			assertNull(storage.getString());
		}
		assertFalse("Gadget was deserialized", Gadget.detonated);
	}

	@Test
	public void testStringArrayElementsAreRead() throws Exception {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try (ObjectOutputStream out = new ObjectOutputStream(baos)) {
			new ObjectStorageStreamAdapter(out).putStrings(new String[] { "a", "b" });
		}
		try (ObjectStorageInputStream in =
			new ObjectStorageInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
			assertArrayEquals(new String[] { "a", "b" },
				new ObjectStorageStreamAdapter(in).getStrings());
		}
	}
}
