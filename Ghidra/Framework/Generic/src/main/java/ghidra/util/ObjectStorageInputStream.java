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

import java.io.*;

/**
 * An {@link ObjectInputStream} for reading content previously written with
 * {@link ObjectStorageStreamAdapter}.
 * <p>
 * {@link ObjectStorage} only supports Java primitives, {@link String} and arrays of those, so the
 * only object type this stream ever needs to deserialize is {@link String}.  Deserialization of
 * any other class is rejected, both with an {@link ObjectInputFilter} and by refusing to resolve
 * the class.  This prevents a file containing a crafted serialization gadget chain from executing
 * code while its property values are being read.
 */
public class ObjectStorageInputStream extends ObjectInputStream {

	private static final ObjectInputFilter STRING_ONLY_FILTER = info -> {
		Class<?> serialClass = info.serialClass();
		if (serialClass == null) {
			// Not a class check (array length, depth, reference or stream size check)
			return ObjectInputFilter.Status.ALLOWED;
		}
		if (serialClass == String.class) {
			return ObjectInputFilter.Status.ALLOWED;
		}
		Msg.error(ObjectStorageInputStream.class,
			"Rejected deserialization of unexpected class: " + serialClass.getName());
		return ObjectInputFilter.Status.REJECTED;
	};

	/**
	 * Construct a stream which only permits {@link String} objects to be deserialized
	 * @param in the stream containing the serialized {@link ObjectStorage} content
	 * @throws IOException if the stream header cannot be read
	 */
	public ObjectStorageInputStream(InputStream in) throws IOException {
		super(in);
		setObjectInputFilter(STRING_ONLY_FILTER);
	}

	@Override
	protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException {
		if (!String.class.getName().equals(desc.getName())) {
			throw new InvalidClassException(desc.getName(), "class is not permitted");
		}
		return String.class;
	}

	@Override
	protected Class<?> resolveProxyClass(String[] interfaces) throws IOException {
		throw new InvalidClassException("proxy class is not permitted");
	}
}
