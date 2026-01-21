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
package ghidra.app.decompiler;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;

/**
 * Unit tests for ClangLine class.
 */
public class ClangLineTest extends AbstractGenericTest {

	private ClangTokenGroup rootGroup;

	@Before
	public void setUp() {
		rootGroup = new ClangTokenGroup(null);
	}

	@Test
	public void testClangLineConstruction() {
		ClangLine line = new ClangLine(1, 0);
		assertNotNull(line);
		assertEquals(1, line.getLineNumber());
		assertEquals(0, line.getIndent());
		assertEquals(0, line.getNumTokens());
	}

	@Test
	public void testClangLineConstructionWithIndent() {
		ClangLine line = new ClangLine(5, 3);
		assertEquals(5, line.getLineNumber());
		assertEquals(3, line.getIndent());
	}

	@Test
	public void testClangLineGetIndentString() {
		ClangLine line = new ClangLine(1, 0);
		assertEquals("", line.getIndentString());

		ClangLine indentedLine = new ClangLine(1, 3);
		assertEquals("   ", indentedLine.getIndentString());
	}

	@Test
	public void testClangLineAddToken() {
		ClangLine line = new ClangLine(1, 0);
		ClangSyntaxToken token = new ClangSyntaxToken(rootGroup, "test");

		line.addToken(token);

		assertEquals(1, line.getNumTokens());
		assertEquals(token, line.getToken(0));
		assertEquals(line, token.getLineParent());
	}

	@Test
	public void testClangLineAddMultipleTokens() {
		ClangLine line = new ClangLine(1, 0);
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "int");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, " ");
		ClangSyntaxToken token3 = new ClangSyntaxToken(rootGroup, "x");
		ClangSyntaxToken token4 = new ClangSyntaxToken(rootGroup, ";");

		line.addToken(token1);
		line.addToken(token2);
		line.addToken(token3);
		line.addToken(token4);

		assertEquals(4, line.getNumTokens());
		assertEquals(token1, line.getToken(0));
		assertEquals(token2, line.getToken(1));
		assertEquals(token3, line.getToken(2));
		assertEquals(token4, line.getToken(3));
	}

	@Test
	public void testClangLineGetAllTokens() {
		ClangLine line = new ClangLine(1, 0);
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "a");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, "b");

		line.addToken(token1);
		line.addToken(token2);

		List<ClangToken> tokens = line.getAllTokens();
		assertEquals(2, tokens.size());
		assertTrue(tokens.contains(token1));
		assertTrue(tokens.contains(token2));
	}

	@Test
	public void testClangLineIndexOfToken() {
		ClangLine line = new ClangLine(1, 0);
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "a");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, "b");
		ClangSyntaxToken token3 = new ClangSyntaxToken(rootGroup, "c");

		line.addToken(token1);
		line.addToken(token2);
		line.addToken(token3);

		assertEquals(0, line.indexOfToken(token1));
		assertEquals(1, line.indexOfToken(token2));
		assertEquals(2, line.indexOfToken(token3));
	}

	@Test
	public void testClangLineIndexOfTokenNotFound() {
		ClangLine line = new ClangLine(1, 0);
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "a");
		ClangSyntaxToken notInLine = new ClangSyntaxToken(rootGroup, "x");

		line.addToken(token1);

		assertEquals(-1, line.indexOfToken(notInLine));
	}

	@Test
	public void testClangLineToString() {
		ClangLine line = new ClangLine(5, 0);
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "int");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, " ");
		ClangSyntaxToken token3 = new ClangSyntaxToken(rootGroup, "x");

		line.addToken(token1);
		line.addToken(token2);
		line.addToken(token3);

		String result = line.toString();
		assertTrue(result.contains("5:"));
		assertTrue(result.contains("int"));
		assertTrue(result.contains("x"));
	}

	@Test
	public void testClangLineToDebugString() {
		ClangLine line = new ClangLine(3, 0);
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "return");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, " ");
		ClangSyntaxToken token3 = new ClangSyntaxToken(rootGroup, "0");

		line.addToken(token1);
		line.addToken(token2);
		line.addToken(token3);

		List<ClangToken> calloutTokens = new ArrayList<>();
		calloutTokens.add(token3);

		String result = line.toDebugString(calloutTokens);
		assertTrue(result.contains("3:"));
		assertTrue(result.contains("return"));
		assertTrue(result.contains("[0]"));
	}

	@Test
	public void testClangLineToDebugStringWithCustomMarkers() {
		ClangLine line = new ClangLine(1, 0);
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "test");

		line.addToken(token1);

		List<ClangToken> calloutTokens = new ArrayList<>();
		calloutTokens.add(token1);

		String result = line.toDebugString(calloutTokens, "<<", ">>");
		assertTrue(result.contains("<<test>>"));
	}

	@Test
	public void testClangLineToDebugStringNullCallouts() {
		ClangLine line = new ClangLine(1, 0);
		ClangSyntaxToken token = new ClangSyntaxToken(rootGroup, "test");

		line.addToken(token);

		String result = line.toDebugString(null);
		assertTrue(result.contains("test"));
		assertFalse(result.contains("["));
	}

	@Test
	public void testClangLineToDebugStringEmptyCallouts() {
		ClangLine line = new ClangLine(1, 0);
		ClangSyntaxToken token = new ClangSyntaxToken(rootGroup, "test");

		line.addToken(token);

		String result = line.toDebugString(Collections.emptyList());
		assertTrue(result.contains("test"));
		assertFalse(result.contains("["));
	}

	@Test
	public void testClangLineEmptyLine() {
		ClangLine line = new ClangLine(1, 0);
		assertEquals(0, line.getNumTokens());
		assertTrue(line.getAllTokens().isEmpty());
	}

	@Test
	public void testClangLineTokenLineParentSet() {
		ClangLine line = new ClangLine(1, 0);
		ClangSyntaxToken token = new ClangSyntaxToken(rootGroup, "test");

		assertNull(token.getLineParent());
		line.addToken(token);
		assertEquals(line, token.getLineParent());
	}

	@Test
	public void testClangLineMultipleIndentLevels() {
		ClangLine line0 = new ClangLine(1, 0);
		ClangLine line1 = new ClangLine(2, 1);
		ClangLine line2 = new ClangLine(3, 2);
		ClangLine line4 = new ClangLine(4, 4);

		assertEquals("", line0.getIndentString());
		assertEquals(" ", line1.getIndentString());
		assertEquals("  ", line2.getIndentString());
		assertEquals("    ", line4.getIndentString());
	}
}
