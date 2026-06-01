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

import java.awt.Color;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;

/**
 * Unit tests for ClangTokenGroup class.
 */
public class ClangTokenGroupTest extends AbstractGenericTest {

	private ClangTokenGroup rootGroup;

	@Before
	public void setUp() {
		rootGroup = new ClangTokenGroup(null);
	}

	@Test
	public void testClangTokenGroupConstruction() {
		ClangTokenGroup group = new ClangTokenGroup(null);
		assertNotNull(group);
		assertNull(group.Parent());
		assertEquals(0, group.numChildren());
		assertNull(group.getMinAddress());
		assertNull(group.getMaxAddress());
	}

	@Test
	public void testClangTokenGroupConstructionWithParent() {
		ClangTokenGroup parent = new ClangTokenGroup(null);
		ClangTokenGroup child = new ClangTokenGroup(parent);
		assertEquals(parent, child.Parent());
	}

	@Test
	public void testClangTokenGroupAddTokenGroup() {
		ClangSyntaxToken token = new ClangSyntaxToken(rootGroup, "test");
		rootGroup.AddTokenGroup(token);

		assertEquals(1, rootGroup.numChildren());
		assertEquals(token, rootGroup.Child(0));
	}

	@Test
	public void testClangTokenGroupAddMultipleTokens() {
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "int");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, " ");
		ClangSyntaxToken token3 = new ClangSyntaxToken(rootGroup, "x");

		rootGroup.AddTokenGroup(token1);
		rootGroup.AddTokenGroup(token2);
		rootGroup.AddTokenGroup(token3);

		assertEquals(3, rootGroup.numChildren());
		assertEquals(token1, rootGroup.Child(0));
		assertEquals(token2, rootGroup.Child(1));
		assertEquals(token3, rootGroup.Child(2));
	}

	@Test
	public void testClangTokenGroupNestedGroups() {
		ClangTokenGroup childGroup = new ClangTokenGroup(rootGroup);
		ClangSyntaxToken token = new ClangSyntaxToken(childGroup, "nested");
		childGroup.AddTokenGroup(token);
		rootGroup.AddTokenGroup(childGroup);

		assertEquals(1, rootGroup.numChildren());
		assertEquals(childGroup, rootGroup.Child(0));
		assertEquals(1, childGroup.numChildren());
		assertEquals(token, childGroup.Child(0));
	}

	@Test
	public void testClangTokenGroupSetHighlight() {
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "a");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, "b");
		rootGroup.AddTokenGroup(token1);
		rootGroup.AddTokenGroup(token2);

		Color highlightColor = Color.YELLOW;
		rootGroup.setHighlight(highlightColor);

		assertEquals(highlightColor, token1.getHighlight());
		assertEquals(highlightColor, token2.getHighlight());
	}

	@Test
	public void testClangTokenGroupSetHighlightNested() {
		ClangTokenGroup childGroup = new ClangTokenGroup(rootGroup);
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "a");
		ClangSyntaxToken token2 = new ClangSyntaxToken(childGroup, "b");
		rootGroup.AddTokenGroup(token1);
		childGroup.AddTokenGroup(token2);
		rootGroup.AddTokenGroup(childGroup);

		Color highlightColor = Color.CYAN;
		rootGroup.setHighlight(highlightColor);

		assertEquals(highlightColor, token1.getHighlight());
		assertEquals(highlightColor, token2.getHighlight());
	}

	@Test
	public void testClangTokenGroupFlatten() {
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "a");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, "b");
		rootGroup.AddTokenGroup(token1);
		rootGroup.AddTokenGroup(token2);

		List<ClangNode> flatList = new ArrayList<>();
		rootGroup.flatten(flatList);

		assertEquals(2, flatList.size());
		assertTrue(flatList.contains(token1));
		assertTrue(flatList.contains(token2));
	}

	@Test
	public void testClangTokenGroupFlattenNested() {
		ClangTokenGroup childGroup = new ClangTokenGroup(rootGroup);
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "a");
		ClangSyntaxToken token2 = new ClangSyntaxToken(childGroup, "b");
		ClangSyntaxToken token3 = new ClangSyntaxToken(childGroup, "c");
		rootGroup.AddTokenGroup(token1);
		childGroup.AddTokenGroup(token2);
		childGroup.AddTokenGroup(token3);
		rootGroup.AddTokenGroup(childGroup);

		List<ClangNode> flatList = new ArrayList<>();
		rootGroup.flatten(flatList);

		assertEquals(3, flatList.size());
		assertTrue(flatList.contains(token1));
		assertTrue(flatList.contains(token2));
		assertTrue(flatList.contains(token3));
	}

	@Test
	public void testClangTokenGroupIterator() {
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "a");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, "b");
		rootGroup.AddTokenGroup(token1);
		rootGroup.AddTokenGroup(token2);

		Iterator<ClangNode> iter = rootGroup.iterator();
		assertTrue(iter.hasNext());
		assertEquals(token1, iter.next());
		assertTrue(iter.hasNext());
		assertEquals(token2, iter.next());
		assertFalse(iter.hasNext());
	}

	@Test
	public void testClangTokenGroupTokenIteratorForward() {
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "a");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, "b");
		ClangSyntaxToken token3 = new ClangSyntaxToken(rootGroup, "c");
		rootGroup.AddTokenGroup(token1);
		rootGroup.AddTokenGroup(token2);
		rootGroup.AddTokenGroup(token3);

		Iterator<ClangToken> iter = rootGroup.tokenIterator(true);
		assertTrue(iter.hasNext());
		assertEquals(token1, iter.next());
		assertTrue(iter.hasNext());
		assertEquals(token2, iter.next());
		assertTrue(iter.hasNext());
		assertEquals(token3, iter.next());
		assertFalse(iter.hasNext());
	}

	@Test
	public void testClangTokenGroupTokenIteratorBackward() {
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "a");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, "b");
		ClangSyntaxToken token3 = new ClangSyntaxToken(rootGroup, "c");
		rootGroup.AddTokenGroup(token1);
		rootGroup.AddTokenGroup(token2);
		rootGroup.AddTokenGroup(token3);

		Iterator<ClangToken> iter = rootGroup.tokenIterator(false);
		assertTrue(iter.hasNext());
		assertEquals(token3, iter.next());
		assertTrue(iter.hasNext());
		assertEquals(token2, iter.next());
		assertTrue(iter.hasNext());
		assertEquals(token1, iter.next());
		assertFalse(iter.hasNext());
	}

	@Test
	public void testClangTokenGroupStream() {
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "a");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, "b");
		rootGroup.AddTokenGroup(token1);
		rootGroup.AddTokenGroup(token2);

		List<ClangNode> streamList = rootGroup.stream().collect(Collectors.toList());
		assertEquals(2, streamList.size());
		assertTrue(streamList.contains(token1));
		assertTrue(streamList.contains(token2));
	}

	@Test
	public void testClangTokenGroupToString() {
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "int");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, " ");
		ClangSyntaxToken token3 = new ClangSyntaxToken(rootGroup, "x");
		rootGroup.AddTokenGroup(token1);
		rootGroup.AddTokenGroup(token2);
		rootGroup.AddTokenGroup(token3);

		String result = rootGroup.toString();
		assertEquals("int x", result);
	}

	@Test
	public void testClangTokenGroupToStringWithSpacing() {
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "return");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, "value");
		rootGroup.AddTokenGroup(token1);
		rootGroup.AddTokenGroup(token2);

		String result = rootGroup.toString();
		assertEquals("return value", result);
	}

	@Test
	public void testClangTokenGroupToStringNoSpacingNeeded() {
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "x");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, "+");
		ClangSyntaxToken token3 = new ClangSyntaxToken(rootGroup, "y");
		rootGroup.AddTokenGroup(token1);
		rootGroup.AddTokenGroup(token2);
		rootGroup.AddTokenGroup(token3);

		String result = rootGroup.toString();
		assertEquals("x+y", result);
	}

	@Test
	public void testClangTokenGroupEmptyGroup() {
		assertEquals(0, rootGroup.numChildren());
		assertEquals("", rootGroup.toString());

		List<ClangNode> flatList = new ArrayList<>();
		rootGroup.flatten(flatList);
		assertTrue(flatList.isEmpty());
	}

	@Test
	public void testClangTokenGroupEmptyTokenText() {
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "a");
		ClangSyntaxToken emptyToken = new ClangSyntaxToken(rootGroup, "");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, "b");
		rootGroup.AddTokenGroup(token1);
		rootGroup.AddTokenGroup(emptyToken);
		rootGroup.AddTokenGroup(token2);

		String result = rootGroup.toString();
		assertEquals("a b", result);
	}

	@Test
	public void testClangTokenGroupTokenIteratorNested() {
		ClangTokenGroup childGroup = new ClangTokenGroup(rootGroup);
		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "a");
		ClangSyntaxToken token2 = new ClangSyntaxToken(childGroup, "b");
		ClangSyntaxToken token3 = new ClangSyntaxToken(childGroup, "c");
		ClangSyntaxToken token4 = new ClangSyntaxToken(rootGroup, "d");

		rootGroup.AddTokenGroup(token1);
		childGroup.AddTokenGroup(token2);
		childGroup.AddTokenGroup(token3);
		rootGroup.AddTokenGroup(childGroup);
		rootGroup.AddTokenGroup(token4);

		Iterator<ClangToken> iter = rootGroup.tokenIterator(true);
		assertEquals(token1, iter.next());
		assertEquals(token2, iter.next());
		assertEquals(token3, iter.next());
		assertEquals(token4, iter.next());
		assertFalse(iter.hasNext());
	}

	@Test
	public void testClangTokenGroupDeeplyNested() {
		ClangTokenGroup level1 = new ClangTokenGroup(rootGroup);
		ClangTokenGroup level2 = new ClangTokenGroup(level1);
		ClangTokenGroup level3 = new ClangTokenGroup(level2);
		ClangSyntaxToken deepToken = new ClangSyntaxToken(level3, "deep");

		level3.AddTokenGroup(deepToken);
		level2.AddTokenGroup(level3);
		level1.AddTokenGroup(level2);
		rootGroup.AddTokenGroup(level1);

		List<ClangNode> flatList = new ArrayList<>();
		rootGroup.flatten(flatList);
		assertEquals(1, flatList.size());
		assertEquals(deepToken, flatList.get(0));
	}
}
