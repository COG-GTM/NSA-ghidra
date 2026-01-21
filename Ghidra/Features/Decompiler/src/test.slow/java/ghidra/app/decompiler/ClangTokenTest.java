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

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;

/**
 * Unit tests for ClangToken and related token classes.
 */
public class ClangTokenTest extends AbstractGenericTest {

	private ClangTokenGroup rootGroup;

	@Before
	public void setUp() {
		rootGroup = new ClangTokenGroup(null);
	}

	@Test
	public void testClangTokenConstruction() {
		ClangToken token = new ClangSyntaxToken(rootGroup);
		assertNotNull(token);
		assertEquals(rootGroup, token.Parent());
		assertNull(token.getText());
		assertEquals(ClangToken.DEFAULT_COLOR, token.getSyntaxType());
	}

	@Test
	public void testClangTokenConstructionWithText() {
		ClangToken token = new ClangSyntaxToken(rootGroup, "test");
		assertNotNull(token);
		assertEquals("test", token.getText());
		assertEquals(ClangToken.DEFAULT_COLOR, token.getSyntaxType());
	}

	@Test
	public void testClangTokenConstructionWithTextAndColor() {
		ClangToken token = new ClangSyntaxToken(rootGroup, "keyword", ClangToken.KEYWORD_COLOR);
		assertNotNull(token);
		assertEquals("keyword", token.getText());
		assertEquals(ClangToken.KEYWORD_COLOR, token.getSyntaxType());
	}

	@Test
	public void testClangTokenSetText() {
		ClangSyntaxToken token = new ClangSyntaxToken(rootGroup);
		token.setText("newText");
		assertEquals("newText", token.getText());
	}

	@Test
	public void testClangTokenHighlight() {
		ClangToken token = new ClangSyntaxToken(rootGroup, "test");
		assertNull(token.getHighlight());

		Color highlightColor = Color.YELLOW;
		token.setHighlight(highlightColor);
		assertEquals(highlightColor, token.getHighlight());

		token.setHighlight(null);
		assertNull(token.getHighlight());
	}

	@Test
	public void testClangTokenMatchingToken() {
		ClangToken token = new ClangSyntaxToken(rootGroup, "test");
		assertFalse(token.isMatchingToken());

		token.setMatchingToken(true);
		assertTrue(token.isMatchingToken());

		token.setMatchingToken(false);
		assertFalse(token.isMatchingToken());
	}

	@Test
	public void testClangTokenSyntaxType() {
		ClangSyntaxToken token = new ClangSyntaxToken(rootGroup, "test");
		assertEquals(ClangToken.DEFAULT_COLOR, token.getSyntaxType());

		token.setSyntaxType(ClangToken.KEYWORD_COLOR);
		assertEquals(ClangToken.KEYWORD_COLOR, token.getSyntaxType());

		token.setSyntaxType(ClangToken.COMMENT_COLOR);
		assertEquals(ClangToken.COMMENT_COLOR, token.getSyntaxType());
	}

	@Test
	public void testClangTokenNumChildren() {
		ClangToken token = new ClangSyntaxToken(rootGroup, "test");
		assertEquals(0, token.numChildren());
	}

	@Test
	public void testClangTokenChild() {
		ClangToken token = new ClangSyntaxToken(rootGroup, "test");
		assertNull(token.Child(0));
	}

	@Test
	public void testClangTokenMinMaxAddress() {
		ClangToken token = new ClangSyntaxToken(rootGroup, "test");
		assertNull(token.getMinAddress());
		assertNull(token.getMaxAddress());
	}

	@Test
	public void testClangTokenToString() {
		ClangToken token = new ClangSyntaxToken(rootGroup, "testText");
		assertEquals("testText", token.toString());
	}

	@Test
	public void testClangTokenFlatten() {
		ClangToken token = new ClangSyntaxToken(rootGroup, "test");
		List<ClangNode> list = new ArrayList<>();
		token.flatten(list);
		assertEquals(1, list.size());
		assertEquals(token, list.get(0));
	}

	@Test
	public void testClangTokenLineParent() {
		ClangToken token = new ClangSyntaxToken(rootGroup, "test");
		assertNull(token.getLineParent());

		ClangLine line = new ClangLine(1, 0);
		token.setLineParent(line);
		assertEquals(line, token.getLineParent());
	}

	@Test
	public void testClangTokenIsVariableRef() {
		ClangSyntaxToken syntaxToken = new ClangSyntaxToken(rootGroup, "(");
		assertFalse(syntaxToken.isVariableRef());

		ClangVariableToken varToken = new ClangVariableToken(rootGroup);
		assertTrue(varToken.isVariableRef());
	}

	@Test
	public void testClangTokenGetHighVariable() {
		ClangToken token = new ClangSyntaxToken(rootGroup, "test");
		assertNull(token.getHighVariable());
	}

	@Test
	public void testClangTokenGetVarnode() {
		ClangToken token = new ClangSyntaxToken(rootGroup, "test");
		assertNull(token.getVarnode());
	}

	@Test
	public void testClangTokenGetPcodeOp() {
		ClangToken token = new ClangSyntaxToken(rootGroup, "test");
		assertNull(token.getPcodeOp());
	}

	@Test
	public void testClangTokenGetScalar() {
		ClangToken token = new ClangSyntaxToken(rootGroup, "test");
		assertNull(token.getScalar());
	}

	@Test
	public void testClangTokenBuildSpacer() {
		ClangToken spacer = ClangToken.buildSpacer(rootGroup, 2, "  ");
		assertNotNull(spacer);
		assertEquals("    ", spacer.getText());
		assertTrue(spacer instanceof ClangSyntaxToken);
	}

	@Test
	public void testClangTokenBuildSpacerZeroIndent() {
		ClangToken spacer = ClangToken.buildSpacer(rootGroup, 0, "  ");
		assertNotNull(spacer);
		assertEquals("", spacer.getText());
	}

	@Test
	public void testClangBreakConstruction() {
		ClangBreak breakToken = new ClangBreak(rootGroup);
		assertNotNull(breakToken);
		assertEquals(0, breakToken.getIndent());
	}

	@Test
	public void testClangBreakConstructionWithIndent() {
		ClangBreak breakToken = new ClangBreak(rootGroup, 4);
		assertNotNull(breakToken);
		assertEquals(4, breakToken.getIndent());
	}

	@Test
	public void testClangSyntaxTokenOpenClose() {
		ClangSyntaxToken token = new ClangSyntaxToken(rootGroup, "(");
		assertEquals(-1, token.getOpen());
		assertEquals(-1, token.getClose());
	}

	@Test
	public void testClangSyntaxTokenIsVariableRefInDecl() {
		ClangVariableDecl decl = new ClangVariableDecl(rootGroup);
		ClangSyntaxToken token = new ClangSyntaxToken(decl, "test");
		assertTrue(token.isVariableRef());
	}

	@Test
	public void testClangVariableTokenConstruction() {
		ClangVariableToken token = new ClangVariableToken(rootGroup);
		assertNotNull(token);
		assertTrue(token.isVariableRef());
		assertNull(token.getVarnode());
		assertNull(token.getPcodeOp());
	}

	@Test
	public void testClangFuncNameTokenConstruction() {
		ClangFuncNameToken token = new ClangFuncNameToken(rootGroup, null);
		assertNotNull(token);
		assertNull(token.getHighFunction());
		assertNull(token.getPcodeOp());
	}

	@Test
	public void testClangOpTokenConstruction() {
		ClangOpToken token = new ClangOpToken(rootGroup);
		assertNotNull(token);
		assertNull(token.getPcodeOp());
		assertNull(token.getMinAddress());
		assertNull(token.getMaxAddress());
	}

	@Test
	public void testClangTokenColorConstants() {
		assertEquals(0, ClangToken.KEYWORD_COLOR);
		assertEquals(1, ClangToken.COMMENT_COLOR);
		assertEquals(2, ClangToken.TYPE_COLOR);
		assertEquals(3, ClangToken.FUNCTION_COLOR);
		assertEquals(4, ClangToken.VARIABLE_COLOR);
		assertEquals(5, ClangToken.CONST_COLOR);
		assertEquals(6, ClangToken.PARAMETER_COLOR);
		assertEquals(7, ClangToken.GLOBAL_COLOR);
		assertEquals(8, ClangToken.DEFAULT_COLOR);
		assertEquals(9, ClangToken.ERROR_COLOR);
		assertEquals(10, ClangToken.SPECIAL_COLOR);
		assertEquals(11, ClangToken.MAX_COLOR);
	}

	@Test
	public void testClangTokenIterator() {
		ClangTokenGroup group = new ClangTokenGroup(null);
		ClangSyntaxToken token1 = new ClangSyntaxToken(group, "a");
		ClangSyntaxToken token2 = new ClangSyntaxToken(group, "b");
		ClangSyntaxToken token3 = new ClangSyntaxToken(group, "c");
		group.AddTokenGroup(token1);
		group.AddTokenGroup(token2);
		group.AddTokenGroup(token3);

		Iterator<ClangToken> forwardIter = token1.iterator(true);
		assertTrue(forwardIter.hasNext());
		assertEquals(token1, forwardIter.next());
		assertTrue(forwardIter.hasNext());
		assertEquals(token2, forwardIter.next());
		assertTrue(forwardIter.hasNext());
		assertEquals(token3, forwardIter.next());
		assertFalse(forwardIter.hasNext());
	}

	@Test
	public void testClangTokenIteratorBackward() {
		ClangTokenGroup group = new ClangTokenGroup(null);
		ClangSyntaxToken token1 = new ClangSyntaxToken(group, "a");
		ClangSyntaxToken token2 = new ClangSyntaxToken(group, "b");
		ClangSyntaxToken token3 = new ClangSyntaxToken(group, "c");
		group.AddTokenGroup(token1);
		group.AddTokenGroup(token2);
		group.AddTokenGroup(token3);

		Iterator<ClangToken> backwardIter = token3.iterator(false);
		assertTrue(backwardIter.hasNext());
		assertEquals(token3, backwardIter.next());
		assertTrue(backwardIter.hasNext());
		assertEquals(token2, backwardIter.next());
		assertTrue(backwardIter.hasNext());
		assertEquals(token1, backwardIter.next());
		assertFalse(backwardIter.hasNext());
	}
}
