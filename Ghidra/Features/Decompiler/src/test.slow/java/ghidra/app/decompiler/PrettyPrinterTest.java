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

import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;

/**
 * Unit tests for PrettyPrinter class.
 */
public class PrettyPrinterTest extends AbstractGenericTest {

	@Test
	public void testGetTextFromClangLine() {
		ClangTokenGroup rootGroup = new ClangTokenGroup(null);
		ClangLine line = new ClangLine(1, 0);

		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "int");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, " ");
		ClangSyntaxToken token3 = new ClangSyntaxToken(rootGroup, "x");
		ClangSyntaxToken token4 = new ClangSyntaxToken(rootGroup, ";");

		line.addToken(token1);
		line.addToken(token2);
		line.addToken(token3);
		line.addToken(token4);

		String text = PrettyPrinter.getText(line);
		assertEquals("int x;", text);
	}

	@Test
	public void testGetTextFromClangLineWithIndent() {
		ClangTokenGroup rootGroup = new ClangTokenGroup(null);
		ClangLine line = new ClangLine(1, 2);

		ClangSyntaxToken token = new ClangSyntaxToken(rootGroup, "return");
		line.addToken(token);

		String text = PrettyPrinter.getText(line);
		assertEquals("  return", text);
	}

	@Test
	public void testGetTextFromEmptyLine() {
		ClangLine line = new ClangLine(1, 0);
		String text = PrettyPrinter.getText(line);
		assertEquals("", text);
	}

	@Test
	public void testGetTextFromLineWithMultipleTokenTypes() {
		ClangTokenGroup rootGroup = new ClangTokenGroup(null);
		ClangLine line = new ClangLine(1, 0);

		ClangSyntaxToken keyword = new ClangSyntaxToken(rootGroup, "if", ClangToken.KEYWORD_COLOR);
		ClangSyntaxToken space = new ClangSyntaxToken(rootGroup, " ");
		ClangSyntaxToken paren = new ClangSyntaxToken(rootGroup, "(");
		ClangVariableToken var = new ClangVariableToken(rootGroup);
		var.setText("x");
		ClangSyntaxToken closeParen = new ClangSyntaxToken(rootGroup, ")");

		line.addToken(keyword);
		line.addToken(space);
		line.addToken(paren);
		line.addToken(var);
		line.addToken(closeParen);

		String text = PrettyPrinter.getText(line);
		assertEquals("if (x)", text);
	}

	@Test
	public void testIndentStringConstant() {
		assertEquals(" ", PrettyPrinter.INDENT_STRING);
	}

	@Test
	public void testGetTextPreservesTokenOrder() {
		ClangTokenGroup rootGroup = new ClangTokenGroup(null);
		ClangLine line = new ClangLine(1, 0);

		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "a");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, "b");
		ClangSyntaxToken token3 = new ClangSyntaxToken(rootGroup, "c");

		line.addToken(token1);
		line.addToken(token2);
		line.addToken(token3);

		String text = PrettyPrinter.getText(line);
		assertEquals("abc", text);
	}

	@Test
	public void testGetTextWithVariousIndentLevels() {
		ClangTokenGroup rootGroup = new ClangTokenGroup(null);

		ClangLine line0 = new ClangLine(1, 0);
		ClangLine line1 = new ClangLine(2, 1);
		ClangLine line2 = new ClangLine(3, 2);
		ClangLine line4 = new ClangLine(4, 4);

		ClangSyntaxToken token = new ClangSyntaxToken(rootGroup, "x");
		line0.addToken(new ClangSyntaxToken(rootGroup, "x"));
		line1.addToken(new ClangSyntaxToken(rootGroup, "x"));
		line2.addToken(new ClangSyntaxToken(rootGroup, "x"));
		line4.addToken(new ClangSyntaxToken(rootGroup, "x"));

		assertEquals("x", PrettyPrinter.getText(line0));
		assertEquals(" x", PrettyPrinter.getText(line1));
		assertEquals("  x", PrettyPrinter.getText(line2));
		assertEquals("    x", PrettyPrinter.getText(line4));
	}

	@Test
	public void testGetTextWithSpecialCharacters() {
		ClangTokenGroup rootGroup = new ClangTokenGroup(null);
		ClangLine line = new ClangLine(1, 0);

		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "ptr");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, "->");
		ClangSyntaxToken token3 = new ClangSyntaxToken(rootGroup, "field");

		line.addToken(token1);
		line.addToken(token2);
		line.addToken(token3);

		String text = PrettyPrinter.getText(line);
		assertEquals("ptr->field", text);
	}

	@Test
	public void testGetTextWithOperators() {
		ClangTokenGroup rootGroup = new ClangTokenGroup(null);
		ClangLine line = new ClangLine(1, 0);

		ClangSyntaxToken token1 = new ClangSyntaxToken(rootGroup, "a");
		ClangSyntaxToken token2 = new ClangSyntaxToken(rootGroup, " ");
		ClangSyntaxToken token3 = new ClangSyntaxToken(rootGroup, "+");
		ClangSyntaxToken token4 = new ClangSyntaxToken(rootGroup, " ");
		ClangSyntaxToken token5 = new ClangSyntaxToken(rootGroup, "b");

		line.addToken(token1);
		line.addToken(token2);
		line.addToken(token3);
		line.addToken(token4);
		line.addToken(token5);

		String text = PrettyPrinter.getText(line);
		assertEquals("a + b", text);
	}

	@Test
	public void testGetTextWithBraces() {
		ClangTokenGroup rootGroup = new ClangTokenGroup(null);
		ClangLine line = new ClangLine(1, 0);

		ClangSyntaxToken openBrace = new ClangSyntaxToken(rootGroup, "{");
		line.addToken(openBrace);

		String text = PrettyPrinter.getText(line);
		assertEquals("{", text);
	}

	@Test
	public void testGetTextWithFunctionCall() {
		ClangTokenGroup rootGroup = new ClangTokenGroup(null);
		ClangLine line = new ClangLine(1, 0);

		ClangFuncNameToken funcName = new ClangFuncNameToken(rootGroup, null);
		funcName.setText("printf");
		ClangSyntaxToken openParen = new ClangSyntaxToken(rootGroup, "(");
		ClangSyntaxToken arg = new ClangSyntaxToken(rootGroup, "\"hello\"");
		ClangSyntaxToken closeParen = new ClangSyntaxToken(rootGroup, ")");
		ClangSyntaxToken semi = new ClangSyntaxToken(rootGroup, ";");

		line.addToken(funcName);
		line.addToken(openParen);
		line.addToken(arg);
		line.addToken(closeParen);
		line.addToken(semi);

		String text = PrettyPrinter.getText(line);
		assertEquals("printf(\"hello\");", text);
	}
}
