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

import java.net.MalformedURLException;
import java.net.URL;

import org.junit.Test;

public class BrowserLoaderTest {

	@Test
	public void testCmdExeStartQuotesTheUrl() throws Exception {
		String[] command = generateCommand(cmdExeStartOption(), url("http://x/?a&calc.exe"));

		assertArrayEquals(
			new String[] { "cmd.exe", "/c", "start", "\"\"", "\"http://x/?a&calc.exe\"" },
			command);
	}

	@Test
	public void testCmdExeStartKeepsUserSuppliedTitle() throws Exception {
		ManualViewerCommandWrappedOption option = cmdExeStartOption();
		option.setCommandArguments(new String[] { "/c", "start", "\"Manual\"" });

		String[] command = generateCommand(option, url("http://example.com/docs"));

		assertArrayEquals(
			new String[] { "cmd.exe", "/c", "start", "\"Manual\"", "\"http://example.com/docs\"" },
			command);
	}

	@Test
	public void testUrlWithQuoteIsRejected() throws Exception {
		assertNull(generateCommand(cmdExeStartOption(), url("http://x/?a=\"&calc.exe&\"")));
	}

	@Test
	public void testUrlWithControlCharacterIsRejected() throws Exception {
		assertNull(generateCommand(cmdExeStartOption(), url("http://x/?a=1\ncalc.exe")));
	}

	@Test
	public void testUnsupportedProtocolIsRejected() throws Exception {
		assertNull(generateCommand(cmdExeStartOption(), url("jar:file:/tmp/evil.jar!/")));
	}

	@Test
	public void testShellCommandRejectsMetaCharacters() throws Exception {
		ManualViewerCommandWrappedOption option = new ManualViewerCommandWrappedOption();
		option.setCommandString("/bin/sh");
		option.setCommandArguments(new String[] { "-c", "xdg-open" });
		option.setUrlReplacementString("${HTTP_URL}");

		assertNull(generateCommand(option, url("http://x/?a;calc")));
		assertArrayEquals(new String[] { "/bin/sh", "-c", "xdg-open", "http://example.com/" },
			generateCommand(option, url("http://example.com/")));
	}

	@Test
	public void testNonShellCommandGetsTheUrlVerbatim() throws Exception {
		ManualViewerCommandWrappedOption option = new ManualViewerCommandWrappedOption();
		option.setCommandString("firefox");
		option.setCommandArguments(new String[] {});
		option.setUrlReplacementString("${HTTP_URL}");

		assertArrayEquals(new String[] { "firefox", "http://example.com/?a=1&b=2" },
			generateCommand(option, url("http://example.com/?a=1&b=2")));
	}

	private static String[] generateCommand(ManualViewerCommandWrappedOption option, URL url) {
		return BrowserLoader.generateCommandArguments(url, null, option);
	}

	private static ManualViewerCommandWrappedOption cmdExeStartOption() {
		ManualViewerCommandWrappedOption option = new ManualViewerCommandWrappedOption();
		option.setCommandString("cmd.exe");
		option.setCommandArguments(new String[] { "/c", "start" });
		option.setUrlReplacementString("${HTTP_URL}");
		return option;
	}

	private static URL url(String urlString) throws MalformedURLException {
		return new URL(urlString);
	}
}
