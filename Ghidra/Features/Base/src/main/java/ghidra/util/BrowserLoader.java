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

import java.awt.Desktop;
import java.awt.Desktop.Action;
import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import docking.options.OptionsService;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;

/** 
 *  BrowserLoader opens a web browser and displays the given url. 
 *  
 *  @see ManualViewerCommandWrappedOption
 */
public class BrowserLoader {

	/**
	 * The protocols that may be handed to an external launcher.  URLs may come from untrusted
	 * content, such as a {@code {@url ...}} comment annotation in a program.
	 */
	private static final Set<String> ALLOWED_PROTOCOLS =
		Set.of("http", "https", "ftp", "ftps", "file", "mailto");

	/** Command interpreters that re-parse their arguments instead of executing them verbatim */
	private static final Set<String> COMMAND_INTERPRETERS = Set.of("cmd.exe", "cmd",
		"command.com", "powershell.exe", "powershell", "pwsh.exe", "pwsh", "sh", "bash", "zsh",
		"ksh", "dash", "csh", "tcsh");

	/** Characters a command interpreter treats as separators, escapes or substitutions */
	private static final String SHELL_META_CHARACTERS = "&|^<>;$`'()!";

	/**
	 * Display the content specified by url in a web browser window.  This call will launch 
	 * a new thread and then immediately return.
	 * @param url The URL to show.
	 */
	public static void display(URL url) {
		display(url, null, null);
	}

	/**
	 * Display the content specified by url in a web browser window.  This call will launch 
	 * a new thread and then immediately return.
	 * 
	 * @param url The web URL to show (e.g., http://localhost...).
	 * @param fileURL The file URL to show (e.g., file:///path/to/file).
	 * @param serviceProvider A service provider from which to get system resources.
	 */
	public static void display(URL url, URL fileURL, ServiceProvider serviceProvider) {
		if (url == null) {
			return;
		}

		// open the browser in a new thread because the call may block
		(new Thread(new BrowserRunner(url, fileURL, serviceProvider))).start();
	}

	private static void displayFromBrowserRunner(URL url, URL fileURL,
			ServiceProvider serviceProvider) {
		try {
			if (serviceProvider == null) {
				displayBrowserForExternalURL(url);
			}
			else {
				displayBrowser(url, fileURL, serviceProvider);
			}
		}
		catch (Exception e) {
			Msg.showError(BrowserLoader.class, null, "Error Loading Browser",
				"Error loading browser for URL: " + url, e);
		}
	}

	private static void displayBrowserForExternalURL(URL url) throws Exception {
		if (browseWithDesktop(url)) {
			return;
		}

		String[] arguments =
			generateCommandArguments(url, null,
				ManualViewerCommandWrappedOption.getDefaultBrowserLoaderOptions());
		if (arguments == null) {
			reportUnsafeURL(url);
			return;
		}

		Process p = Runtime.getRuntime().exec(arguments);
		p.waitFor();
		p.exitValue();  // thought to help memory problems on some versions of windows
	}

	private static void displayBrowser(URL url, URL fileURL, ServiceProvider serviceProvider) {
		OptionsService service = serviceProvider.getService(OptionsService.class);
		ToolOptions options =
			service.getOptions(ManualViewerCommandWrappedOption.OPTIONS_CATEGORY_NAME);

		// add a listener to know when the user updates the options
		ImmediateOptionsChangeListener listener = new ImmediateOptionsChangeListener();
		options.addOptionsChangeListener(listener);

		ManualViewerCommandWrappedOption defaultOption =
			ManualViewerCommandWrappedOption.getDefaultBrowserLoaderOptions();
		ManualViewerCommandWrappedOption customOption =
			(ManualViewerCommandWrappedOption) options.getCustomOption(
				ManualViewerCommandWrappedOption.MANUAL_VIEWER_OPTIONS, defaultOption);

		boolean success = tryToDisplayBrowser(url, fileURL, customOption);
		while (!success) {
			// get browser options from user and try again
			// -show error message
			LaunchErrorDialog dialog = new LaunchErrorDialog(url, fileURL);
			dialog.setVisible(true);
			if (dialog.isCancelled()) {
				return;
			}

			// -if not cancelled, then show the options dialog
			service.showOptionsDialog(ManualViewerCommandWrappedOption.OPTIONS_CATEGORY_NAME,
				ManualViewerCommandWrappedOption.OPTIONS_CATEGORY_NAME);
			if (!listener.hasChanged()) {
				return;  // the user didn't change the options, so we can't do anything
			}

			// -if not cancelled, then reread the options
			customOption =
				(ManualViewerCommandWrappedOption) options.getCustomOption(
					ManualViewerCommandWrappedOption.MANUAL_VIEWER_OPTIONS, defaultOption);
			success = tryToDisplayBrowser(url, fileURL, customOption);
		}
	}

	private static boolean tryToDisplayBrowser(URL url, URL fileURL,
			ManualViewerCommandWrappedOption option) {

		// a plain web URL launched with the unmodified platform default is handed to the desktop
		// browser directly, which avoids any command interpreter
		if (fileURL == null && isDefaultOption(option) && browseWithDesktop(url)) {
			return true;
		}

		String[] processCommands = generateCommandArguments(url, fileURL, option);
		if (processCommands == null) {
			// changing the launch command cannot make this URL safe, so do not prompt for one
			reportUnsafeURL(url);
			return true;
		}

		Process p = null;
		try {
			p = Runtime.getRuntime().exec(processCommands);
		}
		catch (Exception exc) {
			return false;
		}

		try {
			p.waitFor();
			p.exitValue();  // thought to help memory problems on some versions of windows
		}
		catch (InterruptedException e) {
			// we tried; the user can just launch again
		}

		return true;
	}

	/**
	 * Builds the command used to launch the browser, or null if the URL cannot be passed safely
	 * to the configured command.
	 * @param url the web URL to show
	 * @param fileURL the file URL to show; may be null
	 * @param option the configured launch command
	 * @return the command and its arguments, or null if the URL is not safe to launch
	 */
	static String[] generateCommandArguments(URL url, URL fileURL,
			ManualViewerCommandWrappedOption option) {

		String urlArgument = getLaunchArgument(url, fileURL, option);
		if (urlArgument == null || !isSafeLaunchArgument(urlArgument)) {
			return null;
		}

		String commandString = option.getCommandString();
		String[] commandArguments = option.getCommandArguments();
		if (commandArguments == null) {
			commandArguments = new String[0];
		}

		List<String> argumentList = new ArrayList<String>();
		argumentList.add(commandString);
		argumentList.addAll(Arrays.asList(commandArguments));

		if (isCmdExeStart(commandString, commandArguments)) {
			if (commandArguments.length == 2) {
				// 'start' consumes a leading quoted argument as the window title
				argumentList.add("\"\"");
			}

			// quoted so that cmd.exe does not re-parse the URL as further commands; the quotes
			// survive the JDK's Windows argument handling and the URL cannot contain a quote
			argumentList.add('"' + urlArgument + '"');
		}
		else if (isCommandInterpreter(commandString) &&
			containsShellMetaCharacter(urlArgument)) {
			return null;
		}
		else {
			argumentList.add(urlArgument);
		}

		return argumentList.toArray(new String[argumentList.size()]);
	}

	private static String getLaunchArgument(URL url, URL fileURL,
			ManualViewerCommandWrappedOption option) {

		String urlString = option.getUrlReplacementString();
		if (ManualViewerCommandWrappedOption.HTTP_URL_REPLACEMENT_STRING.equals(urlString) ||
			fileURL == null) {
			return hasAllowedProtocol(url) ? url.toExternalForm() : null;
		}

		if (ManualViewerCommandWrappedOption.FILE_URL_REPLACEMENT_STRING.equals(urlString)) {
			return hasAllowedProtocol(fileURL) ? fileURL.toExternalForm() : null;
		}

		return new File(fileURL.getFile()).getAbsolutePath();
	}

	/**
	 * Hands the URL to the platform's default browser without using any command interpreter.
	 * @param url the URL to show
	 * @return true if the URL was given to the desktop browser
	 */
	private static boolean browseWithDesktop(URL url) {
		if (!hasAllowedProtocol(url) || !Desktop.isDesktopSupported()) {
			return false;
		}

		Desktop desktop = Desktop.getDesktop();
		if (!desktop.isSupported(Action.BROWSE)) {
			return false;
		}

		try {
			desktop.browse(url.toURI());
			return true;
		}
		catch (Exception e) {
			Msg.debug(BrowserLoader.class, "Unable to use the desktop browser for URL: " + url, e);
			return false;
		}
	}

	private static boolean isDefaultOption(ManualViewerCommandWrappedOption option) {
		return ManualViewerCommandWrappedOption.getDefaultBrowserLoaderOptions().equals(option);
	}

	static boolean hasAllowedProtocol(URL url) {
		return containsIgnoreCase(ALLOWED_PROTOCOLS, url.getProtocol());
	}

	private static boolean containsIgnoreCase(Set<String> values, String value) {
		if (value == null) {
			return false;
		}

		for (String allowed : values) {
			if (allowed.equalsIgnoreCase(value)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Rejects characters that cannot be passed through to a launcher without changing the
	 * meaning of the generated command line, regardless of any quoting applied below.
	 * @param argument the argument to check
	 * @return true if the argument may be used as a launcher argument
	 */
	static boolean isSafeLaunchArgument(String argument) {
		for (int i = 0; i < argument.length(); i++) {
			char c = argument.charAt(i);
			if (c < 0x20 || c == 0x7f || c == '"') {
				return false;
			}
		}
		return true;
	}

	private static boolean containsShellMetaCharacter(String argument) {
		for (int i = 0; i < argument.length(); i++) {
			if (SHELL_META_CHARACTERS.indexOf(argument.charAt(i)) >= 0) {
				return true;
			}
		}
		return false;
	}

	private static boolean isCmdExeStart(String commandString, String[] commandArguments) {
		return isCommandInterpreter(commandString) && commandArguments.length >= 2 &&
			"/c".equalsIgnoreCase(commandArguments[0]) &&
			"start".equalsIgnoreCase(commandArguments[1]);
	}

	private static boolean isCommandInterpreter(String commandString) {
		if (commandString == null) {
			return false;
		}

		int separator = Math.max(commandString.lastIndexOf('/'), commandString.lastIndexOf('\\'));
		String name = commandString.substring(separator + 1);
		return containsIgnoreCase(COMMAND_INTERPRETERS, name) ||
			StringUtilities.endsWithIgnoreCase(name, ".bat") ||
			StringUtilities.endsWithIgnoreCase(name, ".cmd");
	}

	private static void reportUnsafeURL(URL url) {
		Msg.showError(BrowserLoader.class, null, "Unable to Display URL",
			"Refusing to launch a browser for a URL with an unsupported protocol or with " +
				"characters that the launch command would interpret: " + url);
	}

//==================================================================================================
//  Inner Classes
//==================================================================================================

	static class ImmediateOptionsChangeListener implements OptionsChangeListener {
		private boolean hasChanged = false;

		@Override
		public void optionsChanged(ToolOptions theOptions, String name, Object oldValue, Object newValue) {
			hasChanged = true;
		}

		boolean hasChanged() {
			return hasChanged;
		}
	}

	static class BrowserRunner implements Runnable {
		private final URL url;
		private final ServiceProvider serviceProvider;
		private final URL fileURL;

		private BrowserRunner(URL url, URL fileURL, ServiceProvider serviceProvider) {
			this.url = url;
			this.fileURL = fileURL;
			this.serviceProvider = serviceProvider;
		}

		@Override
		public void run() {
			displayFromBrowserRunner(url, fileURL, serviceProvider);
		}
	}
}
