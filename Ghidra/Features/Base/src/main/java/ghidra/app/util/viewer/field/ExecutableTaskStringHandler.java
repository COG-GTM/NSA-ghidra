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
package ghidra.app.util.viewer.field;

import java.io.*;
import java.util.*;

import docking.options.OptionsService;
import docking.widgets.OptionDialog;
import docking.widgets.fieldpanel.field.AttributedString;
import ghidra.GhidraOptions;
import ghidra.app.nav.Navigatable;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.*;

public class ExecutableTaskStringHandler implements AnnotatedStringHandler {
	private static final String INVALID_SYMBOL_TEXT =
		"@execute annotation must have an executable name";
	private static final String[] SUPPORTED_ANNOTATIONS = { "execute" };
	private static final int MAX_DISPLAY_LENGTH = 200;

	/**
	 * Tool option, in the {@link GhidraOptions#CATEGORY_BROWSER_FIELDS} category, that must be
	 * turned on by the user before an <code>{@literal {@execute}}</code> annotation is allowed to
	 * launch a program.
	 */
	static final String EXECUTE_ENABLED_OPTION_NAME = "Annotations.Enable Execute Annotation";
	private static final String EXECUTE_ENABLED_OPTION_DESCRIPTION =
		"Allows the '{@execute}' comment annotation to launch the program named by the " +
			"annotation when the annotation is double-clicked.  Comments are stored in the program " +
			"database and may come from untrusted sources, such as imported programs, shared " +
			"projects or importers that copy binary contents into comments, so this option is off " +
			"by default.  A confirmation dialog showing the full command is always displayed " +
			"before anything is launched.";

	@Override
	public AttributedString createAnnotatedString(AttributedString prototypeString, String[] text,
			Program program) throws AnnotationException {
		if (text.length <= 1) {
			throw new AnnotationException(INVALID_SYMBOL_TEXT);
		}

		String displayText = getDisplayText(text);
		if (displayText == null) {
			// some kind of error
			throw new AnnotationException(INVALID_SYMBOL_TEXT);
		}

		return new AttributedString(displayText, prototypeString.getColor(0),
			prototypeString.getFontMetrics(0), true, prototypeString.getColor(0));
	}

	private String getDisplayText(String[] text) {
		//
		// We currently support two modes of: 3 parameters or 1. The user can leave off the
		// executable's parameter and display string OR they can have all three.
		//
		if (text.length == 4) {
			return text[3]; // 4 items means they have display text
		}
		else if (text.length != 2) {
			throw new AnnotationException(
				"Invalid number of inputs - " + (text.length - 1) + " found - 1 or 3 required");
		}

		// otherwise, no display text, just use the executable name
		String programInfo = text[1];
		return getDisplayTextForFilePathOrName(programInfo);
	}

	private String getDisplayTextForFilePathOrName(String fileString) {
		File file = new File(fileString);
		if (file.isAbsolute() && file.exists()) {
			return file.getName();
		}
		return fileString;
	}

	@Override
	public String getDisplayString() {
		return "Execute";
	}

	@Override
	public String getPrototypeString() {
		return "{@execute \"executable_path_and_name\" \"arg1 arg2\" \"Display Text\"}";
	}

	@Override
	public String[] getSupportedAnnotations() {
		return SUPPORTED_ANNOTATIONS;
	}

	@Override
	public boolean handleMouseClick(String[] annotationParts, Navigatable sourceNavigatable,
			ServiceProvider serviceProvider) {

		List<String> command = createCommand(annotationParts);
		if (command.isEmpty()) {
			Msg.showError(this, null, "Invalid Execute Annotation", INVALID_SYMBOL_TEXT);
			return false;
		}

		if (SystemUtilities.isInHeadlessMode()) {
			Msg.error(this, "Ignoring '@execute' annotation in headless mode: " +
				getCommandText(command));
			return false;
		}

		ToolOptions options = getFieldOptions(serviceProvider);
		if (options == null || !options.getBoolean(EXECUTE_ENABLED_OPTION_NAME, false)) {
			showExecutionDisabledMessage(serviceProvider, command);
			return true;
		}

		if (!isExecutionConfirmed(command, sourceNavigatable)) {
			Msg.info(this, "User declined to launch '@execute' annotation command: " +
				getCommandText(command));
			return true;
		}

		new ProcessThread(command).start();

		return true;
	}

	/**
	 * Creates the command to launch from the parts of the annotation.  An empty list is returned
	 * when the annotation does not name an executable.
	 *
	 * @param annotationParts the constituent parts of the annotation
	 * @return the command; empty if the annotation is not valid
	 */
	static List<String> createCommand(String[] annotationParts) {

		List<String> command = new ArrayList<>();
		if (annotationParts.length <= 1) {
			return command;
		}

		String executableName = annotationParts[1].trim();
		if (executableName.isEmpty()) {
			return command;
		}
		command.add(executableName);

		if (annotationParts.length > 2) {
			String commandParameterString = annotationParts[2];
			StringTokenizer tokenizer = new StringTokenizer(commandParameterString, " ");
			while (tokenizer.hasMoreTokens()) {
				command.add(tokenizer.nextToken());
			}
		}

		return command;
	}

	private ToolOptions getFieldOptions(ServiceProvider serviceProvider) {

		if (serviceProvider == null) {
			return null;
		}

		OptionsService optionsService = serviceProvider.getService(OptionsService.class);
		if (optionsService == null) {
			return null;
		}

		ToolOptions options = optionsService.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		if (!options.isRegistered(EXECUTE_ENABLED_OPTION_NAME)) {
			options.registerOption(EXECUTE_ENABLED_OPTION_NAME, false,
				new HelpLocation("Annotations", "ExecuteAnnotation"),
				EXECUTE_ENABLED_OPTION_DESCRIPTION);
		}
		return options;
	}

	private void showExecutionDisabledMessage(ServiceProvider serviceProvider,
			List<String> command) {

		Msg.warn(this, "Blocked '@execute' annotation; execution is disabled: " +
			getCommandText(command));

		String message = "<html>This comment contains an '{@execute}' annotation that wants to " +
			"launch:<br><br>" + toDisplayText(getCommandText(command)) +
			"<br><br>Launching programs from annotations is disabled.  Comment text is part of " +
			"the program database and may come from an untrusted source.<br><br>To allow this, " +
			"turn on the '" + EXECUTE_ENABLED_OPTION_NAME + "' option in the '" +
			GhidraOptions.CATEGORY_BROWSER_FIELDS + "' tool options.";

		OptionsService optionsService =
			serviceProvider == null ? null : serviceProvider.getService(OptionsService.class);
		if (optionsService == null) {
			Msg.showWarn(this, null, "Execute Annotation Disabled", message);
			return;
		}

		int choice = OptionDialog.showOptionDialogWithCancelAsDefaultButton(null,
			"Execute Annotation Disabled", message, "Show Options...",
			OptionDialog.WARNING_MESSAGE);
		if (choice == OptionDialog.OPTION_ONE) {
			optionsService.showOptionsDialog(GhidraOptions.CATEGORY_BROWSER_FIELDS,
				"Execute Annotation");
		}
	}

	private boolean isExecutionConfirmed(List<String> command, Navigatable sourceNavigatable) {

		List<String> arguments = command.subList(1, command.size());

		StringBuilder buffy = new StringBuilder("<html>An '{@execute}' comment annotation wants " +
			"to launch the following program:<br><br><b>Program:</b> ");
		buffy.append(toDisplayText(command.get(0)));
		buffy.append("<br><b>Arguments:</b> ");
		buffy.append(
			arguments.isEmpty() ? "&lt;none&gt;" : toDisplayText(String.join(" ", arguments)));

		String source = getSourceText(sourceNavigatable);
		if (source != null) {
			buffy.append("<br><b>Annotation from:</b> ").append(toDisplayText(source));
		}

		buffy.append("<br><br>Comments are stored in the program database and may have been " +
			"created by an untrusted source.<br>The program above will run with your " +
			"permissions.  Only continue if you trust this command.");

		int choice = OptionDialog.showOptionDialogWithCancelAsDefaultButton(null,
			"Launch Program From Annotation?", buffy.toString(), "Launch Program",
			OptionDialog.WARNING_MESSAGE);
		return choice == OptionDialog.OPTION_ONE;
	}

	private String getSourceText(Navigatable sourceNavigatable) {

		if (sourceNavigatable == null) {
			return null;
		}

		Program program = sourceNavigatable.getProgram();
		if (program == null) {
			return null;
		}
		return program.getDomainFile().getPathname();
	}

	private static String getCommandText(List<String> command) {
		return String.join(" ", command);
	}

	/**
	 * Makes the given annotation text safe to place inside of an html dialog message.  Long text
	 * is truncated so that an oversized annotation cannot push the dialog's buttons off screen.
	 *
	 * @param text the text
	 * @return the escaped, possibly truncated, text
	 */
	private static String toDisplayText(String text) {
		return HTMLUtilities.escapeHTML(StringUtilities.trimMiddle(text, MAX_DISPLAY_LENGTH));
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class ProcessThread extends Thread {

		private final List<String> command;

		ProcessThread(List<String> command) {
			super("Process Runner - " + command.get(0));
			this.command = command;
		}

		@Override
		public void run() {
			ProcessBuilder processBuilder = new ProcessBuilder(command);
			processBuilder = processBuilder.redirectErrorStream(true);

			IOThread ioThread = null;
			StringBuilder buffer = new StringBuilder();
			int exitValue = 1;
			InputStream inputStream = null;
			Process process = null;
			String executableName = command.get(0);
			try {
				Msg.info(this, "Launching process: " + executableName);
				process = processBuilder.start();
				inputStream = process.getInputStream();
				ioThread = new IOThread(buffer, inputStream);
				ioThread.start();
				exitValue = process.waitFor();
				ioThread.join();
				inputStream.close();
			}
			catch (Exception e) {
				Msg.showError(this, null, "Error Launching Executable",
					"Unexpected exception trying to launch process: " + executableName, e);

			}
			finally {
				if (inputStream != null) {
					try {
						inputStream.close();
					}
					catch (IOException e) {
						// ignore; we tried
					}
				}
			}

			if (exitValue != 0) {
				Msg.warn(this, "Process \"" + executableName + "\" exited abnormally with value: " +
					exitValue);
			}
		}
	}

	private static class IOThread extends Thread {
		private BufferedReader shellOutput;
		private StringBuilder buffer;

		IOThread(StringBuilder buffer, InputStream input) {
			super("IO Thread - Executable Annotation Task");
			this.buffer = buffer;
			shellOutput = new BufferedReader(new InputStreamReader(input));
		}

		@Override
		public void run() {
			String line = null;
			try {
				while ((line = shellOutput.readLine()) != null) {
					buffer.append(line).append('\n');
				}
			}
			catch (Exception e) {
				Msg.error(this, "Exception reading output for executable annotation", e);
				buffer = null;
			}
		}
	}

	@Override
	public String getPrototypeString(String displayText) {
		return "{@execute " + displayText.trim() + "}";
	}
}
