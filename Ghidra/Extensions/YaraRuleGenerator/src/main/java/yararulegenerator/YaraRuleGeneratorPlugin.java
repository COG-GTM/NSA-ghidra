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
package yararulegenerator;

import docking.action.builder.ActionBuilder;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;

import javax.swing.JFileChooser;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = "YaraRuleGenerator",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Generate YARA rules from selection",
	description = "Generates YARA rules from selected functions, " +
		"code blocks, or data regions in the listing view."
)
//@formatter:on
public class YaraRuleGeneratorPlugin extends Plugin {

	public YaraRuleGeneratorPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	private void createActions() {
		new ActionBuilder("Generate YARA Rule", getName())
			.popupMenuPath("Generate YARA Rule")
			.popupMenuGroup("YARA")
			.description("Generate a YARA rule from the current selection")
			.withContext(ListingActionContext.class)
			.enabledWhen(ctx -> {
				ProgramSelection sel = ctx.getSelection();
				return sel != null && !sel.isEmpty();
			})
			.onAction(this::generateYaraRule)
			.buildAndInstall(tool);
	}

	private void generateYaraRule(ListingActionContext context) {
		Program program = context.getProgram();
		ProgramSelection selection = context.getSelection();

		// 1. Extract byte patterns with wildcards for variable operands
		YaraBytePatternExtractor extractor = new YaraBytePatternExtractor(program);
		List<String> hexPatterns = extractor.extractPatterns(selection);

		// 2. Find high-value string indicators in the selected region
		YaraStringIndicatorFinder stringFinder = new YaraStringIndicatorFinder(program);
		Map<String, String> stringIndicators = stringFinder.findIndicators(selection);

		// 3. Build the YARA rule
		YaraRuleBuilder builder = new YaraRuleBuilder();
		String ruleName = sanitizeRuleName(program.getName());
		builder.setRuleName(ruleName);

		String md5 = program.getExecutableMD5();
		String sha256 = program.getExecutableSHA256();
		if (md5 == null || md5.isEmpty()) {
			md5 = "unknown";
		}
		if (sha256 == null || sha256.isEmpty()) {
			sha256 = "unknown";
		}

		builder.setMetadata(
			md5,
			sha256,
			System.getProperty("user.name", "analyst"),
			new SimpleDateFormat("yyyy-MM-dd").format(new Date()),
			"Auto-generated YARA rule from Ghidra analysis"
		);
		builder.addBytePatterns(hexPatterns);
		builder.addStringIndicators(stringIndicators);
		String yaraRule = builder.build();

		// 4. Output to console
		Msg.info(this, "Generated YARA Rule:\n" + yaraRule);

		// 5. Prompt to save to file
		JFileChooser chooser = new JFileChooser();
		chooser.setSelectedFile(new File(ruleName + ".yar"));
		if (chooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
			try (FileWriter fw = new FileWriter(chooser.getSelectedFile())) {
				fw.write(yaraRule);
				Msg.info(this, "YARA rule saved to: " +
					chooser.getSelectedFile().getAbsolutePath());
			}
			catch (IOException e) {
				Msg.showError(this, null, "Error", "Failed to save YARA rule", e);
			}
		}
	}

	private String sanitizeRuleName(String name) {
		return name.replaceAll("[^a-zA-Z0-9_]", "_");
	}
}
