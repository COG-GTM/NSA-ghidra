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
//@category ExternalDependencies

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import externaldependencyanalyzer.DependencyFinding;
import externaldependencyanalyzer.ExternalDependencyExporter;
import externaldependencyanalyzer.ExternalDependencyScanner;
import ghidra.app.script.GhidraScript;

public class ExportExternalDependenciesScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		List<DependencyFinding> findings = ExternalDependencyScanner.scan(currentProgram,
			monitor);
		String json = ExternalDependencyExporter.toJson(currentProgram, findings);
		String markdown = ExternalDependencyExporter.toMarkdown(currentProgram, findings);
		if (getScriptArgs().length == 0) {
			printf("%s%n%s", json, markdown);
			return;
		}
		Files.writeString(Path.of(getScriptArgs()[0]), json);
		if (getScriptArgs().length > 1) {
			Files.writeString(Path.of(getScriptArgs()[1]), markdown);
		}
		else {
			printf("%s", markdown);
		}
	}
}
