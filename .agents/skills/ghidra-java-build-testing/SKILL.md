---
name: ghidra-java-build-testing
description: How to compile Ghidra Java modules and run headed integration tests in this repo, including the maven-central 429 workaround.
---

# Ghidra Java build & test in this environment

- Gradle 8.14 is at `/opt/gradle-8.14/bin/gradle` (Java 21 works).
- Bootstrap order: `gradle -I gradle/support/fetchDependencies.gradle` then `gradle prepDev` (~1 min after deps are cached).
- `repo.maven.apache.org` may return persistent HTTP 429 from this box. Workaround: use the Google mirror `https://maven-central.storage-download.googleapis.com/maven2/`:
  - For fetchDependencies' own initscript block, temporarily edit line 43 of `gradle/support/fetchDependencies.gradle` (`repositories { mavenCentral() }`) to the mirror URL — REVERT this edit afterwards, never commit it.
  - For project dependency resolution, pass an extra init script (`-I /tmp/mirror-init.gradle`) that remaps any MavenArtifactRepository URL containing `repo.maven.apache.org` to the mirror (see /tmp/mirror-init.gradle pattern with `repositories.all { ... repo.url = mirror }`).
- Compile a module: `gradle :ModuleName:compileJava` (e.g. :Debugger:, :Decompiler:, :Base:, :FunctionGraph:, :VersionTracking:, :MachineLearning:, :CodeCompare:).
- Test source sets: `src/test/java` → task `:Module:test`; `src/test.slow/java` → source set `integrationTest`, compile with `:Module:compileIntegrationTestJava`, run with `:Module:integrationTest --tests fully.qualified.ClassName`.
- Headed tests (AbstractGhidraHeadedIntegrationTest) need a DISPLAY; the desktop `:0` works as-is.
- Tests that spin up the decompiler (DecompInterface.openProgram / FillOutStructureHelper.setUpDecompiler) silently return null unless the native decompiler exists: run `gradle :Decompiler:buildNatives` first (produces `Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile`).
- Native decompiler C++ regression suite: build `decomp_test_dbg` in `Ghidra/Features/Decompiler/src/decompile/cpp`; requires compiled .sla files under Ghidra/Processors (do not commit .sla artifacts or `sleigh_opt`).
