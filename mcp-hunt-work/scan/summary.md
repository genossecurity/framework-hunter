# mcp-hunt scan summary — 2026-11-03 10:20

- Targets: 141 (141 scanned, 0 with no JS/TS/Python files scanned, 0 failed)
- Tiers run: taint, helper
- Tools exposed across scanned servers (heuristic count): 5799
- taint findings: 236
- helper findings: 27507
- **Priority queue** (taint, or helper reached from tool code): 10201 in 102 repos

Candidates are not vulnerabilities. Each needs: reachable from a tool arg, no containment/sanitization, a local PoC, then disclosure. Track that in findings.csv.

## Priority findings by rule

| rule | count |
|---|---|
| mcp-js-path-traversal | 6955 |
| mcp-js-sql-injection | 1040 |
| mcp-js-argument-injection | 917 |
| mcp-js-ssrf | 819 |
| mcp-py-path-traversal | 224 |
| mcp-js-command-injection | 172 |
| mcp-py-argument-injection | 32 |
| mcp-js-code-injection | 24 |
| mcp-py-ssrf | 8 |
| mcp-py-sql-injection | 8 |
| mcp-py-command-injection | 2 |

## Triage queue (priority findings, highest severity first)

| sev | tier | repo | tool / function | rule | reach | location |
|---|---|---|---|---|---|---|
| ERROR | helper | ChristopherVR__ooxml | open() | mcp-js-command-injection | called from tool file: freeform-tool-overlay.component.ts -> label -> run -> open | [apps/office-suite/src/session.js:27](https://github.com/ChristopherVR/ooxml/blob/323f7d5f8a8c/apps/office-suite/src/session.js#L27) |
| ERROR | helper | ChristopherVR__ooxml | runCommand() | mcp-js-command-injection | called from tool file: node.ts -> target -> runCommand | [viewers/pptx/packages/cli/src/run-command.ts:34](https://github.com/ChristopherVR/ooxml/blob/323f7d5f8a8c/viewers/pptx/packages/cli/src/run-command.ts#L34) |
| ERROR | helper | Cotal-AI__Cotal | pass() | mcp-js-command-injection | called from tool file: scopes.smoke.ts -> pass | [implementations/cli/src/lib/persona-files.ts:256](https://github.com/Cotal-AI/Cotal/blob/7e3f333383d8/implementations/cli/src/lib/persona-files.ts#L256) |
| ERROR | helper | Cotal-AI__Cotal | evaluate() | mcp-js-code-injection | called from tool file: run-driver-auth.smoke.ts -> issue -> evaluate | [packages/lang/smoke/differential.smoke.ts:109](https://github.com/Cotal-AI/Cotal/blob/7e3f333383d8/packages/lang/smoke/differential.smoke.ts#L109) |
| ERROR | helper | DayuanJiang__next-ai-draw-io | openBrowser() | mcp-js-command-injection | inside tool file | [packages/mcp-server/src/index.ts:439](https://github.com/DayuanJiang/next-ai-draw-io/blob/c9dc5f5cc62e/packages/mcp-server/src/index.ts#L439) |
| ERROR | helper | JKHeadley__instar | compileSchema() | mcp-js-code-injection | inside tool file | [packages/threadline-mcp/.smithery/shttp/module.js:2942](https://github.com/JKHeadley/instar/blob/7b824562012a/packages/threadline-mcp/.smithery/shttp/module.js#L2942) |
| ERROR | helper | JKHeadley__instar | git() | mcp-js-command-injection | called from tool file: server.ts -> read -> git | [src/core/InstarWorktreeManager.ts:142](https://github.com/JKHeadley/instar/blob/7b824562012a/src/core/InstarWorktreeManager.ts#L142) |
| ERROR | helper | JKHeadley__instar | done() | mcp-js-command-injection | called from tool file: module.js -> abort -> done | [src/core/MeshUrlAdvertiser.ts:213](https://github.com/JKHeadley/instar/blob/7b824562012a/src/core/MeshUrlAdvertiser.ts#L213) |
| ERROR | helper | JKHeadley__instar | raw() | mcp-js-command-injection | called from tool file: server.ts -> raw | [src/monitoring/greenPrAutomergeWiring.ts:369](https://github.com/JKHeadley/instar/blob/7b824562012a/src/monitoring/greenPrAutomergeWiring.ts#L369) |
| ERROR | helper | JKHeadley__instar | raw() | mcp-js-command-injection | called from tool file: server.ts -> raw | [src/monitoring/greenPrAutomergeWiring.ts:382](https://github.com/JKHeadley/instar/blob/7b824562012a/src/monitoring/greenPrAutomergeWiring.ts#L382) |
| ERROR | helper | JKHeadley__instar | raw() | mcp-js-command-injection | called from tool file: server.ts -> raw | [src/monitoring/greenPrAutomergeWiring.ts:385](https://github.com/JKHeadley/instar/blob/7b824562012a/src/monitoring/greenPrAutomergeWiring.ts#L385) |
| ERROR | helper | JKHeadley__instar | testTmuxFdaAccess() | mcp-js-command-injection | called from tool file: module.js -> fail -> run -> testTmuxFdaAccess | [src/monitoring/probes/PlatformProbe.ts:39](https://github.com/JKHeadley/instar/blob/7b824562012a/src/monitoring/probes/PlatformProbe.ts#L39) |
| ERROR | helper | JKHeadley__instar | testTmuxFdaAccess() | mcp-js-command-injection | called from tool file: module.js -> fail -> run -> testTmuxFdaAccess | [src/monitoring/probes/PlatformProbe.ts:48](https://github.com/JKHeadley/instar/blob/7b824562012a/src/monitoring/probes/PlatformProbe.ts#L48) |
| ERROR | helper | JKHeadley__instar | testTmuxFdaAccess() | mcp-js-command-injection | called from tool file: module.js -> fail -> run -> testTmuxFdaAccess | [src/monitoring/probes/PlatformProbe.ts:58](https://github.com/JKHeadley/instar/blob/7b824562012a/src/monitoring/probes/PlatformProbe.ts#L58) |
| ERROR | helper | JKHeadley__instar | spawn() | mcp-js-command-injection | called from tool file: server.ts -> release -> spawn | [src/threadline/PipeSessionSpawner.ts:395](https://github.com/JKHeadley/instar/blob/7b824562012a/src/threadline/PipeSessionSpawner.ts#L395) |
| ERROR | helper | JKHeadley__instar | spawn() | mcp-js-command-injection | called from tool file: server.ts -> release -> spawn | [src/threadline/PipeSessionSpawner.ts:489](https://github.com/JKHeadley/instar/blob/7b824562012a/src/threadline/PipeSessionSpawner.ts#L489) |
| ERROR | helper | JKHeadley__instar | spawn() | mcp-js-command-injection | called from tool file: server.ts -> release -> spawn | [src/threadline/PipeSessionSpawner.ts:497](https://github.com/JKHeadley/instar/blob/7b824562012a/src/threadline/PipeSessionSpawner.ts#L497) |
| ERROR | helper | JKHeadley__instar | killPipeSession() | mcp-js-command-injection | called from tool file: server.ts -> release -> spawn -> killPipeSession | [src/threadline/PipeSessionSpawner.ts:588](https://github.com/JKHeadley/instar/blob/7b824562012a/src/threadline/PipeSessionSpawner.ts#L588) |
| ERROR | helper | JKHeadley__instar | killPipeSession() | mcp-js-command-injection | called from tool file: server.ts -> release -> spawn -> killPipeSession | [src/threadline/PipeSessionSpawner.ts:597](https://github.com/JKHeadley/instar/blob/7b824562012a/src/threadline/PipeSessionSpawner.ts#L597) |
| ERROR | helper | JKHeadley__instar | killPipeSession() | mcp-js-command-injection | called from tool file: server.ts -> release -> spawn -> killPipeSession | [src/threadline/PipeSessionSpawner.ts:618](https://github.com/JKHeadley/instar/blob/7b824562012a/src/threadline/PipeSessionSpawner.ts#L618) |
| ERROR | helper | JKHeadley__instar | killPipeSession() | mcp-js-command-injection | called from tool file: server.ts -> release -> spawn -> killPipeSession | [src/threadline/PipeSessionSpawner.ts:641](https://github.com/JKHeadley/instar/blob/7b824562012a/src/threadline/PipeSessionSpawner.ts#L641) |
| ERROR | helper | MCPJam__inspector | displayIsUp() | mcp-js-code-injection | called from tool file: browser.ts -> onAbort -> finish -> ensureDisplay -> displayIsUp | [mcpjam-inspector/server/services/browserd/boot-browserd.ts:140](https://github.com/MCPJam/inspector/blob/a9d64c864ce7/mcpjam-inspector/server/services/browserd/boot-browserd.ts#L140) |
| ERROR | helper | MetaMask__device-mcp | dispose() | mcp-js-command-injection | called from tool file: select-device.ts -> getDeviceInfo -> ensureConnected -> reconnect -> dispose | [src/backends/idb-backend.ts:194](https://github.com/MetaMask/device-mcp/blob/b7e63d3982e6/src/backends/idb-backend.ts#L194) |
| ERROR | helper | MetaMask__device-mcp | dispose() | mcp-js-command-injection | called from tool file: select-device.ts -> getDeviceInfo -> ensureConnected -> reconnect -> dispose | [src/backends/idb-backend.ts:200](https://github.com/MetaMask/device-mcp/blob/b7e63d3982e6/src/backends/idb-backend.ts#L200) |
| ERROR | helper | MetaMask__device-mcp | connect() | mcp-js-command-injection | called from tool file: select-device.ts -> getDeviceInfo -> ensureConnected -> connect | [src/backends/idb-connection.ts:69](https://github.com/MetaMask/device-mcp/blob/b7e63d3982e6/src/backends/idb-connection.ts#L69) |
| ERROR | helper | MetaMask__device-mcp | execStrict() | mcp-js-command-injection | called from tool file: screen-recording.ts -> stopScreenRecording -> execStrict | [src/utils/exec.ts:61](https://github.com/MetaMask/device-mcp/blob/b7e63d3982e6/src/utils/exec.ts#L61) |
| ERROR | helper | SAP__mdk-mcp-server | runCommand() | mcp-js-command-injection | called from tool file: index.ts -> runCommand | [src/utils.ts:405](https://github.com/SAP/mdk-mcp-server/blob/1f1a4364bac8/src/utils.ts#L405) |
| ERROR | helper | agentistics__agentistics | planHarnessInstall() | mcp-js-command-injection | called from tool file: agentistics-mcp.ts -> patch -> commit -> failed -> planHarnessInstall | [packages/server/server/sessions/harness-install-plan.ts:142](https://github.com/agentistics/agentistics/blob/d4ae9989a38a/packages/server/server/sessions/harness-install-plan.ts#L142) |
| ERROR | helper | anis-marrouchi__agentx | finish() | mcp-js-command-injection | called from tool file: chat.ts -> finish | [src/actions/runner.ts:70](https://github.com/anis-marrouchi/agentx/blob/2c7ef816bc73/src/actions/runner.ts#L70) |
| ERROR | helper | anis-marrouchi__agentx | cap() | mcp-js-command-injection | called from tool file: chat.ts -> now -> decide -> recordAnswered -> cap | [src/commands/usage.ts:148](https://github.com/anis-marrouchi/agentx/blob/2c7ef816bc73/src/commands/usage.ts#L148) |
| ERROR | helper | anis-marrouchi__agentx | post() | mcp-js-command-injection | called from tool file: mesh.ts -> sendTask -> post | [src/native/macos/banner.ts:40](https://github.com/anis-marrouchi/agentx/blob/2c7ef816bc73/src/native/macos/banner.ts#L40) |
| ERROR | helper | anis-marrouchi__agentx | listOpen() | mcp-js-command-injection | called from tool file: signal.ts -> resume -> route -> listOpen | [src/native/macos/tasks.ts:47](https://github.com/anis-marrouchi/agentx/blob/2c7ef816bc73/src/native/macos/tasks.ts#L47) |
| ERROR | helper | anis-marrouchi__agentx | update() | mcp-js-command-injection | called from tool file: chat.ts -> agents -> save -> write -> update | [src/native/macos/tasks.ts:72](https://github.com/anis-marrouchi/agentx/blob/2c7ef816bc73/src/native/macos/tasks.ts#L72) |
| ERROR | helper | anis-marrouchi__agentx | remove() | mcp-js-command-injection | called from tool file: http.ts -> cancel -> drop -> remove | [src/native/macos/tasks.ts:78](https://github.com/anis-marrouchi/agentx/blob/2c7ef816bc73/src/native/macos/tasks.ts#L78) |
| ERROR | helper | anis-marrouchi__agentx | post() | mcp-js-command-injection | called from tool file: mesh.ts -> sendTask -> post | [src/native/windows/banner.ts:39](https://github.com/anis-marrouchi/agentx/blob/2c7ef816bc73/src/native/windows/banner.ts#L39) |
| ERROR | helper | anis-marrouchi__agentx | downloadMedia() | mcp-js-command-injection | called from tool file: channel.ts -> relateIssue -> log -> mediaDescriber -> downloadMedia | [src/whatsapp-triage/wacli.ts:39](https://github.com/anis-marrouchi/agentx/blob/2c7ef816bc73/src/whatsapp-triage/wacli.ts#L39) |
| ERROR | helper | anis-marrouchi__agentx | git() | mcp-js-command-injection | called from tool file: http.ts -> done -> git | [tsup.config.ts:13](https://github.com/anis-marrouchi/agentx/blob/2c7ef816bc73/tsup.config.ts#L13) |
| ERROR | helper | artokun__comfyui-mcp | probePortOwner() | mcp-js-command-injection | called from tool file: process-control.ts -> stopComfyUI -> probePortOwner | [src/services/port-owner.ts:885](https://github.com/artokun/comfyui-mcp/blob/5bfe534ed114/src/services/port-owner.ts#L885) |
| ERROR | helper | artokun__comfyui-mcp | killProcessTree() | mcp-js-command-injection | called from tool file: process-control.ts -> stopComfyUI -> killProcessTree | [src/services/process-control.ts:677](https://github.com/artokun/comfyui-mcp/blob/5bfe534ed114/src/services/process-control.ts#L677) |
| ERROR | helper | artokun__comfyui-mcp | killProcessTree() | mcp-js-command-injection | called from tool file: process-control.ts -> stopComfyUI -> killProcessTree | [src/services/process-control.ts:690](https://github.com/artokun/comfyui-mcp/blob/5bfe534ed114/src/services/process-control.ts#L690) |
| ERROR | helper | artokun__comfyui-mcp | restartViaConfiguredCommand() | mcp-js-command-injection | called from tool file: panel-tools.ts -> restartComfyUI -> restartViaConfiguredCommand | [src/services/process-control.ts:6194](https://github.com/artokun/comfyui-mcp/blob/5bfe534ed114/src/services/process-control.ts#L6194) |
| ERROR | helper | asklokesh__loki-mode | prepare() | mcp-py-command-injection | called from tool file: server.py -> prepare | [autonomy/lib/workspace.py:160](https://github.com/asklokesh/loki-mode/blob/e504a5060099/autonomy/lib/workspace.py#L160) |
| ERROR | helper | cline__cline | webEvaluate() | mcp-js-code-injection | called from tool file: user-instruction-service.ts -> start -> stop -> handleCommand -> webEvaluate | [apps/vscode/src/dev/debug-harness/server.ts:776](https://github.com/cline/cline/blob/5b454165353a/apps/vscode/src/dev/debug-harness/server.ts#L776) |
| ERROR | helper | cline__cline | pendingPrompts() | mcp-js-command-injection | called from tool file: templates.ts -> project -> abort -> pendingPrompts | [sdk/packages/core/src/cloud/controller.ts:2063](https://github.com/cline/cline/blob/5b454165353a/sdk/packages/core/src/cloud/controller.ts#L2063) |
| ERROR | helper | cline__cline | commandIfSupported() | mcp-js-command-injection | called from tool file: plugin-registry.ts -> list -> commandIfSupported | [sdk/packages/core/src/hub/client/plugin-commands.ts:21](https://github.com/cline/cline/blob/5b454165353a/sdk/packages/core/src/hub/client/plugin-commands.ts#L21) |
| ERROR | helper | cline__cline | command() | mcp-js-command-injection | called from tool file: templates.ts -> command | [sdk/packages/core/src/hub/client/providers.ts:14](https://github.com/cline/cline/blob/5b454165353a/sdk/packages/core/src/hub/client/providers.ts#L14) |
| ERROR | helper | cline__cline | connect() | mcp-js-command-injection | called from tool file: plugin-registry.ts -> cleanup -> dispose -> connect | [sdk/packages/core/src/hub/client/session-client.ts:316](https://github.com/cline/cline/blob/5b454165353a/sdk/packages/core/src/hub/client/session-client.ts#L316) |
| ERROR | helper | cline__cline | onMessage() | mcp-js-command-injection | called from tool file: user-instruction-service.ts -> start -> onMessage | [sdk/packages/core/src/hub/server/browser-websocket.ts:212](https://github.com/cline/cline/blob/5b454165353a/sdk/packages/core/src/hub/server/browser-websocket.ts#L212) |
| ERROR | helper | cline__cline | stop() | mcp-js-command-injection | called from tool file: user-instruction-service.ts -> start -> stop | [sdk/packages/core/src/hub/server/hub-server-transport.ts:924](https://github.com/cline/cline/blob/5b454165353a/sdk/packages/core/src/hub/server/hub-server-transport.ts#L924) |
| ERROR | helper | corsairdev__corsair | handler() | mcp-js-code-injection | called from tool file: openai-agents.ts -> handler | [packages/mcp/src/core/tools.ts:92](https://github.com/corsairdev/corsair/blob/db9e8b6f06c1/packages/mcp/src/core/tools.ts#L92) |
| ERROR | helper | decocms__studio | ensureTenantUser() | mcp-js-command-injection | called from tool file: index.ts -> queryCustomerLake -> ensureTenantUser | [apps/api/src/customer-lake/client.ts:94](https://github.com/decocms/studio/blob/59b48462e74b/apps/api/src/customer-lake/client.ts#L94) |
| ERROR | helper | decocms__studio | ensureTenantUser() | mcp-js-command-injection | called from tool file: index.ts -> queryCustomerLake -> ensureTenantUser | [apps/api/src/customer-lake/client.ts:97](https://github.com/decocms/studio/blob/59b48462e74b/apps/api/src/customer-lake/client.ts#L97) |
| ERROR | helper | decocms__studio | put() | mcp-js-command-injection | called from tool file: site-ground.ts -> put | [packages/sandbox/server/provider/postgres-state-store.ts:127](https://github.com/decocms/studio/blob/59b48462e74b/packages/sandbox/server/provider/postgres-state-store.ts#L127) |
| ERROR | helper | foldkit__foldkit | killQuery() | mcp-js-command-injection | called from tool file: McpServer.ts -> onError -> killQuery | [repos/effect/packages/sql/clickhouse/src/ClickhouseClient.ts:89](https://github.com/foldkit/foldkit/blob/a471adb24d75/repos/effect/packages/sql/clickhouse/src/ClickhouseClient.ts#L89) |
| ERROR | helper | foldkit__foldkit | runRaw() | mcp-js-command-injection | called from tool file: httpApiSwagger.ts -> try -> runRaw | [repos/effect/packages/sql/clickhouse/src/ClickhouseClient.ts:252](https://github.com/foldkit/foldkit/blob/a471adb24d75/repos/effect/packages/sql/clickhouse/src/ClickhouseClient.ts#L252) |
| ERROR | helper | foldkit__foldkit | try() | mcp-js-command-injection | called from tool file: httpApiSwagger.ts -> try | [repos/effect/packages/sql/sqlite-bun/src/SqliteClient.ts:172](https://github.com/foldkit/foldkit/blob/a471adb24d75/repos/effect/packages/sql/sqlite-bun/src/SqliteClient.ts#L172) |
| ERROR | helper | foldkit__foldkit | try() | mcp-js-command-injection | called from tool file: httpApiSwagger.ts -> try | [repos/effect/packages/sql/sqlite-bun/src/SqliteClient.ts:184](https://github.com/foldkit/foldkit/blob/a471adb24d75/repos/effect/packages/sql/sqlite-bun/src/SqliteClient.ts#L184) |
| ERROR | helper | foldkit__foldkit | try() | mcp-js-command-injection | called from tool file: httpApiSwagger.ts -> try | [repos/effect/packages/sql/sqlite-bun/src/SqliteClient.ts:192](https://github.com/foldkit/foldkit/blob/a471adb24d75/repos/effect/packages/sql/sqlite-bun/src/SqliteClient.ts#L192) |
| ERROR | helper | foldkit__foldkit | try() | mcp-js-command-injection | called from tool file: httpApiSwagger.ts -> try | [repos/effect/packages/sql/sqlite-node/src/SqliteClient.ts:170](https://github.com/foldkit/foldkit/blob/a471adb24d75/repos/effect/packages/sql/sqlite-node/src/SqliteClient.ts#L170) |
| ERROR | helper | foldkit__foldkit | try() | mcp-js-command-injection | called from tool file: httpApiSwagger.ts -> try | [repos/effect/packages/sql/sqlite-node/src/SqliteClient.ts:188](https://github.com/foldkit/foldkit/blob/a471adb24d75/repos/effect/packages/sql/sqlite-node/src/SqliteClient.ts#L188) |
| ERROR | helper | griffinwork40__agent-afk | git() | mcp-js-command-injection | called from tool file: tool-card.ts -> formatElapsed -> now -> git | [src/agent/subagent/continuation-guards.ts:145](https://github.com/griffinwork40/agent-afk/blob/33e0051b03ff/src/agent/subagent/continuation-guards.ts#L145) |
| ERROR | helper | griffinwork40__agent-afk | finish() | mcp-js-command-injection | called from tool file: tool-card.ts -> formatElapsed -> now -> kill -> finish | [src/agent/worktree/worktree-setup.ts:134](https://github.com/griffinwork40/agent-afk/blob/33e0051b03ff/src/agent/worktree/worktree-setup.ts#L134) |
| ERROR | helper | mastra-ai__mastra | startRegistry() | mcp-js-command-injection | called from tool file: client.ts -> fail -> teardown -> startRegistry | [e2e-tests/_local-registry-setup/registry.js:77](https://github.com/mastra-ai/mastra/blob/42004349c10c/e2e-tests/_local-registry-setup/registry.js#L77) |
| ERROR | helper | mastra-ai__mastra | startRegistry() | mcp-js-command-injection | called from tool file: client.ts -> fail -> teardown -> startRegistry | [e2e-tests/_local-registry-setup/registry.js:78](https://github.com/mastra-ai/mastra/blob/42004349c10c/e2e-tests/_local-registry-setup/registry.js#L78) |
| ERROR | helper | mastra-ai__mastra | check() | mcp-js-command-injection | inside tool file | [explorations/network-validation-bridge.ts:125](https://github.com/mastra-ai/mastra/blob/42004349c10c/explorations/network-validation-bridge.ts#L125) |
| ERROR | helper | mastra-ai__mastra | check() | mcp-js-command-injection | inside tool file | [explorations/ralph-wiggum-loop-prototype.ts:84](https://github.com/mastra-ai/mastra/blob/42004349c10c/explorations/ralph-wiggum-loop-prototype.ts#L84) |
| ERROR | helper | mastra-ai__mastra | check() | mcp-js-command-injection | inside tool file | [explorations/ralph-wiggum-loop-prototype.ts:108](https://github.com/mastra-ai/mastra/blob/42004349c10c/explorations/ralph-wiggum-loop-prototype.ts#L108) |
| ERROR | helper | mastra-ai__mastra | check() | mcp-js-command-injection | inside tool file | [explorations/ralph-wiggum-loop-prototype.ts:132](https://github.com/mastra-ai/mastra/blob/42004349c10c/explorations/ralph-wiggum-loop-prototype.ts#L132) |
| ERROR | helper | mastra-ai__mastra | git() | mcp-js-command-injection | called from tool file: template-builder.ts -> git | [mastracode/sdk/src/utils/project.ts:38](https://github.com/mastra-ai/mastra/blob/42004349c10c/mastracode/sdk/src/utils/project.ts#L38) |
| ERROR | helper | mastra-ai__mastra | evaluateZodExpression() | mcp-js-code-injection | called from tool file: mcp-transport-test-suite.ts -> invalid -> visit -> evaluateZodExpression | [packages/_types-builder/src/compile-zod.js:31](https://github.com/mastra-ai/mastra/blob/42004349c10c/packages/_types-builder/src/compile-zod.js#L31) |
| ERROR | helper | mastra-ai__mastra | processDirectory() | mcp-js-command-injection | inside tool file | [packages/agent-builder/src/defaults.ts:2885](https://github.com/mastra-ai/mastra/blob/42004349c10c/packages/agent-builder/src/defaults.ts#L2885) |
| ERROR | helper | mastra-ai__mastra | resolveZodSchema() | mcp-js-code-injection | called from tool file: ai-sdk-turn-step.ts -> prepare -> validate -> getValidator -> resolveZodSchema | [packages/core/src/datasets/validation/validator.ts:16](https://github.com/mastra-ai/mastra/blob/42004349c10c/packages/core/src/datasets/validation/validator.ts#L16) |
| ERROR | helper | mastra-ai__mastra | resolveSerializedZodOutput() | mcp-js-code-injection | called from tool file: agent.ts -> ensureToolProperties -> setVercelToolProperties -> convertVercelToolParameters -> resolveSerializedZodOutput | [packages/core/src/utils.ts:276](https://github.com/mastra-ai/mastra/blob/42004349c10c/packages/core/src/utils.ts#L276) |
| ERROR | helper | mastra-ai__mastra | createChildProcessLogger() | mcp-js-command-injection | called from tool file: utils.ts -> installPackages -> createChildProcessLogger | [packages/deployer/src/deploy/log.ts:39](https://github.com/mastra-ai/mastra/blob/42004349c10c/packages/deployer/src/deploy/log.ts#L39) |
| ERROR | helper | mastra-ai__mastra | xAdd() | mcp-js-command-injection | called from tool file: index.ts -> nack -> xAdd | [pubsub/valkey-streams/src/client.ts:78](https://github.com/mastra-ai/mastra/blob/42004349c10c/pubsub/valkey-streams/src/client.ts#L78) |
| ERROR | helper | mastra-ai__mastra | xGroupDestroy() | mcp-js-command-injection | called from tool file: index.ts -> unsubscribe -> xGroupDestroy | [pubsub/valkey-streams/src/client.ts:87](https://github.com/mastra-ai/mastra/blob/42004349c10c/pubsub/valkey-streams/src/client.ts#L87) |
| ERROR | helper | mastra-ai__mastra | xRange() | mcp-js-command-injection | called from tool file: multi-connection.ts -> active -> xRange | [pubsub/valkey-streams/src/client.ts:142](https://github.com/mastra-ai/mastra/blob/42004349c10c/pubsub/valkey-streams/src/client.ts#L142) |
| ERROR | helper | mastra-ai__mastra | xRevRange() | mcp-js-command-injection | called from tool file: multi-connection.ts -> active -> xRevRange | [pubsub/valkey-streams/src/client.ts:145](https://github.com/mastra-ai/mastra/blob/42004349c10c/pubsub/valkey-streams/src/client.ts#L145) |
| ERROR | helper | mastra-ai__mastra | xInfoGroups() | mcp-js-command-injection | called from tool file: multi-connection.ts -> active -> xInfoGroups | [pubsub/valkey-streams/src/client.ts:149](https://github.com/mastra-ai/mastra/blob/42004349c10c/pubsub/valkey-streams/src/client.ts#L149) |
| ERROR | helper | mastra-ai__mastra | del() | mcp-js-command-injection | called from tool file: with-pg-storage.ts -> deleteThread -> del | [pubsub/valkey-streams/src/client.ts:156](https://github.com/mastra-ai/mastra/blob/42004349c10c/pubsub/valkey-streams/src/client.ts#L156) |
| ERROR | helper | mastra-ai__mastra | set() | mcp-js-command-injection | called from tool file: create-cycle.ts -> isActive -> set | [pubsub/valkey-streams/src/client.ts:162](https://github.com/mastra-ai/mastra/blob/42004349c10c/pubsub/valkey-streams/src/client.ts#L162) |
| ERROR | helper | mastra-ai__mastra | get() | mcp-js-command-injection | called from tool file: defaults.ts -> kill -> get | [pubsub/valkey-streams/src/client.ts:166](https://github.com/mastra-ai/mastra/blob/42004349c10c/pubsub/valkey-streams/src/client.ts#L166) |
| ERROR | helper | mastra-ai__mastra | eval() | mcp-js-command-injection | called from tool file: agent.ts -> releaseLease -> eval | [pubsub/valkey-streams/src/client.ts:171](https://github.com/mastra-ai/mastra/blob/42004349c10c/pubsub/valkey-streams/src/client.ts#L171) |
| ERROR | helper | mastra-ai__mastra | clearTopic() | mcp-js-command-injection | called from tool file: index.ts -> unsubscribe -> clearTopic | [pubsub/valkey-streams/src/index.ts:879](https://github.com/mastra-ai/mastra/blob/42004349c10c/pubsub/valkey-streams/src/index.ts#L879) |
| ERROR | helper | mastra-ai__mastra | ensureSkipIndexes() | mcp-js-command-injection | called from tool file: index.ts -> subscribe -> init -> ensureSkipIndexes | [stores/clickhouse/src/storage/db/index.ts:193](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/db/index.ts#L193) |
| ERROR | helper | mastra-ai__mastra | checkForDuplicateSpans() | mcp-js-command-injection | called from tool file: index.ts -> subscribe -> init -> checkForDuplicateSpans | [stores/clickhouse/src/storage/db/index.ts:397](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/db/index.ts#L397) |
| ERROR | helper | mastra-ai__mastra | checkForDuplicateSpans() | mcp-js-command-injection | called from tool file: index.ts -> subscribe -> init -> checkForDuplicateSpans | [stores/clickhouse/src/storage/db/index.ts:436](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/db/index.ts#L436) |
| ERROR | helper | mastra-ai__mastra | checkForDuplicateSpans() | mcp-js-command-injection | called from tool file: index.ts -> subscribe -> init -> checkForDuplicateSpans | [stores/clickhouse/src/storage/db/index.ts:464](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/db/index.ts#L464) |
| ERROR | helper | mastra-ai__mastra | checkForDuplicateSpans() | mcp-js-command-injection | called from tool file: index.ts -> subscribe -> init -> checkForDuplicateSpans | [stores/clickhouse/src/storage/db/index.ts:476](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/db/index.ts#L476) |
| ERROR | helper | mastra-ai__mastra | checkForDuplicateSpans() | mcp-js-command-injection | called from tool file: index.ts -> subscribe -> init -> checkForDuplicateSpans | [stores/clickhouse/src/storage/db/index.ts:494](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/db/index.ts#L494) |
| ERROR | helper | mastra-ai__mastra | checkForDuplicateSpans() | mcp-js-command-injection | called from tool file: index.ts -> subscribe -> init -> checkForDuplicateSpans | [stores/clickhouse/src/storage/db/index.ts:499](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/db/index.ts#L499) |
| ERROR | helper | mastra-ai__mastra | getSqlType() | mcp-js-command-injection | called from tool file: weather-workflow.ts -> commit -> load -> getSqlType | [stores/clickhouse/src/storage/db/index.ts:620](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/db/index.ts#L620) |
| ERROR | helper | mastra-ai__mastra | getSqlType() | mcp-js-command-injection | called from tool file: weather-workflow.ts -> commit -> load -> getSqlType | [stores/clickhouse/src/storage/db/index.ts:676](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/db/index.ts#L676) |
| ERROR | helper | mastra-ai__mastra | clearTable() | mcp-js-command-injection | called from tool file: server-setup.ts -> dangerouslyClearAll -> clearTable | [stores/clickhouse/src/storage/db/index.ts:710](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/db/index.ts#L710) |
| ERROR | helper | mastra-ai__mastra | clearTable() | mcp-js-command-injection | called from tool file: server-setup.ts -> dangerouslyClearAll -> clearTable | [stores/clickhouse/src/storage/db/index.ts:711](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/db/index.ts#L711) |
| ERROR | helper | mastra-ai__mastra | clearTable() | mcp-js-command-injection | called from tool file: server-setup.ts -> dangerouslyClearAll -> clearTable | [stores/clickhouse/src/storage/db/index.ts:714](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/db/index.ts#L714) |
| ERROR | helper | mastra-ai__mastra | deleteMessages() | mcp-js-command-injection | called from tool file: mock.ts -> deleteMessages | [stores/clickhouse/src/storage/domains/memory/index.ts:131](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/domains/memory/index.ts#L131) |
| ERROR | helper | mastra-ai__mastra | _sortMessages() | mcp-js-command-injection | called from tool file: message-ordering.ts -> listMessages -> _sortMessages | [stores/clickhouse/src/storage/domains/memory/index.ts:692](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/domains/memory/index.ts#L692) |
| ERROR | helper | mastra-ai__mastra | _sortMessages() | mcp-js-command-injection | called from tool file: message-ordering.ts -> listMessages -> _sortMessages | [stores/clickhouse/src/storage/domains/memory/index.ts:707](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/domains/memory/index.ts#L707) |
| ERROR | helper | mastra-ai__mastra | listThreads() | mcp-js-command-injection | called from tool file: om-tools.ts -> listThreads | [stores/clickhouse/src/storage/domains/memory/index.ts:1298](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/domains/memory/index.ts#L1298) |
| ERROR | helper | mastra-ai__mastra | batchDeleteTraces() | mcp-js-command-injection | called from tool file: server-setup.ts -> handler -> batchDeleteTraces | [stores/clickhouse/src/storage/domains/observability/index.ts:850](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/domains/observability/index.ts#L850) |
| ERROR | helper | mastra-ai__mastra | deleteFeedback() | mcp-js-command-injection | called from tool file: server-setup.ts -> handler -> deleteFeedback | [stores/clickhouse/src/storage/domains/observability/v-next/feedback.ts:283](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/domains/observability/v-next/feedback.ts#L283) |
| ERROR | helper | mastra-ai__mastra | applyClickHouseRetention() | mcp-js-command-injection | called from tool file: index.ts -> subscribe -> init -> applyRetention -> applyClickHouseRetention | [stores/clickhouse/src/storage/domains/observability/v-next/index.ts:415](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/domains/observability/v-next/index.ts#L415) |
| ERROR | helper | mastra-ai__mastra | reconcileDiscoveryTables() | mcp-js-command-injection | called from tool file: index.ts -> subscribe -> init -> reconcileDiscoveryTables | [stores/clickhouse/src/storage/domains/observability/v-next/index.ts:514](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/domains/observability/v-next/index.ts#L514) |
| ERROR | helper | mastra-ai__mastra | reconcileDiscoveryTables() | mcp-js-command-injection | called from tool file: index.ts -> subscribe -> init -> reconcileDiscoveryTables | [stores/clickhouse/src/storage/domains/observability/v-next/index.ts:515](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/domains/observability/v-next/index.ts#L515) |
| ERROR | helper | mastra-ai__mastra | reconcileScoreDeltaMv() | mcp-js-command-injection | called from tool file: index.ts -> subscribe -> init -> reconcileScoreDeltaMv | [stores/clickhouse/src/storage/domains/observability/v-next/index.ts:601](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/domains/observability/v-next/index.ts#L601) |
| ERROR | helper | mastra-ai__mastra | migrateLegacySpans() | mcp-js-command-injection | called from tool file: course.ts -> leave -> close -> migrateSpans -> migrateLegacySpans | [stores/clickhouse/src/storage/domains/observability/v-next/migration.ts:373](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/domains/observability/v-next/migration.ts#L373) |
| ERROR | helper | mastra-ai__mastra | migrateSignalTables() | mcp-js-command-injection | called from tool file: course.ts -> leave -> close -> migrateSpans -> migrateSignalTables | [stores/clickhouse/src/storage/domains/observability/v-next/migration.ts:431](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/domains/observability/v-next/migration.ts#L431) |
| ERROR | helper | mastra-ai__mastra | deleteScores() | mcp-js-command-injection | called from tool file: server-setup.ts -> handler -> deleteScores | [stores/clickhouse/src/storage/domains/observability/v-next/scores.ts:292](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/domains/observability/v-next/scores.ts#L292) |
| ERROR | helper | mastra-ai__mastra | batchDeleteTraces() | mcp-js-command-injection | called from tool file: server-setup.ts -> handler -> batchDeleteTraces | [stores/clickhouse/src/storage/domains/observability/v-next/tracing.ts:290](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/domains/observability/v-next/tracing.ts#L290) |
| ERROR | helper | mastra-ai__mastra | batchDeleteTraces() | mcp-js-command-injection | called from tool file: server-setup.ts -> handler -> batchDeleteTraces | [stores/clickhouse/src/storage/domains/observability/v-next/tracing.ts:297](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/domains/observability/v-next/tracing.ts#L297) |
| ERROR | helper | mastra-ai__mastra | deleteWorkflowRunById() | mcp-js-command-injection | called from tool file: workflow.ts -> deleteWorkflowRunById | [stores/clickhouse/src/storage/domains/workflows/index.ts:364](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/clickhouse/src/storage/domains/workflows/index.ts#L364) |
| ERROR | helper | mastra-ai__mastra | get() | mcp-js-command-injection | called from tool file: defaults.ts -> kill -> get | [stores/valkey/src/cache.ts:69](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/valkey/src/cache.ts#L69) |
| ERROR | helper | mastra-ai__mastra | set() | mcp-js-command-injection | called from tool file: create-cycle.ts -> isActive -> set | [stores/valkey/src/cache.ts:83](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/valkey/src/cache.ts#L83) |
| ERROR | helper | mastra-ai__mastra | listLength() | mcp-js-command-injection | called from tool file: background-store.ts -> onCancel -> handleInput -> move -> listLength | [stores/valkey/src/cache.ts:87](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/valkey/src/cache.ts#L87) |
| ERROR | helper | mastra-ai__mastra | listPush() | mcp-js-command-injection | called from tool file: server-setup.ts -> handler -> listPush | [stores/valkey/src/cache.ts:92](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/valkey/src/cache.ts#L92) |
| ERROR | helper | mastra-ai__mastra | listPush() | mcp-js-command-injection | called from tool file: server-setup.ts -> handler -> listPush | [stores/valkey/src/cache.ts:93](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/valkey/src/cache.ts#L93) |
| ERROR | helper | mastra-ai__mastra | listFromTo() | mcp-js-command-injection | called from tool file: server-setup.ts -> handler -> listFromTo | [stores/valkey/src/cache.ts:97](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/valkey/src/cache.ts#L97) |
| ERROR | helper | mastra-ai__mastra | increment() | mcp-js-command-injection | called from tool file: loops.ts -> increment | [stores/valkey/src/cache.ts:127](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/valkey/src/cache.ts#L127) |
| ERROR | helper | mastra-ai__mastra | increment() | mcp-js-command-injection | called from tool file: loops.ts -> increment | [stores/valkey/src/cache.ts:144](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/valkey/src/cache.ts#L144) |
| ERROR | helper | mastra-ai__mastra | get() | mcp-js-command-injection | called from tool file: defaults.ts -> kill -> get | [stores/valkey/src/client.ts:91](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/valkey/src/client.ts#L91) |
| ERROR | helper | mastra-ai__mastra | set() | mcp-js-command-injection | called from tool file: create-cycle.ts -> isActive -> set | [stores/valkey/src/client.ts:95](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/valkey/src/client.ts#L95) |
| ERROR | helper | mastra-ai__mastra | del() | mcp-js-command-injection | called from tool file: with-pg-storage.ts -> deleteThread -> del | [stores/valkey/src/client.ts:107](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/valkey/src/client.ts#L107) |
| ERROR | helper | mastra-ai__mastra | del() | mcp-js-command-injection | called from tool file: with-pg-storage.ts -> deleteThread -> del | [stores/valkey/src/client.ts:111](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/valkey/src/client.ts#L111) |
| ERROR | helper | mastra-ai__mastra | zAdd() | mcp-js-command-injection | called from tool file: with-pg-storage.ts -> deleteThread -> zAdd | [stores/valkey/src/client.ts:129](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/valkey/src/client.ts#L129) |
| ERROR | helper | mastra-ai__mastra | zRem() | mcp-js-command-injection | called from tool file: with-pg-storage.ts -> deleteThread -> zRem | [stores/valkey/src/client.ts:133](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/valkey/src/client.ts#L133) |
| ERROR | helper | mastra-ai__mastra | eval() | mcp-js-command-injection | called from tool file: agent.ts -> releaseLease -> eval | [stores/valkey/src/client.ts:137](https://github.com/mastra-ai/mastra/blob/42004349c10c/stores/valkey/src/client.ts#L137) |
| ERROR | helper | meshy-dev__meshy-mcp-server | detectOnLinux() | mcp-js-command-injection | called from tool file: printing.ts -> detectInstalledSlicers -> detectOnLinux | [src/utils/slicer-detector.ts:157](https://github.com/meshy-dev/meshy-mcp-server/blob/0f4c10a3c37f/src/utils/slicer-detector.ts#L157) |
| ERROR | helper | mksglu__context-mode | ? | mcp-js-code-injection | inside tool file | [cli.bundle.mjs:494](https://github.com/mksglu/context-mode/blob/7164222685f7/cli.bundle.mjs#L494) |
| ERROR | helper | mksglu__context-mode | ? | mcp-js-code-injection | inside tool file | [server.bundle.mjs:6](https://github.com/mksglu/context-mode/blob/7164222685f7/server.bundle.mjs#L6) |
| ERROR | helper | mksglu__context-mode | whichOnPath() | mcp-js-command-injection | inside tool file | [src/adapters/pi/mcp-bridge.ts:64](https://github.com/mksglu/context-mode/blob/7164222685f7/src/adapters/pi/mcp-bridge.ts#L64) |
| ERROR | helper | mksglu__context-mode | npmExec() | mcp-js-command-injection | called from tool file: cli.bundle.mjs -> npmExec | [src/cli.ts:297](https://github.com/mksglu/context-mode/blob/7164222685f7/src/cli.ts#L297) |
| ERROR | helper | mksglu__context-mode | killTree() | mcp-js-command-injection | called from tool file: server.ts -> executeFile -> killTree | [src/executor.ts:200](https://github.com/mksglu/context-mode/blob/7164222685f7/src/executor.ts#L200) |
| ERROR | helper | mksglu__context-mode | executeFile() | mcp-js-command-injection | called from tool file: server.ts -> executeFile | [src/executor.ts:463](https://github.com/mksglu/context-mode/blob/7164222685f7/src/executor.ts#L463) |
| ERROR | helper | mksglu__context-mode | commandExists() | mcp-js-command-injection | called from tool file: server.ts -> detectRuntimes -> commandExists | [src/runtime.ts:81](https://github.com/mksglu/context-mode/blob/7164222685f7/src/runtime.ts#L81) |
| ERROR | helper | mksglu__context-mode | runnableExists() | mcp-js-command-injection | called from tool file: server.ts -> detectRuntimes -> runnableExists | [src/runtime.ts:100](https://github.com/mksglu/context-mode/blob/7164222685f7/src/runtime.ts#L100) |
| ERROR | helper | mksglu__context-mode | runnableExists() | mcp-js-command-injection | called from tool file: server.ts -> detectRuntimes -> runnableExists | [src/runtime.ts:119](https://github.com/mksglu/context-mode/blob/7164222685f7/src/runtime.ts#L119) |
| ERROR | helper | nikolai-vysotskyi__trace-mcp | which() | mcp-js-command-injection | called from tool file: session.ts -> which | [packages/app/src/main/ollama-control.ts:156](https://github.com/nikolai-vysotskyi/trace-mcp/blob/b092938431c0/packages/app/src/main/ollama-control.ts#L156) |
| ERROR | helper | nitrocloudofficial__nitrostack | execSilent() | mcp-js-command-injection | called from tool file: init.ts -> shutdownAnalytics -> shutdown -> execSilent | [typescript/packages/cli/src/commands/dev.ts:157](https://github.com/nitrocloudofficial/nitrostack/blob/10859befd51c/typescript/packages/cli/src/commands/dev.ts#L157) |
| ERROR | helper | poe-platform__poe-code | withLock() | mcp-js-command-injection | called from tool file: safe-bash-main.ts -> replace -> withLock | [packages/auth-store-rust/src/runtime.js:271](https://github.com/poe-platform/poe-code/blob/5bfcc90ac5d6/packages/auth-store-rust/src/runtime.js#L271) |
| ERROR | helper | poe-platform__poe-code | runMetric() | mcp-js-command-injection | called from tool file: parser.ts -> pending -> evaluate -> runMetric | [packages/experiment-loop/src/evaluator/evaluator.ts:33](https://github.com/poe-platform/poe-code/blob/5bfcc90ac5d6/packages/experiment-loop/src/evaluator/evaluator.ts#L33) |
| ERROR | helper | poe-platform__poe-code | spawnShellCommand() | mcp-js-command-injection | called from tool file: http-server.ts -> handleRequest -> call -> createBackgroundCommand -> spawnShellCommand | [packages/poe-agent-rust/src/plugin-shell.js:239](https://github.com/poe-platform/poe-code/blob/5bfcc90ac5d6/packages/poe-agent-rust/src/plugin-shell.js#L239) |
| ERROR | helper | poe-platform__poe-code | spawnShellCommand() | mcp-js-command-injection | called from tool file: http-server.ts -> handleRequest -> call -> createBackgroundCommand -> spawnShellCommand | [packages/poe-agent/src/plugins/poe-agent-plugin-shell.ts:875](https://github.com/poe-platform/poe-code/blob/5bfcc90ac5d6/packages/poe-agent/src/plugins/poe-agent-plugin-shell.ts#L875) |
| ERROR | helper | poe-platform__poe-code | isEngineAvailable() | mcp-js-command-injection | called from tool file: mcp.ts -> field -> open -> detectEngine -> isEngineAvailable | [packages/process-runner-rust/src/docker-engine.js:2](https://github.com/poe-platform/poe-code/blob/5bfcc90ac5d6/packages/process-runner-rust/src/docker-engine.js#L2) |
| ERROR | helper | poe-platform__poe-code | isEngineAvailable() | mcp-js-command-injection | called from tool file: mcp.ts -> field -> open -> detectEngine -> isEngineAvailable | [packages/process-runner/src/docker/engine.ts:23](https://github.com/poe-platform/poe-code/blob/5bfcc90ac5d6/packages/process-runner/src/docker/engine.ts#L23) |
| ERROR | helper | poe-platform__poe-code | update() | mcp-js-code-injection | called from tool file: parser.ts -> expression -> update | [packages/safe-bash-command-playwright-cli/src/playwright/highlight.ts:56](https://github.com/poe-platform/poe-code/blob/5bfcc90ac5d6/packages/safe-bash-command-playwright-cli/src/playwright/highlight.ts#L56) |
| ERROR | helper | poe-platform__poe-code | task() | mcp-js-command-injection | called from tool file: index.ts -> task | [packages/safe-bash-sqlite-engine/src/sqlite-native.ts:34](https://github.com/poe-platform/poe-code/blob/5bfcc90ac5d6/packages/safe-bash-sqlite-engine/src/sqlite-native.ts#L34) |
| ERROR | helper | poe-platform__poe-code | pipeline() | mcp-js-command-injection | called from tool file: mcp.ts -> word -> script -> pipeline | [packages/safe-bash/src/shell/runtime.ts:4509](https://github.com/poe-platform/poe-code/blob/5bfcc90ac5d6/packages/safe-bash/src/shell/runtime.ts#L4509) |
| ERROR | helper | poe-platform__poe-code | runCommandIsolated() | mcp-js-command-injection | called from tool file: test-support.js -> resume -> restore -> runCommandIsolated | [packages/safe-bash/src/shell/runtime.ts:4778](https://github.com/poe-platform/poe-code/blob/5bfcc90ac5d6/packages/safe-bash/src/shell/runtime.ts#L4778) |
| ERROR | helper | poe-platform__poe-code | send() | mcp-js-command-injection | called from tool file: safe-bash-main.ts -> normalized -> send | [packages/safe-playwright-cloudflare/src/browser-run-code-relay.ts:101](https://github.com/poe-platform/poe-code/blob/5bfcc90ac5d6/packages/safe-playwright-cloudflare/src/browser-run-code-relay.ts#L101) |
| ERROR | helper | poe-platform__poe-code | array() | mcp-js-command-injection | called from tool file: parser.ts -> array | [packages/toolcraft-design-rust/src/command-errors.js:19](https://github.com/poe-platform/poe-code/blob/5bfcc90ac5d6/packages/toolcraft-design-rust/src/command-errors.js#L19) |
| ERROR | helper | poe-platform__poe-code | suggestions() | mcp-js-command-injection | called from tool file: mcp.ts -> suggestions | [packages/toolcraft-design-rust/src/command-errors.js:21](https://github.com/poe-platform/poe-code/blob/5bfcc90ac5d6/packages/toolcraft-design-rust/src/command-errors.js#L21) |
| ERROR | helper | poe-platform__poe-code | renderMarkdown() | mcp-js-command-injection | called from tool file: internal.ts -> reset -> renderMarkdown | [packages/toolcraft-design/src/components/catalog.ts:99](https://github.com/poe-platform/poe-code/blob/5bfcc90ac5d6/packages/toolcraft-design/src/components/catalog.ts#L99) |
| ERROR | helper | poe-platform__poe-code | action() | mcp-js-command-injection | called from tool file: mcp.ts -> action | [src/cli/program.ts:827](https://github.com/poe-platform/poe-code/blob/5bfcc90ac5d6/src/cli/program.ts#L827) |
| ERROR | helper | ruvnet__claude-flow | runEntry() | mcp-js-command-injection | called from tool file: coordination-tools.ts -> action -> steal -> runEntry | [plugins/ruflo-console/hooks/runner.ts:474](https://github.com/ruvnet/claude-flow/blob/5f3dacc54b72/plugins/ruflo-console/hooks/runner.ts#L474) |
| ERROR | helper | ruvnet__claude-flow | run() | mcp-js-command-injection | inside tool file | [v3/@claude-flow/cli/src/mcp-tools/github-tools.ts:88](https://github.com/ruvnet/claude-flow/blob/5f3dacc54b72/v3/@claude-flow/cli/src/mcp-tools/github-tools.ts#L88) |
| ERROR | helper | ruvnet__claude-flow | handler() | mcp-js-command-injection | inside tool file | [v3/@claude-flow/cli/src/mcp-tools/terminal-tools.ts:204](https://github.com/ruvnet/claude-flow/blob/5f3dacc54b72/v3/@claude-flow/cli/src/mcp-tools/terminal-tools.ts#L204) |
| ERROR | helper | ruvnet__claude-flow | run() | mcp-js-command-injection | called from tool file: x-federation-channels.ts -> fn -> run | [v3/@claude-flow/cli/src/mods/plugin-repair.ts:113](https://github.com/ruvnet/claude-flow/blob/5f3dacc54b72/v3/@claude-flow/cli/src/mods/plugin-repair.ts#L113) |
| ERROR | helper | ruvnet__claude-flow | uninstallPlugins() | mcp-js-command-injection | called from tool file: coordination-tools.ts -> action -> removeMods -> uninstallPlugins | [v3/@claude-flow/cli/src/mods/plugin-repair.ts:162](https://github.com/ruvnet/claude-flow/blob/5f3dacc54b72/v3/@claude-flow/cli/src/mods/plugin-repair.ts#L162) |
| ERROR | helper | ruvnet__claude-flow | terminateContainer() | mcp-js-command-injection | called from tool file: index.ts -> shutdown -> terminateContainer | [v3/@claude-flow/cli/src/services/container-worker-pool.ts:468](https://github.com/ruvnet/claude-flow/blob/5f3dacc54b72/v3/@claude-flow/cli/src/services/container-worker-pool.ts#L468) |
| ERROR | helper | ruvnet__claude-flow | execCommand() | mcp-js-command-injection | called from tool file: plugin.ts -> validate -> execCommand | [v3/@claude-flow/deployment/src/publisher.ts:231](https://github.com/ruvnet/claude-flow/blob/5f3dacc54b72/v3/@claude-flow/deployment/src/publisher.ts#L231) |
| ERROR | helper | ruvnet__claude-flow | execCommand() | mcp-js-command-injection | called from tool file: plugin.ts -> validate -> execCommand | [v3/@claude-flow/deployment/src/release-manager.ts:355](https://github.com/ruvnet/claude-flow/blob/5f3dacc54b72/v3/@claude-flow/deployment/src/release-manager.ts#L355) |
| ERROR | helper | ruvnet__claude-flow | execCommand() | mcp-js-command-injection | called from tool file: plugin.ts -> validate -> execCommand | [v3/@claude-flow/deployment/src/validator.ts:287](https://github.com/ruvnet/claude-flow/blob/5f3dacc54b72/v3/@claude-flow/deployment/src/validator.ts#L287) |
| ERROR | helper | ruvnet__ruvector | __wbg_get_imports() | mcp-js-code-injection | called from tool file: rvagent_wasm.js -> __wbg_get_imports | [crates/ruvector-attention-unified-wasm/pkg/ruvector_attention_unified_wasm.js:2583](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/crates/ruvector-attention-unified-wasm/pkg/ruvector_attention_unified_wasm.js#L2583) |
| ERROR | helper | ruvnet__ruvector | __wbg_get_imports() | mcp-js-code-injection | called from tool file: rvagent_wasm.js -> __wbg_get_imports | [crates/ruvector-exotic-wasm/pkg/ruvector_exotic_wasm.js:1046](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/crates/ruvector-exotic-wasm/pkg/ruvector_exotic_wasm.js#L1046) |
| ERROR | helper | ruvnet__ruvector | __wbg_get_imports() | mcp-js-code-injection | called from tool file: rvagent_wasm.js -> __wbg_get_imports | [crates/ruvector-nervous-system-wasm/pkg/ruvector_nervous_system_wasm.js:1481](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/crates/ruvector-nervous-system-wasm/pkg/ruvector_nervous_system_wasm.js#L1481) |
| ERROR | helper | ruvnet__ruvector | preWarmForBurst() | mcp-js-command-injection | called from tool file: PluginManager.ts -> message -> start -> checkPredictiveScaling -> preWarmForBurst | [npm/packages/burst-scaling/index.ts:232](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/npm/packages/burst-scaling/index.ts#L232) |
| ERROR | helper | ruvnet__ruvector | executeScalingAction() | mcp-js-command-injection | called from tool file: PluginManager.ts -> message -> start -> startMetricsCollection -> executeScalingAction | [npm/packages/burst-scaling/index.ts:277](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/npm/packages/burst-scaling/index.ts#L277) |
| ERROR | helper | ruvnet__ruvector | status() | mcp-js-command-injection | called from tool file: mcp-server.js -> status | [npm/packages/postgres-cli/src/commands/install.ts:799](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/npm/packages/postgres-cli/src/commands/install.ts#L799) |
| ERROR | helper | ruvnet__ruvector | status() | mcp-js-command-injection | called from tool file: mcp-server.js -> status | [npm/packages/postgres-cli/src/commands/install.ts:808](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/npm/packages/postgres-cli/src/commands/install.ts#L808) |
| ERROR | helper | ruvnet__ruvector | status() | mcp-js-command-injection | called from tool file: mcp-server.js -> status | [npm/packages/postgres-cli/src/commands/install.ts:813](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/npm/packages/postgres-cli/src/commands/install.ts#L813) |
| ERROR | helper | ruvnet__ruvector | start() | mcp-js-command-injection | called from tool file: PluginManager.ts -> message -> start | [npm/packages/postgres-cli/src/commands/install.ts:883](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/npm/packages/postgres-cli/src/commands/install.ts#L883) |
| ERROR | helper | ruvnet__ruvector | start() | mcp-js-command-injection | called from tool file: PluginManager.ts -> message -> start | [npm/packages/postgres-cli/src/commands/install.ts:888](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/npm/packages/postgres-cli/src/commands/install.ts#L888) |
| ERROR | helper | ruvnet__ruvector | isSyntacticallyValid() | mcp-js-code-injection | called from tool file: mcp-server.js -> decompilePackage -> decompileSource -> splitModules -> isSyntacticallyValid | [npm/packages/ruvector/src/decompiler/module-splitter.js:112](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/npm/packages/ruvector/src/decompiler/module-splitter.js#L112) |
| ERROR | helper | ruvnet__ruvector | isSyntacticallyValid() | mcp-js-code-injection | called from tool file: mcp-server.js -> decompilePackage -> decompileSource -> splitModules -> isSyntacticallyValid | [npm/packages/ruvector/src/decompiler/module-splitter.js:120](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/npm/packages/ruvector/src/decompiler/module-splitter.js#L120) |
| ERROR | helper | ruvnet__ruvector | isSyntacticallyValid() | mcp-js-code-injection | called from tool file: mcp-server.js -> decompilePackage -> decompileSource -> splitModules -> isSyntacticallyValid | [npm/packages/ruvector/src/decompiler/module-splitter.js:128](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/npm/packages/ruvector/src/decompiler/module-splitter.js#L128) |
| ERROR | helper | ruvnet__ruvector | isSyntacticallyValid() | mcp-js-code-injection | called from tool file: mcp-server.js -> decompilePackage -> decompileSource -> splitModules -> isSyntacticallyValid | [npm/packages/ruvector/src/decompiler/reconstructor.js:352](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/npm/packages/ruvector/src/decompiler/reconstructor.js#L352) |
| ERROR | helper | ruvnet__ruvector | clearInterval() | mcp-js-code-injection | called from tool file: mcp_server.py -> acquire -> startHeartbeat -> clearInterval | [npm/packages/ruvector/src/decompiler/reconstructor.js:381](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/npm/packages/ruvector/src/decompiler/reconstructor.js#L381) |
| ERROR | helper | ruvnet__ruvector | clearInterval() | mcp-js-code-injection | called from tool file: mcp_server.py -> acquire -> startHeartbeat -> clearInterval | [npm/packages/ruvector/src/decompiler/reconstructor.js:382](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/npm/packages/ruvector/src/decompiler/reconstructor.js#L382) |
| ERROR | helper | ruvnet__ruvector | checkSyntaxValidity() | mcp-js-code-injection | called from tool file: mcp-server.js -> decompilePackage -> decompileSource -> validateReconstruction -> checkSyntaxValidity | [npm/packages/ruvector/src/decompiler/validator.js:122](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/npm/packages/ruvector/src/decompiler/validator.js#L122) |
| ERROR | helper | ruvnet__ruvector | clearInterval() | mcp-js-code-injection | called from tool file: mcp_server.py -> acquire -> startHeartbeat -> clearInterval | [npm/packages/ruvector/src/decompiler/validator.js:362](https://github.com/ruvnet/ruvector/blob/cf357d8121f9/npm/packages/ruvector/src/decompiler/validator.js#L362) |
| ERROR | helper | southleft__figma-console-mcp | setTimeout() | mcp-js-code-injection | called from tool file: index.ts -> setTimeout | [figma-desktop-bridge/code.js:519](https://github.com/southleft/figma-console-mcp/blob/5ef4df379160/figma-desktop-bridge/code.js#L519) |
| ERROR | helper | southleft__figma-console-mcp | getProcessAgeMs() | mcp-js-command-injection | called from tool file: local.ts -> cleanupOrphanedProcesses -> getProcessAgeMs | [src/core/port-discovery.ts:444](https://github.com/southleft/figma-console-mcp/blob/5ef4df379160/src/core/port-discovery.ts#L444) |
| ERROR | helper | southleft__figma-console-mcp | cleanupOrphanedProcesses() | mcp-js-command-injection | called from tool file: local.ts -> cleanupOrphanedProcesses | [src/core/port-discovery.ts:758](https://github.com/southleft/figma-console-mcp/blob/5ef4df379160/src/core/port-discovery.ts#L758) |
| ERROR | helper | southleft__figma-console-mcp | cleanupOrphanedProcesses() | mcp-js-command-injection | called from tool file: local.ts -> cleanupOrphanedProcesses | [src/core/port-discovery.ts:772](https://github.com/southleft/figma-console-mcp/blob/5ef4df379160/src/core/port-discovery.ts#L772) |
| ERROR | helper | stevehuang0115__crewly | execute() | mcp-js-command-injection | called from tool file: desktop-task.tool.ts -> async -> poll -> dispatch -> execute | [backend/src/services/provisioning/deployment-orchestrator.service.ts:74](https://github.com/stevehuang0115/crewly/blob/537cf5208f38/backend/src/services/provisioning/deployment-orchestrator.service.ts#L74) |
| ERROR | helper | stevehuang0115__crewly | signal() | mcp-js-command-injection | called from tool file: tool-registry.ts -> signal | [cli/src/commands/stop.ts:307](https://github.com/stevehuang0115/crewly/blob/537cf5208f38/cli/src/commands/stop.ts#L307) |
| ERROR | helper | stevehuang0115__crewly | exec() | mcp-js-command-injection | called from tool file: subagent.ts -> initialize -> emit -> exec | [cli/src/utils/gh-submit.ts:59](https://github.com/stevehuang0115/crewly/blob/537cf5208f38/cli/src/utils/gh-submit.ts#L59) |
| ERROR | helper | stevehuang0115__crewly | site_errors() | mcp-py-command-injection | called from tool file: desktop-task.tool.ts -> async -> refresh -> run -> site_errors | [config/skills/team-leader/signal-digest/signal_digest.py:295](https://github.com/stevehuang0115/crewly/blob/537cf5208f38/config/skills/team-leader/signal-digest/signal_digest.py#L295) |
| ERROR | helper | stevehuang0115__crewly | checkCommand() | mcp-js-command-injection | called from tool file: tool-registry.ts -> post -> schedule -> check -> checkCommand | [desktop/src/main/installer.ts:31](https://github.com/stevehuang0115/crewly/blob/537cf5208f38/desktop/src/main/installer.ts#L31) |
| ERROR | helper | stevehuang0115__crewly | execGitAsync() | mcp-js-command-injection | inside tool file | [packages/crewly-agent/src/runtime/tool-registry.ts:271](https://github.com/stevehuang0115/crewly/blob/537cf5208f38/packages/crewly-agent/src/runtime/tool-registry.ts#L271) |
| ERROR | helper | sweetrb__apple-mail-mcp | executeAppleScript() | mcp-js-command-injection | called from tool file: resourcesAndPrompts.ts -> listMailboxes -> resolveAccount -> executeAppleScript | [src/utils/applescript.ts:466](https://github.com/sweetrb/apple-mail-mcp/blob/4bebdde08383/src/utils/applescript.ts#L466) |
| ERROR | helper | vercel__next-devtools-mcp | getPortsViaSs() | mcp-js-command-injection | called from tool file: nextjs_index.ts -> getAllAvailableServers -> findNextJsServers -> getListeningPort -> getPortsViaSs | [src/_internal/nextjs-runtime-manager.ts:170](https://github.com/vercel/next-devtools-mcp/blob/1e8dcfa47897/src/_internal/nextjs-runtime-manager.ts#L170) |
| ERROR | taint | VoltAgent__voltagent | calculator | mcp-js-code-injection | inside tool handler | [packages/core/src/agent/agent.spec-d.ts:1174](https://github.com/VoltAgent/voltagent/blob/72a46c76b450/packages/core/src/agent/agent.spec-d.ts#L1174) |
| ERROR | taint | mastra-ai__mastra | runCommand | mcp-js-command-injection | inside tool handler | [explorations/network-validation-bridge.ts:449](https://github.com/mastra-ai/mastra/blob/42004349c10c/explorations/network-validation-bridge.ts#L449) |
| ERROR | taint | mastra-ai__mastra | execute() | mcp-js-command-injection | inside tool handler | [packages/core/src/loop/network/run-command-tool.ts:289](https://github.com/mastra-ai/mastra/blob/42004349c10c/packages/core/src/loop/network/run-command-tool.ts#L289) |
| ERROR | taint | ruvnet__agentic-flow | memory_store | mcp-js-command-injection | inside tool handler | [agentic-flow/docker/claude-agent-sdk/src/mcp/fastmcp/servers/http-streaming.ts:36](https://github.com/ruvnet/agentic-flow/blob/2c86073bf55a/agentic-flow/docker/claude-agent-sdk/src/mcp/fastmcp/servers/http-streaming.ts#L36) |
| ERROR | taint | stevehuang0115__crewly | execute() | mcp-js-command-injection | inside tool handler | [packages/crewly-agent/src/runtime/auditor-tools.ts:260](https://github.com/stevehuang0115/crewly/blob/537cf5208f38/packages/crewly-agent/src/runtime/auditor-tools.ts#L260) |
| WARNING | helper | AgentWorkforce__relayhistory | helperRequest() | mcp-js-argument-injection | called from tool file: mcp-server.ts -> discoverSessions -> discoverSourcePlugins -> discover -> helperRequest | [plugins/provider-sources/sdk/src/helper.ts:57](https://github.com/AgentWorkforce/relayhistory/blob/6065ddd7bd94/plugins/provider-sources/sdk/src/helper.ts#L57) |
| WARNING | helper | Aureliolo__gdharness | scriptsAutoloaded() | mcp-js-path-traversal | called from tool file: server.ts -> scriptsAutoloaded | [src/autoload-failure.ts:28](https://github.com/Aureliolo/gdharness/blob/cd3a6f8faea2/src/autoload-failure.ts#L28) |

…10001 more in findings.csv

17542 lower-priority finding(s) are in findings.csv after the priority rows (3079 demoted by a context check — see auto_notes; the rest are helper findings not traced to tool code, or audit tier).

## Per-repo

| repo | status | tools | taint | helper | audit | version |
|---|---|---|---|---|---|---|
| ruvnet__agentic-flow | ok | 111 | 47 | 113 | 0 | agentic-flow@2.0.2-alpha |
| mastra-ai__mastra | ok | 202 | 46 | 1967 | 0 | mastra-turbo@0.1.11 |
| vuluu2k__sbuilder-mcp | ok | 38 | 19 | 61 | 0 | sbuilder-mcp@0.104.0 |
| stevehuang0115__crewly | ok | 18 | 15 | 1317 | 0 | crewly@1.20.470 |
| chrisryugj__kordoc | ok | 22 | 13 | 102 | 0 | kordoc@4.24.39 |
| microsoft__azure-devops-mcp | ok | 0 | 13 | 4 | 0 | @azure-devops/mcp@2.11.0 |
| AlaeddineMessadi__opencode-mcp | ok | 85 | 12 | 19 | 0 | opencode-mcp@3.1.0 |
| SAP__mdk-mcp-server | ok | 5 | 10 | 36 | 0 | @sap/mdk-mcp-server@0.5.0 |
| ruvnet__claude-flow | ok | 1273 | 7 | 1011 | 0 | claude-flow@3.71.0 |
| ruvnet__ruvector | ok | 215 | 7 | 434 | 0 | ruvector@0.1.2 |
| anis-marrouchi__agentx | ok | 55 | 6 | 941 | 0 | agentix-cli@0.206.0 |
| southleft__figma-console-mcp | ok | 131 | 5 | 30 | 0 | figma-console-mcp@1.46.0 |
| kshivam1177__android-mcp-framwork | ok | 0 | 4 | 163 | 0 | androidmcp-framework@0.1.49 |
| angelogiacco__elevenlabs-mcp | ok | 7 | 4 | 8 | 0 | elevenlabs-mcp==0.9.1 |
| asklokesh__loki-mode | ok | 56 | 3 | 1373 | 0 | loki-mode@11.124.2 |
| MCPJam__inspector | ok | 339 | 3 | 485 | 0 | mcpjam-workspace@? |
| artokun__comfyui-mcp | ok | 43 | 3 | 322 | 0 | comfyui-mcp@0.52.206 |
| VoltAgent__voltagent | ok | 14 | 3 | 101 | 0 | voltagent@0.1.0 |
| jmagly__aiwg | ok | 85 | 2 | 3137 | 0 | aiwg@2026.11.0 |
| nikolai-vysotskyi__trace-mcp | ok | 202 | 2 | 598 | 0 | trace-mcp@3.42.7 |
| decocms__studio | ok | 292 | 2 | 578 | 0 | @decocms/studio@? |
| ruvnet__agentdb | ok | 53 | 2 | 92 | 0 | agentdb@3.3.0 |
| firecrawl__firecrawl-mcp-server | ok | 30 | 2 | 3 | 0 | firecrawl-mcp@3.36.0 |
| mksglu__context-mode | ok | 17 | 1 | 67 | 0 | context-mode@1.0.169 |
| jgraph__drawio-mcp | ok | 8 | 1 | 20 | 0 |  |
| ioBroker__mcp-package | ok | 52 | 1 | 8 | 0 | @iobroker/mcp-server@1.9.2 |
| Ashish-Bansal__playwright-mcp | ok | 5 | 1 | 3 | 0 | playwright-mcp@0.0.13 |
| supabase__mcp | ok | 34 | 1 | 2 | 0 | ?@? |
| joshuayoes__ios-simulator-mcp | ok | 17 | 1 | 0 | 0 | ios-simulator-mcp@2.2.0 |
| JKHeadley__instar | ok | 53 | 0 | 2322 | 0 | instar@1.3.1612 |
| ubugeeei-prod__vize | ok | 13 | 0 | 2005 | 0 | vize-workspace@? |
| poe-platform__poe-code | ok | 138 | 0 | 1507 | 0 | poe-code@0.0.0-dev |
| Cotal-AI__Cotal | ok | 36 | 0 | 1457 | 0 | cotal-monorepo@0.0.0 |
| agentistics__agentistics | ok | 48 | 0 | 890 | 0 | agentistics@2.193.0 |
| abhigyanpatwari__GitNexus | ok | 29 | 0 | 761 | 0 | gitnexus-monorepo@? |
| griffinwork40__agent-afk | ok | 56 | 0 | 632 | 0 | agent-afk@5.346.0 |
| thedotmack__claude-mem | ok | 34 | 0 | 538 | 0 | claude-mem@15.9.0 |
| TinyCloudLabs__js-sdk | ok | 1 | 0 | 483 | 0 | tinycloud-web-sdk@0.0.1 |
| cline__cline | ok | 48 | 0 | 444 | 0 | @cline/packages@? |
| ruvnet__metaharness | ok | 40 | 0 | 245 | 0 | agent-harness-generator@0.1.0 |
| vouchington__vouchington-tooling | ok | 0 | 0 | 239 | 0 | vouchington-tooling-workspace@0.0.0 |
| foldkit__foldkit | ok | 20 | 0 | 210 | 0 | foldkit-monorepo@0.1.0 |
| haydenbleasel__blume | ok | 5 | 0 | 191 | 0 | blume-monorepo@? |
| SAP__open-ux-tools | ok | 15 | 0 | 190 | 0 | @sap-ux/open-ux-tools-root@0.9.0 |
| corsairdev__corsair | ok | 4 | 0 | 169 | 0 | @corsair/root@? |
| eyaltoledano__claude-task-master | ok | 46 | 0 | 164 | 0 | task-master-ai@0.43.1 |
| Aureliolo__gdharness | ok | 37 | 0 | 143 | 0 | gdharness@1.3.67 |
| hypequery__hypequery | ok | 6 | 0 | 132 | 0 | hypequery-monorepo@? |
| getsentry__XcodeBuildMCP | ok | 0 | 0 | 122 | 0 | mobilebuildmcp@2.7.1 |
| mcp-use__mcp-use | ok | 15 | 0 | 116 | 0 |  |
| jaminsmoke__codarch | ok | 15 | 0 | 116 | 0 | codarch@0.3.77 |
| basementstudio__xmcp | ok | 16 | 0 | 94 | 0 | xmcp-monorepo@? |
| transcend-io__tools | ok | 112 | 0 | 86 | 0 | ?@? |
| t8y2__dbx | ok | 1 | 0 | 85 | 0 | dbx@0.6.64 |
| ChristopherVR__ooxml | ok | 0 | 0 | 77 | 0 | ooxml@? |
| SocketDev__socket-mcp | ok | 7 | 0 | 73 | 0 | @socketsecurity/mcp@0.3.0 |
| nitrocloudofficial__nitrostack | ok | 35 | 0 | 62 | 0 |  |
| sweetrb__apple-mail-mcp | ok | 0 | 0 | 55 | 0 | apple-mail-mcp@2.20.52 |
| nrwl__nx-console | ok | 0 | 0 | 54 | 0 | nx-console@17.28.3 |
| upstash__context7 | ok | 40 | 0 | 49 | 0 | @upstash/context7@1.0.0 |
| Softeria__ms-365-mcp-server | ok | 9 | 0 | 40 | 0 | @softeria/ms-365-mcp-server@0.0.0-development |
| QuantGeekDev__mcp-framework | ok | 0 | 0 | 38 | 0 | mcp-framework@0.2.22 |
| auth0__auth0-mcp-server | ok | 23 | 0 | 38 | 0 | @auth0/auth0-mcp-server@0.1.0-beta.19 |
| webpro-nl__knip | ok | 4 | 0 | 36 | 0 | @knip/root@0.0.0 |
| mongodb-js__mongodb-mcp-server | ok | 1 | 0 | 32 | 0 | mongodb-mcp-server-monorepo@3.2.2 |
| czlonkowski__n8n-mcp | ok | 37 | 0 | 31 | 0 | n8n-mcp@2.99.2 |
| jonathanong__agent-blackboard | ok | 8 | 0 | 26 | 0 | agent-blackboard-workspace@0.0.0 |
| UI5__mcp-server | ok | 0 | 0 | 25 | 0 | @ui5/mcp-server@0.3.2 |
| DayuanJiang__next-ai-draw-io | ok | 4 | 0 | 25 | 0 | next-ai-draw-io@0.5.1 |
| BrowserMCP__mcp | ok | 11 | 0 | 23 | 0 | browsermcp@? |
| MetaMask__device-mcp | ok | 29 | 0 | 23 | 0 | @metamask/device-mcp@0.7.0 |
| bytebase__dbhub | ok | 0 | 0 | 23 | 0 | dbhub@1.5.0 |
| SmartBear__smartbear-mcp | ok | 0 | 0 | 22 | 0 | @smartbear/mcp@0.43.0 |
| browserstack__mcp-server | ok | 52 | 0 | 17 | 0 | @browserstack/mcp-server@2.5.0 |
| freee__freee-mcp | ok | 4 | 0 | 17 | 0 | freee-mcp@0.37.10 |
| heroku__heroku-mcp-server | ok | 37 | 0 | 17 | 0 | @heroku/mcp-server@1.2.13 |
| apify__apify-mcp-server | ok | 9 | 0 | 16 | 0 | @apify/actors-mcp-server@0.20.1 |
| cap-js__mcp-server | ok | 0 | 0 | 15 | 0 | @cap-js/mcp-server@0.1.0 |
| remorses__goke | ok | 0 | 0 | 15 | 0 | goke@? |
| runpod__runpod-mcp | ok | 92 | 0 | 15 | 0 | @runpod/mcp-server@4.9.1 |
| meshy-dev__meshy-mcp-server | ok | 28 | 0 | 14 | 0 | @meshy-ai/meshy-mcp-server@0.6.7 |
| mui__mui-x | ok | 1 | 0 | 14 | 0 | ?@9.17.0 |
| tufantunc__ssh-mcp | ok | 15 | 0 | 14 | 0 | ssh-mcp@2.22.1 |
| armitage-labs__creem | ok | 0 | 0 | 13 | 0 | creem-adapter@? |
| netlify__netlify-mcp | ok | 3 | 0 | 13 | 0 | @netlify/mcp@1.21.0 |
| b1ff__atlassian-dc-mcp | ok | 58 | 0 | 13 | 0 | atlassian-dc-mcp@0.1.0 |
| appium__appium-mcp | ok | 33 | 0 | 12 | 0 | appium-mcp@1.99.2 |
| tidewave-ai__tidewave_js | ok | 5 | 0 | 11 | 0 | tidewave@0.10.0 |
| eslint__rewrite | ok | 1 | 0 | 10 | 0 | eslint-rewrite@1.0.0 |
| fiberplane__mcp-lite | ok | 38 | 0 | 10 | 0 | mcp-monorepo@? |
| AgentWorkforce__relayhistory | ok | 36 | 0 | 10 | 0 | relayhistory-repository@? |
| harsha-iiiv__openapi-mcp-generator | ok | 1 | 0 | 10 | 0 | openapi-mcp-generator@5.0.1 |
| IgniteUI__igniteui-theming | ok | 15 | 0 | 10 | 0 | @igniteui-theming/root@? |
| nabheet__google-services-mcp | ok | 134 | 0 | 10 | 0 | google-services-mcp@0.1.0 |
| ktnyt__cclsp | ok | 12 | 0 | 9 | 0 | cclsp@0.7.0 |
| Unleash__unleash-mcp | ok | 11 | 0 | 8 | 0 | @unleash/mcp@0.6.0-beta.5 |
| nteract__semiotic | ok | 29 | 0 | 8 | 0 | semiotic@3.13.3 |
| chrisryugj__korean-law-mcp | ok | 100 | 0 | 8 | 0 | korean-law-mcp@4.15.21 |
| antfu__nuxt-mcp-dev | ok | 7 | 0 | 8 | 0 | ?@0.3.2 |
| GLips__Figma-Context-MCP | ok | 2 | 0 | 7 | 0 | figma-developer-mcp@0.13.2 |
| pijusz__mcp-gsc | ok | 0 | 0 | 6 | 0 | mcp-gsc@0.4.1 |
| RajwardhanShinde__elk-mcp | ok | 7 | 0 | 6 | 0 | elasticsearch-mcp@0.1.3 |
| googleapis__gcloud-mcp | ok | 62 | 0 | 5 | 0 | @google-cloud/gcloud-mcp-servers@0.1.0 |
| letoribo__mcp-graphql-enhanced | ok | 0 | 0 | 5 | 0 | @letoribo/mcp-graphql-enhanced@4.15.8 |
| zencoderai__slack-mcp-server | ok | 8 | 0 | 5 | 0 | @zencoderai/slack-mcp-server@0.0.0-dev |
| nulab__backlog-mcp-server | ok | 3 | 0 | 5 | 0 | backlog-mcp-server@0.23.3 |
| postmanlabs__postman-mcp-server | ok | 0 | 0 | 5 | 0 | @postman/postman-mcp-server@2.15.0 |
| pdogra1299__bitbucket-mcp-server | ok | 25 | 0 | 5 | 0 | @nexus2520/bitbucket-mcp-server@4.0.0 |
| mantinedev__mantine | ok | 5 | 0 | 5 | 0 | mantine-a91763c0e2@9.7.4 |
| ivo-toby__mcp-openapi-server | ok | 3 | 0 | 5 | 0 | @ivotoby/openapi-mcp-server@0.1.0 |
| vercel__next-devtools-mcp | ok | 4 | 0 | 4 | 0 | next-devtools-mcp@0.4.1 |
| Flux159__mcp-server-kubernetes | ok | 28 | 0 | 4 | 0 | mcp-server-kubernetes@4.2.1 |
| nspady__google-calendar-mcp | ok | 13 | 0 | 4 | 0 | @cocal/google-calendar-mcp@2.8.1 |
| dataforseo__mcp-server-typescript | ok | 0 | 0 | 4 | 0 | dataforseo-mcp-server@3.1.3 |
| hermoso-ai__hermoso | ok | 1 | 0 | 4 | 0 | hermoso@0.1.497 |
| benborla__mcp-server-mysql | ok | 2 | 0 | 3 | 0 | @benborla29/mcp-server-mysql@2.0.9 |
| harness__mcp-server | ok | 202 | 0 | 3 | 0 | harness-mcp-v2@3.2.39 |
| brave__brave-search-mcp-server | ok | 1 | 0 | 2 | 0 | @brave/brave-search-mcp-server@2.1.4 |
| Serdnaley__metabase-mcp | ok | 182 | 0 | 2 | 0 | @serdnaley/metabase-mcp@0.4.0 |
| argoproj-labs__mcp-for-argocd | ok | 0 | 0 | 2 | 0 | argocd-mcp@0.0.0 |
| qase-tms__qase-mcp-server | ok | 20 | 0 | 2 | 0 | @qase/mcp-server@3.0.4 |
| growthbook__growthbook-mcp | ok | 4 | 0 | 2 | 0 | @growthbook/mcp@2.2.0 |
| currents-dev__currents-mcp | ok | 0 | 0 | 1 | 0 |  |
| exa-labs__exa-mcp-server | ok | 10 | 0 | 1 | 0 | exa-mcp-server@3.4.3 |
| mclenhard__mcp-evals | ok | 1 | 0 | 1 | 0 | mcp-evals@1.0.18 |
| lobehub__mcp-hello-world | ok | 3 | 0 | 1 | 0 | mcp-hello-world@1.1.2 |
| microsoft__clarity-mcp-server | ok | 0 | 0 | 1 | 0 | @microsoft/clarity-mcp-server@2.0.2 |
| contentful__contentful-mcp-server | ok | 0 | 0 | 1 | 0 | contentful-mcp-tools@0.0.0 |
| agentfront__mcp-from-openapi | ok | 0 | 0 | 1 | 0 | mcp-from-openapi@2.5.0 |
| winor30__mcp-server-datadog | ok | 0 | 0 | 0 | 0 | @winor30/mcp-server-datadog@1.8.0 |
| ericthered926__duckduckgo-mcp-server | ok | 2 | 0 | 0 | 0 | @ericthered926/duckduckgo-mcp-server@0.6.0 |
| tavily-ai__tavily-mcp | ok | 6 | 0 | 0 | 0 | tavily-mcp@0.2.23 |
| florentine-ai__mcp | ok | 2 | 0 | 0 | 0 | @florentine-ai/mcp@1.0.0 |
| stripe__ai | ok | 0 | 0 | 0 | 0 |  |
| ihor-sokoliuk__mcp-searxng | ok | 4 | 0 | 0 | 0 | mcp-searxng@2.9.0 |
| XeroAPI__xero-mcp-server | ok | 0 | 0 | 0 | 0 | @xeroapi/xero-mcp-server@0.0.16 |
| samuraikun__aws-s3-mcp | ok | 0 | 0 | 0 | 0 | aws-s3-mcp@0.4.0 |
| cyanheads__obsidian-mcp-server | ok | 4 | 0 | 0 | 0 | obsidian-mcp-server@3.8.0 |
| primefaces__primeuix | ok | 43 | 0 | 0 | 0 | @primeuix/monorepo@0.7.0 |
| dswbx__jsonv-ts | ok | 0 | 0 | 0 | 0 | jsonv-ts@0.11.1 |
| useshortcut__mcp-server-shortcut | ok | 26 | 0 | 0 | 0 | @shortcut/mcp@0.7.1 |
