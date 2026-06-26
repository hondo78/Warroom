// English dictionary for the Agent-Workflow page. Loaded as a global before js/i18n.js.
window.I18N = window.I18N || {};
window.I18N.en = window.I18N.en || {};
window.I18N.en.agentWorkflow = {
    // page + card titles
    pageTitle: "🔀 AI Agent — Workflow",
    pipelineTitle: "Decision pipeline",
    pipelineHint: "Every stage runs through the same pipeline. The LLM is addressed via <strong>structured outputs</strong> (Pydantic schema through <code>response_format</code>); the response is validated against the type and restricted to the stage's allowed actions.",
    globalTitle: "⚙️ Global (LLM connection)",

    // global form
    agentEnabled: "Agent active (master)",
    structuredOutput: "Structured output (Pydantic schema)",
    model: "Model",
    temperature: "Temperature",
    maxTokens: "Max. tokens",
    autoExecute: "Auto-Execute",
    autoExecuteHint: "Only runs non-destructive actions (acknowledge) automatically. Block actions always stay pending until approval.",
    saveGlobal: "Save global",

    // structured-output badge
    structuredOn: "Structured Output: ON",
    structuredOff: "Structured Output: OFF",

    // stage cards (JS-emitted chrome)
    onDemand: "on-demand",
    runNow: "Run now",
    triggerLabel: "Trigger:",
    promptCustom: "custom prompt",
    promptDefault: "default prompt",
    systemPrompt: "System prompt",
    systemPromptHint: "(empty ⇒ built-in default)",
    promptPlaceholder: "(empty → default for {stage})",
    loadDefault: "Load default",
    clear: "Clear",
    saveStage: "Save stage",

    // toasts / confirms
    globalSaved: "Global saved",
    stageSaved: "Stage \"{stage}\" saved",
    loadFailed: "Loading failed: {error}",
    saveFailed: "Saving failed: {error}",
    confirmOverwrite: "Overwrite the current prompt with the default?",
    defaultLoaded: "Default prompt loaded — not saved yet.",
    confirmClear: "Clear field? On save the built-in default prompt takes effect.",
    runStarted: "Run started — results will appear under /agent.html.",
    error: "Error: {error}",
};
