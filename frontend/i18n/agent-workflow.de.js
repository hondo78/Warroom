// German dictionary for the Agent-Workflow page. Loaded as a global before js/i18n.js.
window.I18N = window.I18N || {};
window.I18N.de = window.I18N.de || {};
window.I18N.de.agentWorkflow = {
    // page + card titles
    pageTitle: "🔀 KI-Agent — Workflow",
    pipelineTitle: "Entscheidungs-Pipeline",
    pipelineHint: "Jede Stufe durchläuft dieselbe Pipeline. Das LLM wird über <strong>strukturierte Ausgaben</strong> (Pydantic-Schema via <code>response_format</code>) angesprochen; die Antwort wird typisiert validiert und auf die erlaubten Aktionen der Stufe beschränkt.",
    globalTitle: "⚙️ Global (LLM-Anbindung)",

    // global form
    agentEnabled: "Agent aktiv (Master)",
    structuredOutput: "Strukturierte Ausgabe (Pydantic-Schema)",
    model: "Modell",
    temperature: "Temperatur",
    maxTokens: "max. Tokens",
    autoExecute: "Auto-Execute",
    autoExecuteHint: "Führt nur nicht-destruktive Aktionen (acknowledge) automatisch aus. Block-Aktionen bleiben immer bis zur Freigabe pending.",
    saveGlobal: "Global speichern",

    // structured-output badge
    structuredOn: "Structured Output: AN",
    structuredOff: "Structured Output: AUS",

    // stage cards (JS-emitted chrome)
    onDemand: "on-demand",
    runNow: "Jetzt ausführen",
    triggerLabel: "Trigger:",
    promptCustom: "eigener Prompt",
    promptDefault: "Default-Prompt",
    systemPrompt: "System-Prompt",
    systemPromptHint: "(leer ⇒ eingebauter Default)",
    promptPlaceholder: "(leer → Default für {stage})",
    loadDefault: "Default laden",
    clear: "Leeren",
    saveStage: "Stufe speichern",

    // toasts / confirms
    globalSaved: "Global gespeichert",
    stageSaved: "Stufe „{stage}\" gespeichert",
    loadFailed: "Laden fehlgeschlagen: {error}",
    saveFailed: "Speichern fehlgeschlagen: {error}",
    confirmOverwrite: "Aktuellen Prompt mit dem Default überschreiben?",
    defaultLoaded: "Default-Prompt geladen — noch nicht gespeichert.",
    confirmClear: "Feld leeren? Beim Speichern greift der eingebaute Default-Prompt.",
    runStarted: "Lauf angestoßen — Ergebnisse erscheinen unter /agent.html.",
    error: "Fehler: {error}",
};
