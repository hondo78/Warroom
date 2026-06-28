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

    // Entscheidungs-Pipeline (vom Backend geliefert, nach Schritt-Key)
    pipeline: {
        candidates: { step: "Kandidaten", detail: "Quelle liefert Kandidaten (Alert / WAF- / IPS- / Login-Events)" },
        osint: { step: "OSINT", detail: "Anreicherung öffentlicher IPs (AbuseIPDB, VirusTotal, Shodan, GreyNoise, Intelix, ipinfo) — Shodan >2 CVEs ⇒ Block-Indikator" },
        llm: { step: "LLM", detail: "Strukturierte Abfrage mit Pydantic-Schema (response_format) je Stufen-Prompt" },
        validation: { step: "Validierung", detail: "Pydantic-Validierung + Beschränkung auf erlaubte Aktionen der Stufe" },
        persistence: { step: "Persistenz", detail: "Entscheidung in agent_decisions gespeichert" },
        execution: { step: "Ausführung", detail: "Auto-Execute nur für acknowledge (Master-Switch); Block-Aktionen immer pending zur Freigabe" },
    },

    // Stufen-Karten (vom Backend geliefert, nach Stufen-Key)
    stages: {
        alert: { label: "Sophos Alerts", trigger: "Neue Alarme aus Sophos Central (letzte 24 h)" },
        event: { label: "Central Events", trigger: "Sophos-Central-Event-Stream (Endpoint-Threat/C2/Exploit), gefiltert nach event_type" },
        waf: { label: "WAF", trigger: "Frische 4xx/5xx-WAF-Events pro IP · Pfad-Cache (Redis, 24 h) erkennt Wordlist-/Directory-Brute-Force" },
        ips: { label: "IPS / IDP", trigger: "IDP/IPS-Intrusion-Events pro IP" },
        failed_login: { label: "Failed-Login (per IP)", trigger: "Fehlgeschlagene Logins pro Quell-IP" },
        failed_login_distributed: { label: "Verteilter Brute-Force", trigger: "Alle Login-Versuche des Fensters → LLM gruppiert nach /24" },
        triage: { label: "Triage (OSINT-Übergabe)", trigger: "Manuelle Übergabe eines Werts von der OSINT-Seite" },
    },

    // Numerische Stufen-Feld-Labels (nach Setting-Key)
    fields: {
        agent_interval_seconds: "Intervall (s)",
        agent_event_interval_seconds: "Intervall (s)",
        agent_waf_threshold: "Schwelle (24 h)",
        agent_waf_interval_seconds: "Intervall (s)",
        agent_ips_threshold: "Schwelle (24 h)",
        agent_ips_interval_seconds: "Intervall (s)",
        agent_failed_login_threshold: "Schwelle (24 h)",
        agent_failed_login_interval_seconds: "Intervall (s)",
        agent_failed_login_distributed_window_minutes: "Fenster (min)",
        agent_failed_login_distributed_attempts: "Versuche/​/24 (Richtwert)",
        agent_failed_login_distributed_min_ips: "Distinct-IPs/​/24",
    },
};
