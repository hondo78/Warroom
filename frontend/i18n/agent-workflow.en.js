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

    // self-learning auto-approval
    learnTitle: "🧠 Self-learning auto-approval",
    learnHint: "Records every human approval/rejection per decision <strong>signature</strong> (source · action · rule). Once a signature's <strong>net score</strong> (approvals − rejections) reaches the threshold, matching new decisions are <strong>auto-approved and executed</strong> — block actions included. The whitelist is always re-checked, so your own IPs stay safe.",
    learnEnabled: "Learning active",
    learnThreshold: "Approval threshold",
    learnSave: "Save learning settings",
    learnSaved: "Learning settings saved",
    learnPatternsTitle: "Learned patterns",
    learnPatternsHint: "Eligible patterns (net ≥ threshold) auto-approve while learning is active.",
    learnNoPatterns: "Nothing learned yet — approve or reject decisions to train patterns.",
    learnEligible: "auto-approves",
    learnProgress: "learning ({n}/{t})",
    learnForget: "forget",
    learnForgetConfirm: "Forget this learned pattern? Its approvals/rejections are reset.",
    learnForgotten: "Pattern forgotten.",
    colSource: "Source",
    colAction: "Action",
    colRule: "Rule / signature",
    colApprovals: "Appr.",
    colRejections: "Rej.",
    colNet: "Net",
    colAuto: "Auto",
    colStatus: "Status",

    // decision pipeline (backend-driven, keyed by step id)
    pipeline: {
        candidates: { step: "Candidates", detail: "Source yields candidates (alert / WAF / IPS / login events)" },
        osint: { step: "OSINT", detail: "Enrichment of public IPs (AbuseIPDB, VirusTotal, Shodan, GreyNoise, Intelix, ipinfo) — Shodan >2 CVEs ⇒ block indicator" },
        llm: { step: "LLM", detail: "Structured query with Pydantic schema (response_format) per stage prompt" },
        validation: { step: "Validation", detail: "Pydantic validation + restriction to the stage's allowed actions" },
        persistence: { step: "Persistence", detail: "Decision stored in agent_decisions" },
        execution: { step: "Execution", detail: "Auto-execute only for acknowledge (master switch); block actions always stay pending for approval" },
    },

    // stage cards (backend-driven, keyed by stage key)
    stages: {
        alert: { label: "Sophos Alerts", trigger: "New alerts from Sophos Central (last 24 h)" },
        event: { label: "Central Events", trigger: "Sophos Central event stream (endpoint threat/C2/exploit), filtered by event_type" },
        waf: { label: "WAF", trigger: "Fresh 4xx/5xx WAF events per IP · path cache (Redis, 24 h) detects wordlist/directory brute force" },
        ips: { label: "IPS / IDP", trigger: "IDP/IPS intrusion events per IP" },
        failed_login: { label: "Failed login (per IP)", trigger: "Failed logins per source IP" },
        failed_login_distributed: { label: "Distributed brute force", trigger: "All login attempts in the window → LLM groups by /24" },
        triage: { label: "Triage (OSINT handoff)", trigger: "Manual handoff of a value from the OSINT page" },
    },

    // stage numeric-setting field labels (keyed by setting key)
    fields: {
        agent_interval_seconds: "Interval (s)",
        agent_event_interval_seconds: "Interval (s)",
        agent_waf_threshold: "Threshold (24 h)",
        agent_waf_interval_seconds: "Interval (s)",
        agent_ips_threshold: "Threshold (24 h)",
        agent_ips_interval_seconds: "Interval (s)",
        agent_failed_login_threshold: "Threshold (24 h)",
        agent_failed_login_interval_seconds: "Interval (s)",
        agent_failed_login_distributed_window_minutes: "Window (min)",
        agent_failed_login_distributed_attempts: "Attempts //24 (guideline)",
        agent_failed_login_distributed_min_ips: "Distinct IPs //24",
    },
};
