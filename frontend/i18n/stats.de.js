window.I18N = window.I18N || {}; window.I18N.de = window.I18N.de || {};
window.I18N.de.stats = {
    page_title: "📊 OSINT-API — Nutzung & Kosten",

    // header controls
    range_today: "Heute",
    range_7d: "Letzte 7 Tage",
    range_30d: "Letzte 30 Tage",
    range_90d: "Letzte 90 Tage",
    flush_reload_title: "In-Memory-Counter sofort in die DB schreiben und Daten neu laden",
    flush_reload: "Flush+Reload",
    limits_title: "Quota-Limits konfigurieren",
    limits: "Limits",

    // section tabs
    tab_osint: "OSINT-Provider",
    tab_llm: "LLM",

    // OSINT KPIs
    calls_today: "Calls heute",
    real_calls_no_cache: "echte API-Calls (ohne Cache)",
    calls_month: "Calls diesen Monat",
    since_month_start: "seit Monatsanfang",
    cache_hit_rate: "Cache-Hit-Rate",
    kpi_saved: "— gespart",
    providers_near_limit: "Provider nahe Limit",
    utilization_80: "≥ 80 % Auslastung",

    // OSINT provider section
    daily_trend_all: "Tagesverlauf — alle Provider",
    provider_detail: "Provider-Detail",
    col_provider: "Provider",
    col_today: "Heute",
    col_this_month: "Diesen Monat",
    col_daily_limit: "Tageslimit",
    col_monthly_limit: "Monatslimit",
    col_cache_hit: "Cache-Hit",
    col_2xx_norecord_error: "2xx / no_record / Fehler",
    col_last_call: "Letzter Call",

    // provider card (dynamic)
    limit_exceeded: "LIMIT ÜBERSCHRITTEN",
    near_limit: "nahe Limit",
    ok_badge: "ok",
    day: "Tag",
    month: "Monat",
    no_limit: "(kein Limit)",
    cache_hit: "Cache-Hit",
    from_cache: "aus Cache",
    errors: "Fehler",
    saved_from_cache_window: "{n} aus Cache (Window)",

    // LLM KPIs
    llm_calls_endpoint: "an /chat/completions",
    success_rate: "Erfolgsrate",
    avg_latency_ms: "Ø Latenz (ms)",
    tokens_month: "Tokens diesen Monat",
    last_call_prefix: "letzter Call:",
    today_prefix: "heute:",
    window_calls: "Fenster: {n} Calls",

    // LLM charts / analyzer
    calls_per_source: "Calls pro Quelle",
    daily_trend: "Tagesverlauf",
    analyze_title: "Analyse — Calls & Tokens",
    range_btn_24h: "24h",
    range_btn_7d: "7 T",
    range_btn_30d: "30 T",
    range_btn_90d: "90 T",
    from: "Von",
    to: "Bis",
    sources_label: "Quellen:",

    // source detail
    source_detail: "Quellen-Detail",
    col_source: "Quelle",
    col_calls: "Calls",
    col_success: "Erfolg",
    col_error: "Fehler",
    col_prompt_tokens: "Prompt-Tokens",
    col_completion_tokens: "Completion-Tokens",
    col_avg_latency: "Ø Latenz (ms)",

    // models
    models: "Modelle",
    col_model: "Modell",

    // chart series labels / axes
    chart_success: "Erfolg",
    chart_error: "Fehler",
    calls: "Calls",
    tokens: "Tokens",
    tokens_sum: "Tokens (Summe)",

    // empty states
    no_llm_calls: "Noch keine LLM-Aufrufe — der Agent muss eingeschaltet sein und einen Lauf gemacht haben.",
    no_model_runs: "Kein Modell-Lauf erfasst.",

    // analyzer footer
    sources_active: "{active} von {total} Quellen aktiv",
    all_sources: "alle {total} Quellen",
    day_one: "{n} Tag",
    day_many: "{n} Tage",
    analyze_footer: "{from} bis {to} ({days}) · {srcNote} · {calls} Calls (Ø {avgPerDay}/Tag) · {tokens} Tokens (Ø {perCall}/Call)",

    // LLM source labels
    src_test: "Test (Probe)",
    src_manual: "Manuell",

    // errors
    error: "Fehler:",
};
