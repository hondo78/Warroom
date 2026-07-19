window.I18N = window.I18N || {}; window.I18N.en = window.I18N.en || {};
window.I18N.en.stats = {
    page_title: "📊 OSINT API — Usage & Cost",

    // header controls
    range_today: "Today",
    range_7d: "Last 7 days",
    range_30d: "Last 30 days",
    range_90d: "Last 90 days",
    flush_reload_title: "Write in-memory counters to the DB immediately and reload data",
    flush_reload: "Flush+Reload",
    limits_title: "Configure quota limits",
    limits: "Limits",

    // section tabs
    tab_osint: "OSINT Providers",
    tab_llm: "LLM",

    // OSINT KPIs
    calls_today: "Calls today",
    real_calls_no_cache: "real API calls (excluding cache)",
    calls_month: "Calls this month",
    since_month_start: "since start of month",
    cache_hit_rate: "Cache hit rate",
    kpi_saved: "— saved",
    providers_near_limit: "Providers near limit",
    utilization_80: "≥ 80 % utilization",

    // OSINT provider section
    daily_trend_all: "Daily trend — all providers",
    provider_detail: "Provider detail",
    col_provider: "Provider",
    col_today: "Today",
    col_this_month: "This month",
    col_daily_limit: "Daily limit",
    col_monthly_limit: "Monthly limit",
    col_cache_hit: "Cache hit",
    col_2xx_norecord_error: "2xx / no_record / error",
    col_last_call: "Last call",

    // provider card (dynamic)
    limit_exceeded: "LIMIT EXCEEDED",
    near_limit: "near limit",
    ok_badge: "ok",
    day: "Day",
    month: "Month",
    no_limit: "(no limit)",
    cache_hit: "Cache hit",
    from_cache: "from cache",
    errors: "errors",
    saved_from_cache_window: "{n} from cache (window)",

    // LLM KPIs
    llm_calls_endpoint: "to /chat/completions",
    success_rate: "Success rate",
    avg_latency_ms: "Avg latency (ms)",
    tokens_month: "Tokens this month",
    last_call_prefix: "last call:",
    today_prefix: "today:",
    window_calls: "Window: {n} calls",

    // LLM charts / analyzer
    calls_per_source: "Calls per source",
    daily_trend: "Daily trend",
    analyze_title: "Analysis — Calls & Tokens",
    range_btn_24h: "24h",
    range_btn_7d: "7 d",
    range_btn_30d: "30 d",
    range_btn_90d: "90 d",
    from: "From",
    to: "To",
    sources_label: "Sources:",

    // source detail
    source_detail: "Source detail",
    col_source: "Source",
    col_calls: "Calls",
    col_success: "Success",
    col_error: "Error",
    col_prompt_tokens: "Prompt tokens",
    col_completion_tokens: "Completion tokens",
    col_avg_latency: "Avg latency (ms)",

    // models
    models: "Models",
    col_model: "Model",

    // chart series labels / axes
    chart_success: "Success",
    chart_error: "Error",
    calls: "Calls",
    tokens: "Tokens",
    tokens_sum: "Tokens (sum)",

    // empty states
    no_llm_calls: "No LLM calls yet — the agent must be enabled and have completed a run.",
    no_model_runs: "No model runs recorded.",

    // analyzer footer
    sources_active: "{active} of {total} sources active",
    all_sources: "all {total} sources",
    day_one: "{n} day",
    day_many: "{n} days",
    analyze_footer: "{from} to {to} ({days}) · {srcNote} · {calls} calls (avg {avgPerDay}/day) · {tokens} tokens (avg {perCall}/call)",

    // LLM source labels
    src_test: "Test (probe)",
    src_manual: "Manual",

    // errors
    error: "Error:",
};
