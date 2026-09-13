"""The predicates that define "a WAF event" and "an IPS event".

These appear twice by necessity — once in the queries behind the dashboard
widgets, once in the ``WHERE`` clause of the partial indexes those queries rely
on. The two must stay character-identical: a partial index only serves a query
whose predicate the planner can prove is implied by the index's own. Change the
query and not the index and nothing breaks loudly — the widget simply starts
sequentially scanning ~29M rows, and the first symptom is a dashboard that got
slow for no visible reason.

They live here rather than in either file because ``main.py`` imports
``database.py``, so the constants cannot sit in ``main.py`` without a cycle.
This module imports nothing.

Sophos spells the same thing several ways across firmware versions and log
components, which is why these are disjunctions rather than a single equality.
"""
from __future__ import annotations

WAF_FILTER_SQL = """(
    log_type = 'WAF'
    OR (raw_data->>'log_component') ILIKE '%waf%'
    OR (raw_data->>'log_component') ILIKE '%web app%'
    OR (raw_data->>'log_component') ILIKE '%web server protection%'
    OR (raw_data->>'log_subtype')   ILIKE '%waf%'
)"""

IPS_FILTER_SQL = """(
    log_type IN ('IDP', 'IPS')
    OR (raw_data->>'log_component') ILIKE '%intrusion%'
    OR (raw_data->>'log_component') ILIKE '%idp%'
    OR (raw_data->>'log_component') = 'IPS'
)"""
