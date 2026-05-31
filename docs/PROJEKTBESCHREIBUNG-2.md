# Warroom — Agent-Architektur (Kurzbeschreibung)

A security-operations system where agents detect threats and drive automated defense across a Sophos environment.

- 'WAF', 'IPS', and 'BruteForce' agents analyze firewall and login telemetry to spot attacks. They discover and invoke defensive controls through a central MCP Server.
- The 'MCP Server' acts as a universal integration bridge to all Sophos and threat-intel systems, exposing tools like 'blockIp', 'blockSubnet', 'isolateEndpoint', 'osintLookup', and 'releaseQuarantine'. It provides a secure, API-key-guarded client-server model — including a whitelist that prevents blocking the organization's own assets.
- A 'Triage' agent assesses any IP, domain, or URL on demand, using the MCP Server's 'osintLookup' tool (AbuseIPDB, VirusTotal, Shodan, GreyNoise, Sophos Intelix, DNS) to enrich its verdict before recommending a block.
- An 'Email' agent monitors mail quarantine, using MCP Server tools to release or delete messages and to allow/block senders securely.
- A central 'SecOpsOrchestrator' agent manages high-level commands ("Containment"), using MCP to discover available device-control tools and orchestrating the detection agents via the A2A protocol to execute the response (block sources, isolate endpoints, quarantine mail).
- Agents operate with high autonomy yet stay human-supervised — recommendations queue as pending decisions and execute only on approval or above a confidence threshold; MCP ensures secure and standardized access to all defensive hardware and APIs.
