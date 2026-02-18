# ClawTower Go-to-Market Strategy

**INTERNAL — PRAXIS AI + JR MORENO — NOT FOR PUBLIC DISTRIBUTION**

---

## Executive Summary

ClawTower is the first OS-level security watchdog purpose-built for AI agents. No competing product exists in this category. The strategy is to open-source under AGPL-3.0 with a Contributor License Agreement (CLA) to:

1. **Flood the space** — establish ClawTower as the default answer to "how do I secure my AI agent deployment"
2. **Lock in community** — AGPL copyleft prevents competitors from forking without open-sourcing their modifications
3. **Retain commercial control** — CLA enables dual-licensing; exclusive commercial services through Praxis AI
4. **Preserve optionality** — if open source doesn't achieve critical mass, pivot to closed-source Praxis-internal product

**IP ownership remains with JR Moreno.** Praxis receives an exclusive commercial license for services, support, and enterprise distribution. Equity negotiation is deferred until community traction validates the market.

---

## Product Positioning

### Category Creation: "AI Agent Security Watchdog"

No established category exists. Competitors are either:
- **Generic HIDS** (OSSEC, Wazuh) — not AI-agent-aware, no behavioral threat model for autonomous agents
- **Container security** (Falco, Sysdig) — runtime detection but no agent-specific policies, no "swallowed key" tamper resistance
- **AI safety tools** (Guardrails, NeMo) — prompt-level, not OS-level; can be bypassed by the agent itself

ClawTower is the only product that:
- Monitors at the **kernel level** (auditd, inotify, eBPF) — the agent cannot evade or disable it
- Has a **behavioral threat model** specifically for AI agents (data exfil, credential theft, persistence, container escape)
- Implements the **"swallowed key" pattern** — the agent it protects cannot modify, stop, or reconfigure ClawTower
- Includes **clawsudo** — a policy-enforced sudo gatekeeper that prevents privilege escalation

### Target Audience

| Segment | Pain Point | Message |
|---------|-----------|---------|
| **AI/ML Engineers** | "My agent has shell access and I have no idea what it's doing" | Real-time monitoring dashboard, Slack alerts |
| **DevOps/SRE** | "How do I give an AI agent access without giving it the keys to the kingdom?" | clawsudo policy enforcement, file integrity monitoring |
| **Security Teams** | "We need to audit what autonomous agents are doing on our infrastructure" | Hash-chained audit logs, 30+ security scanners, MITRE ATT&CK-aligned detection |
| **Startups deploying AI agents** | "We need security for compliance but don't have a security team" | One-line install, sensible defaults, OpenClaw integration |

### Key Differentiators

1. **Tamper-proof by design** — immutable binaries, chattr protection, the agent cannot disable its own watchdog
2. **270+ behavioral detection patterns** — purpose-built for AI agent threat models
3. **Drop-in for OpenClaw** — pre-configured monitoring for the most popular AI agent framework
4. **Defense-in-depth** — auditd + inotify + behavioral + policy + network + scanner layers
5. **Battle-tested** — Red Lobster pentest suite with 35+ attack vectors across 17 flags

---

## Licensing Architecture

### AGPL-3.0 + CLA on GitHub

```
┌─────────────────────────────────────────────────────┐
│  ClawTower Source Code                               │
│  License: AGPL-3.0-or-later                         │
│  Copyright (c) 2025-2026 JR Moreno                  │
│                                                      │
│  ┌──────────────┐    ┌───────────────────────┐      │
│  │ Contributors │───▶│ CLA (assign rights)   │      │
│  └──────────────┘    └───────────┬───────────┘      │
│                                  │                   │
│                    ┌─────────────▼─────────────┐    │
│                    │ Dual Licensing Enabled     │    │
│                    │                            │    │
│                    │  AGPL: Community/free      │    │
│                    │  Commercial: Praxis AI     │    │
│                    └────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

**Why AGPL-3.0:**
- **Real OSI-approved open source** — engineers trust it, unlike BSL/SSPL/Elastic which are "source-available"
- **Network copyleft clause** — if a cloud provider hosts ClawTower as a service, they must open-source their modifications (this is why MongoDB moved to SSPL — AGPL already covers this use case)
- **Prevents silent forks** — competitors can fork, but must release all modifications under AGPL
- **CLA enables dual-licensing** — because all contributors assign rights, the copyright holder (JR Moreno) can offer a separate commercial license that doesn't have AGPL obligations

**Why CLA (Contributor License Agreement):**
- Without CLA, each contributor owns their copyright and you can't dual-license
- CLA grants JR Moreno (and by extension, Praxis via commercial license) the right to relicense contributions
- Industry standard: used by Apache Foundation, Google, Meta, GitLab
- Use the [Apache Individual CLA](https://www.apache.org/licenses/icla.pdf) as template — well-understood, contributor-friendly

**What this means practically:**
- Anyone can use ClawTower for free under AGPL terms
- Enterprises that don't want AGPL obligations (can't open-source their deployment configs, custom policies, etc.) buy a commercial license from Praxis
- Competitors can't just fork and close-source it
- Cloud providers can't offer "ClawTower-as-a-Service" without open-sourcing their wrapper

---

## Praxis AI Partnership Structure

### Current State: Consulting Services

- JR Moreno provides consulting services to Praxis AI
- ClawTower IP is **not a work product** — it is independently created and owned by JR Moreno
- Praxis receives an exclusive right to provide commercial services (support, enterprise licenses, managed deployment) around ClawTower

### Commercial License Terms (Proposed)

| Term | Detail |
|------|--------|
| **Licensor** | JR Moreno (sole copyright holder) |
| **Exclusive Licensee** | Praxis AI, Inc. |
| **Scope** | Commercial sublicensing, enterprise support, managed services, training |
| **Territory** | Worldwide |
| **Duration** | 3 years initial, auto-renew |
| **Revenue share** | [To be negotiated — 15-30% of commercial revenue to licensor] |
| **Equity trigger** | If ARR from ClawTower exceeds $[X], renegotiate for equity position |
| **Termination** | If Praxis fails to commercialize within 18 months, exclusive rights revert to non-exclusive |
| **Attribution** | All commercial distributions must credit "Created by JR Moreno" |

### Equity Negotiation Framework

The equity conversation is deferred until market validation, but the commercial license should include **pre-negotiated triggers**:

- **Trigger 1: GitHub stars > 5,000** — Validates market demand. Begin equity discussion.
- **Trigger 2: First paying enterprise customer** — Validates commercial viability. Formalize equity offer.
- **Trigger 3: ARR > $500K** — Validates business model. Equity must be resolved or exclusive license terminates.

This protects both sides: Praxis doesn't give equity for an unproven product, and JR doesn't give away commercial rights to a product that Praxis profits from without fair compensation.

---

## Go-to-Market Phases

### Phase 1: Open Source Launch (Weeks 1-4) — "Flood the Space"

**Goal:** Establish ClawTower as the first and only AI agent security watchdog. Own the category before anyone else enters.

**Actions:**
- [ ] Push to GitHub under AGPL-3.0 with CLA
- [ ] Write launch blog post: "Your AI Agent Has Root Access. Now What?"
- [ ] Submit to Hacker News, Reddit r/netsec, r/MachineLearning, r/selfhosted
- [ ] Post on X/Twitter with demo video (TUI dashboard, live threat detection)
- [ ] Publish to awesome-security, awesome-ai-agents, awesome-rust lists
- [ ] Create a 2-minute demo video: install ClawTower → deploy AI agent → watch it detect threats in real-time
- [ ] Cross-post to OpenClaw community channels (Discord, forums)

**Messaging:** "The AI agent security problem is solved. ClawTower monitors your agent at the OS level — and the agent can't turn it off."

**Key metric:** GitHub stars in first 30 days. Target: 1,000+

### Phase 2: Community Building (Months 2-6)

**Goal:** Build contributor base, establish ClawTower as the standard.

**Actions:**
- [ ] Create "good first issue" labels for onboarding contributors
- [ ] Write contributor guide + CLA signing workflow (use CLA Assistant on GitHub)
- [ ] Monthly security advisories / threat intelligence blog posts
- [ ] Conference talks: DEF CON AI Village, BSides, KubeCon, AI Engineer Summit
- [ ] Integration guides for major AI agent frameworks beyond OpenClaw
- [ ] Plugin system for community-contributed detection rules
- [ ] Discord / community forum

**Key metric:** Monthly active contributors. Target: 20+

### Phase 3: Commercial Offering via Praxis (Months 6-12)

**Goal:** Monetize through Praxis AI with enterprise features.

**Commercial-only features (not in AGPL repo):**
- Managed ClawTower SaaS (Praxis-hosted)
- Multi-agent fleet dashboard (central monitoring for N agents)
- Compliance reporting (SOC2, ISO 27001 evidence generation)
- Priority support SLA
- Custom policy development
- Incident response consulting

**Key metric:** First 3 paying enterprise customers. Target ARR: $100K+

### Phase 4: Foundation (Month 12+, conditional)

**Trigger:** Community traction validates foundation model (500+ stars, 20+ contributors, 3+ enterprise customers).

**Structure:**
- Establish ClawTower Foundation (Linux Foundation / CNCF sandbox project or independent)
- Transfer trademark (not copyright) to foundation
- JR Moreno retains copyright + CLA rights (foundation governs the project, not the IP)
- Foundation handles governance, roadmap voting, contributor management
- Praxis remains exclusive commercial licensee

**Why foundation matters:**
- Signals long-term commitment to enterprises evaluating adoption
- Neutral governance attracts contributors who won't contribute to a single-company project
- CNCF/LF membership is a credibility signal in enterprise sales

---

## Contingency: Closed-Source Pivot

**Trigger:** Open source fails to achieve critical mass within 12 months (< 500 stars, < 5 contributors, no enterprise interest).

**Pivot plan:**
1. Archive GitHub repo (don't delete — maintains credibility)
2. Continue development as Praxis-internal product
3. Offer as proprietary SaaS or on-prem enterprise software
4. Existing AGPL users can continue using the last open-source version (AGPL is irrevocable for published code)
5. New development is proprietary

**Why this works:** AGPL + CLA means you always have the right to change licensing for new code. Existing published code remains AGPL forever, but new features and improvements can be proprietary.

---

## Competitive Moat (Why This Is Defensible)

1. **First mover in an empty category** — there is no "AI agent security watchdog" market today. ClawTower defines it.
2. **AGPL prevents hostile forks** — competitors must open-source modifications, so they can't out-feature you in secret
3. **Deep Linux integration** — 10K+ lines of Rust interfacing with auditd, inotify, eBPF, chattr, AppArmor. Non-trivial to replicate.
4. **Battle-tested pentest suite** — Red Lobster v5-v8, 35+ attack vectors. This is years of adversarial testing baked in.
5. **OpenClaw integration** — first-party support for the leading AI agent framework. Network effects if OpenClaw recommends ClawTower.
6. **Community lock-in** — once engineers deploy ClawTower and write custom policies, switching costs are high

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Cloud provider forks ClawTower | Medium | High | AGPL forces open-sourcing; CLA enables commercial enforcement |
| OpenClaw builds native security | Low | Critical | Deepen integration, contribute upstream, make ClawTower complementary not competitive |
| Generic HIDS adds AI-agent features | Medium | Medium | Move faster, own the narrative, community > features |
| No community adoption | Medium | High | Closed-source pivot to Praxis internal |
| Praxis can't commercialize | Medium | Medium | Revert to non-exclusive license, find alternative partner |
| Contributor refuses CLA | Low | Low | Standard in industry; explain dual-licensing rationale transparently |

---

## Immediate Next Steps

1. **Legal:** Draft CLA based on Apache ICLA template. Review AGPL-3.0 header for all source files.
2. **GitHub:** Add LICENSE file, CONTRIBUTING.md with CLA requirement, CODE_OF_CONDUCT.md
3. **Praxis:** Draft commercial license agreement with equity triggers
4. **Content:** Write launch blog post and record demo video
5. **Launch:** Coordinate HN/Reddit/X push for maximum first-day visibility

---

*Document prepared for internal strategy discussion. JR Moreno + Praxis AI. February 2026.*
