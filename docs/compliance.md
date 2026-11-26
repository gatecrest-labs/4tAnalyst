# Data Sensitivity & Compliance Considerations

⚠️ **Warning for anyone deploying 4tAnalyst:** this tool sends firewall request data — IPs, hostnames, ports, firewall/zone names, ticket justification text — to an AI inference endpoint (Anthropic direct, AWS Bedrock, or self-hosted) as part of normal operation. If your organization's network topology, device identifiers, or change records are subject to a regulatory or contractual data-protection regime — NERC CIP, HIPAA, SOX, PCI-DSS, GDPR/CCPA, or an internal data-classification policy — **you are responsible for determining whether that data may be sent to your chosen inference path before using this tool in production.** 4tAnalyst itself does not classify data or enforce any compliance regime.

This document is written to be regime-agnostic: the questions and architectural controls below apply the same way regardless of which regulatory framework governs your deployment. Substitute your own regime's terms as you read — regulated/sensitive data, protected information, cardholder data, PHI, PII, financial records, or whatever your organization's data-classification policy calls it.

**Status:** Reference document — not a finished compliance assessment for any regime. If you operate in a regulated environment, take this to your own compliance/legal team before production use.

---

## The core question

When an engineer uses Claude Code to analyze a firewall change request, data typed into the prompt — including source IPs, destination IPs, hostnames, service ports, and firewall names — is sent to an AI inference endpoint for processing. If any of that data qualifies as protected/regulated information under the regime that applies to your organization, then the data transmission path must meet that regime's protection requirements.

This document addresses: what data is transmitted, where it goes under each deployment model, and what architectural controls can reduce or eliminate the exposure.

---

## What data leaves the internal network

### Data the engineer types into Claude Code prompts

Any text the engineer enters into a Claude Code prompt is sent to the AI model for processing. This includes:

- Source and destination IP addresses
- Hostnames or device names
- Service names, port numbers, and protocols
- Justification text copied from the ServiceNow ticket
- Firewall names mentioned explicitly

### Data returned by MCP tool calls

When Claude Code calls an MCP tool (e.g., zone_mcp to resolve an IP, fortimanager_mcp to search for existing rules), the tool result is also sent back through the AI model to generate the response. This means:

- Zone names and policy verdicts returned from 4THealth
- Rule names, descriptions, and object names returned from FortiManager
- Any subnet or IP data returned by those tools

### Policy-export review (`/sanitize-policy`, `/review-policy`)

A Rule Review policy export never leaves the workstation in raw form. The engineer renames it to a neutral `export-*.json` name, and the offline `policy_sanitize` tool replaces IPs, hostnames, and configured company/site terms with consistent fakes locally; a fail-closed verifier blocks the output if any original value remains. Only the sanitized copy is read by the model. The real-to-fake map stays on the workstation (`~/.local/share/4tanalyst/sanitize/`, mode 0600, refused in synced folders, expires after 30 days) and is never sent to the model. Restoring real values (`map-back`) is a local step whose output must not be pasted back into Claude. Residual exposure: rule structure, service names, and meaning words in object names (for example OT, DMZ) are kept so the review is useful; terms the engineer did not list may survive, which the `unmatched-identifiers` count and `--strict` mode are designed to catch.

**What does NOT leave the internal network:** Firewall credentials, API keys, and direct API traffic between the MCP servers and FortiManager. Those calls happen entirely on the central MCP server. Engineer workstations never connect directly to firewall management APIs.

---

## The two deployment paths and their compliance profiles

### Path A — AWS Bedrock (current configuration)

In the current setup, Claude Code sends prompts to **AWS Bedrock in us-east-2** using your organization's AWS account. This is not the same as sending data to Anthropic's consumer service.

| Factor | Detail |
|---|---|
| Data recipient | AWS Bedrock inference endpoint, in your AWS account |
| Model training | AWS states that prompts and completions sent via Bedrock are **not used to train models** |
| Data retention | AWS does not retain prompt/response data beyond the inference call (unless you explicitly enable Bedrock logging) |
| Geographic boundary | Data stays in us-east-2 unless Cross-Region Inference is explicitly enabled |
| Governing agreement | Your organization's AWS Customer Agreement and associated DPA/BAA |
| Audit control | CloudWatch can be configured to log Bedrock invocations — confirm whether this is enabled and whether those logs are subject to your organization's data-protection controls |

**Key question for your AWS team:** Does your organization's existing AWS enterprise agreement explicitly cover Bedrock inference data under its data processing addendum? Most do — verify with your AWS account team.

**Key question for compliance:** Does your organization treat AWS (under an enterprise agreement with appropriate DPA) as an authorized recipient of your regulated/protected data, consistent with how you treat other cloud services that process that same category of information?

### Path B — Anthropic consumer API or Claude Max subscription

If the decision is made to use Anthropic's direct API or a Claude Max subscription (not Bedrock), the data handling profile is different.

| Factor | Detail |
|---|---|
| Data recipient | Anthropic's infrastructure (US-based data centers) |
| Model training | Anthropic's API terms state that API inputs/outputs are **not used to train models** by default (as of the current terms of service — verify current policy) |
| Data retention | Anthropic retains prompts for a limited period for trust and safety purposes under their standard terms; enterprise agreements may provide different terms |
| Geographic boundary | Anthropic's infrastructure is US-based; data may traverse Anthropic's CDN and cloud provider network |
| Governing agreement | Anthropic's standard API terms, or an enterprise agreement if negotiated |
| Audit control | No equivalent to CloudWatch; limited visibility into data handling beyond Anthropic's published policies |

**This path generally has a weaker compliance posture than a managed cloud path like Bedrock** for a regulated environment (any regime — NERC CIP, HIPAA, SOX, PCI-DSS, etc.) because:

- The governing agreement is with a third party (Anthropic) rather than an existing enterprise cloud provider
- Data retention and handling terms are less customizable without a negotiated enterprise agreement
- Visibility and audit controls are more limited

If the organization does not already have an enterprise agreement with Anthropic, pursuing one before production use is advisable. The agreement should address: no training on customer data, data retention windows, incident notification, and geographic processing boundaries.

### Path C — Self-hosted model (future option)

A third path exists that eliminates the external data transmission question entirely: running a self-hosted open-source model on the central MCP server or an internal inference server. In this model, Claude Code would connect to the internal inference endpoint rather than any external service.

This approach would require:
- A self-hosted model capable of the analysis tasks (Llama 3, Mistral, or similar)
- Sufficient GPU/CPU infrastructure for inference
- Integration with Claude Code's configurable model endpoint

This is the most conservative option from a regulated-data perspective (whatever your regime calls the protected category — BCSI, PHI, cardholder data, PII, or otherwise) but requires the most infrastructure investment. It is worth raising with your compliance team as a potential long-term direction if external transmission of protected data is ruled out entirely.

---

## Architectural mitigation: MCP server as the data boundary

Regardless of the inference path chosen, there is an architectural control that can significantly reduce the amount of sensitive data that reaches the AI model.

**The problem today:** Engineers type raw IPs and hostnames directly into Claude Code prompts. Those values are transmitted verbatim to the inference endpoint.

**The mitigation:** Engineer provides a ServiceNow ticket number. The MCP server retrieves the source/destination IPs internally, resolves them to zones, and returns only the **zone names and verdicts** to Claude Code. The raw IPs never appear in the prompt or response. This is useful for any zone your organization considers sensitive under whatever regime applies — a NERC CIP regulated zone, a PCI cardholder-data zone, a HIPAA-scoped clinical network, etc.

```
Current flow (IPs reach the inference endpoint):
  Engineer types: "Check 10.4.20.5 to 10.6.0.1 on tcp/102"
                          ↓
              Sent to Bedrock/Anthropic verbatim

Mitigated flow (IPs stay inside the MCP boundary):
  Engineer types: "Analyze ticket INC0045892"
                          ↓
        intake_mcp fetches ticket → resolves IPs internally
                          ↓
        Returns to Claude: "Source zone: OT-PROD, Dest zone: SENSITIVE-ZONE, verdict: BLOCKED"
                          ↓
              Only zone names and verdicts reach Bedrock/Anthropic
```

This mitigation means the AI model only ever sees:
- Zone names (e.g., `OT-PROD`, `SENSITIVE-ZONE`) — not IP addresses
- Policy verdicts (ALLOWED / BLOCKED / UNKNOWN)
- Rule names and object names (which may or may not be regulated depending on your classification)
- ServiceNow ticket numbers (which typically are not regulated data on their own)

**Implementation status:** Not yet built. `intake_mcp` currently returns raw field values including IPs. Implementing this pattern requires adding a ticket-number lookup path to `intake_mcp` and updating the skills to use it for sensitive/regulated-zone requests. This is an optional Phase 3 item — build it if your deployment's data classification calls for it, not as a default gate on using the tool.

**Interim guidance:** Until this mitigation is implemented, engineers at organizations with regulated zones should not enter raw sensitive identifiers (e.g., IPs of systems in scope under your regime) into Claude Code prompts. Use zone names directly if you know them, or perform the IP resolution manually and provide only the zone name. The system will work correctly with zone names as input to `/check-policy`.

---

## Questions for your compliance team

If you operate in a regulated environment, the following questions should be answered before production use. Bring this document and `SECURITY.md` to the engagement. Substitute your own regime's terms as needed (BCSI/NERC CIP, PHI/HIPAA, cardholder data/PCI-DSS, PII/GDPR, financial records/SOX) — the shape of each question carries over.

### 1. Data classification

- Do IP addresses of your most sensitive systems (e.g., systems in scope under your regulatory regime) qualify as protected/regulated information under your current procedures?
- Do IP addresses of the firewall management systems themselves qualify?
- Do firewall rule names, object names, and zone names qualify, or are they treated differently?
- What is the classification of network topology information (zone names, subnet ranges, policy verdicts)?

*Note: not all IPs that appear in firewall rules are necessarily regulated. IPs of general IT workstations, servers, and user systems that appear as traffic sources or destinations are often out of scope even when your most sensitive systems are in scope. The classification question is primarily about IPs of the systems your regime actually protects.*

### 2. Inference path approval

- Under the chosen deployment path (Bedrock, Anthropic direct, or self-hosted), does your organization's existing data processing agreement with the provider cover AI inference data?
- Is the chosen provider an authorized recipient of your regulated data under your current data-protection procedures, or must procedures be updated?
- If Bedrock is used: does AWS Bedrock inference fall under the same data processing addendum as other AWS services your organization uses?
- If Anthropic direct API is used: does Anthropic need to be added as a new authorized vendor under your vendor-approval process? What is that process?

### 3. Data retention and audit

- Are you required to retain records of what regulated data was transmitted, to whom, and when? If so, does CloudWatch Bedrock logging (or equivalent) satisfy that requirement, or is additional logging needed?
- Is the feedback_mcp decision log (which records ticket numbers, engineer IDs, and decision outcomes but not raw IPs) subject to your data-protection controls?
- Are peer review packages generated by 4tAnalyst considered regulated if they contain zone names, rule details, and approval chains?

### 4. Procedure updates

- Does your current data-protection procedure need to be updated to address AI-assisted tooling before production use?
- Does your change-management procedure need to reference the use of AI assistance in firewall change analysis?
- Are there any restrictions on which personnel may use AI-assisted tools for work touching your most sensitive systems?

### 5. Architectural mitigation decision

- Is the MCP-as-boundary architecture (ticket number in, zone names out — no raw IPs to the inference endpoint) sufficient to reduce exposure to an acceptable level for your most sensitive zones?
- If yes: can requests that don't touch those zones use the current flow (raw IPs in prompts) without additional controls?
- If no: is self-hosted inference required, or is there another acceptable control?

---

## Recommended actions before production use in a regulated environment

If your deployment doesn't touch regulated/sensitive data, none of this applies and you can use the tool as-is. If it does, listed in order of lead time (longest first):

1. **Determine inference path (Bedrock vs. Anthropic direct vs. self-hosted)** — the compliance argument differs significantly. Resolve this with IT/InfoSec before engaging your compliance team, so you bring a defined architecture to the meeting rather than an open question.

2. **Engage your compliance/legal team** with this document and `SECURITY.md`. That review typically has the longest lead time of any item — start early.

3. **Verify your cloud provider's data processing terms** with your account team (e.g. AWS for Bedrock). Get written confirmation that inference data is covered under your existing DPA.

4. **Confirm provider-side invocation logging status** — check whether logging (e.g. AWS CloudWatch for Bedrock) is capturing inference calls in your account, and if so, confirm those logs are stored and protected consistently with your own data-handling requirements.

5. **Implement MCP-as-boundary mitigation** for your most sensitive zone requests before allowing engineers to use the system on those changes. This is an optional Phase 3 development item — build it only if your classification calls for it.

6. **Update internal data-protection procedures** if required by your compliance team's assessment.

7. **Restrict sensitive-zone requests to the mitigated path** until mitigation is implemented — engineers working on those requests should provide zone names rather than raw sensitive identifiers.

---

## References

Regimes to check if applicable to your deployment (not exhaustive — consult your own compliance team for the authoritative list):
- NERC CIP — CIP-011 (Information Protection / BCSI handling), CIP-010 (Configuration Change Management and Vulnerability Management), CIP-005 (Electronic Security Perimeters / Interactive Remote Access), if any traffic touches BES Cyber Systems
- HIPAA / HITECH — Protected Health Information (PHI), if any traffic touches clinical or health-data networks
- PCI-DSS — cardholder data environment (CDE) requirements, if any traffic touches payment systems
- SOX — internal controls over financial reporting systems
- GDPR / CCPA / state privacy laws — personal data (PII) handling and cross-border transfer rules

General:
- AWS Bedrock data privacy: [aws.amazon.com/bedrock/faqs](https://aws.amazon.com/bedrock/faqs) — "Does Amazon Bedrock use my data to train models?"
- Anthropic usage policies and data handling: [anthropic.com/legal/privacy](https://www.anthropic.com/legal/privacy)
- `SECURITY.md` — credential handling, sensitive data checklist, accuracy limitations
- `docs/engineer-workflow.md` — engineer operational guidance including interim sensitive-data handling
