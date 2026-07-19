# Console Capture Guide: AWS Bedrock AgentCore for Check Point MCP

This document is the operator walkthrough and collection guide for capturing, preparing, and sanitizing AWS Bedrock AgentCore console screenshots. These images illustrate the step-by-step click-ops deployment described in [docs/scenarios/mcp-tools-on-agentcore.md](../../../docs/scenarios/mcp-tools-on-agentcore.md).

Following this guide ensures your console captures are visually consistent, functionally complete, and fully sanitized for public distribution.

---

## Screen Catalog & Visual Specifications

Registering Check Point MCP servers requires capturing five essential screens. Standardize each image to a recommended width of **1400px** in **PNG or WebP** format.

### 1. Agent Runtime Creation (`01-runtime-create.png`)
* **Console Path:** Bedrock AgentCore → Agent Runtimes → **Host agent / Create runtime**
* **Key Fields & Expected Inputs:**
  * **Name / Identifier:** `chkp_quantum_management` (or corresponding runtime name).
  * **Container Image URI:** Your ECR image URI (e.g., `<account-id>.dkr.ecr.us-east-1.amazonaws.com/bedrock-agentcore-chkpmcp:v1`).
  * **Protocol:** `MCP` (Model Context Protocol).
  * **Network Mode:** `Public` (or your chosen egress subnets/VPC config).
  * **Execution Role:** Select or input the IAM role `AgentCoreRuntimeChkpMcp` created in Phase 3.
  * **Environment Variables:**
    * `CHKP_PKG` = `@chkp/quantum-management-mcp`
    * `CHKP_SECRET_ARN` = `<secret-arn>`
    * `AWS_REGION` = `us-east-1`
* **Visual Anchor:** The Form Submit section should remain visible at the bottom of the screen before clicking **Create**.

### 2. Gateway Provisioning (`02-gateway-create.png`)
* **Console Path:** Bedrock AgentCore → Gateways → **Create gateway**
* **Key Fields & Expected Inputs:**
  * **Name:** `chkp-mcp-gw`
  * **Protocol Type:** `MCP`
  * **Service Role:** `AgentCoreGatewayRole`
* **Visual Anchor:** Capture the top-half of the gateway creation form showing the basic details and IAM service role selection clearly.

### 3. Inbound Authorization (`03-gateway-inbound-auth.png`)
* **Console Path:** Bedrock AgentCore → Gateways → Create gateway → **Inbound authorization** section
* **Key Fields & Expected Inputs:**
  * **Authorization Type:** `Custom JWT`
  * **JWKS / Discovery URL:** The Cognito OpenID Configuration endpoint (e.g., `https://cognito-idp.us-east-1.amazonaws.com/<user-pool-id>/.well-known/openid-configuration`).
  * **Allowed Clients:** The generated Cognito client ID (e.g., `<app-client-id>`).
* **Visual Anchor:** Ensure the allowed client ID and discovery URL input boxes are fully expanded and readable.

### 4. Gateway Target Registration (`04-target-mcpserver.png`)
* **Console Path:** Bedrock AgentCore → Gateways → `chkp-mcp-gw` → Targets → **Add target**
* **Key Fields & Expected Inputs:**
  * **Target Name:** `quantummanagement`
  * **Target Type:** `MCP server`
  * **Endpoint:** The URL-encoded Runtime invocations endpoint (e.g., `https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/arn%3Aaws%3Abedrock-agentcore%3Aus-east-1%3A123456789012%3Aruntime%2Fchkp-rt-uuid/invocations?qualifier=DEFAULT`).
  * **Listing Mode:** `DEFAULT`
  * **Outbound Credentials:** `Gateway IAM role`
* **Visual Anchor:** Highlight the URL-encoded runtime invocations parameter to emphasize that raw ARNs are not used directly.

### 5. Consolidated Gateway Overview (`05-gateway-targets-ready.png`)
* **Console Path:** Bedrock AgentCore → Gateways → `chkp-mcp-gw` → **Targets** tab
* **Expected State:**
  * Target names `quantummanagement`, `managementlogs`, `threatprevention`, etc. should show **Status = Ready**.
  * The tool count summary for each active target should be visible.
* **Visual Anchor:** Focus on the target grid showing multiple aggregated and healthy targets in a single unified view.

---

## Sanitation & Compliance Protocol

Before saving, exporting, or committing any file to [docs/img/console](../../../docs/img/console):

1. **Purge AWS Identifiers:**
   * Overlay color blocks, blur, or redact your **12-digit AWS Account ID** wherever it appears in ARNs, endpoint URLs, or image URIs. Refer to [docs/scenarios/go-live-and-operations.md](../../../docs/scenarios/go-live-and-operations.md) for standard placeholder conventions.
2. **Redact Cognito Internals:**
   * Obfuscate User Pool IDs (e.g., `us-east-1_xxxxxxxxx`) and Client Secrets.
3. **No Real Check Point Hostnames or IPs:**
   * Obfuscate or block out real SMS/Gateway IPs, corporate domain names, or sensitive API keys. Use `127.0.0.1` or `DUMMY` as illustrated in [docs/scenarios/local-mcp-probe.md](../../../docs/scenarios/local-mcp-probe.md).
4. **Contrast and Quality:**
   * Capture using a high-density viewport.
   * Do not cut or crop important surrounding field labels; context is key for click-ops guidance.

---

## File Structure

Captured images should land in this layout. **None are committed yet — this
guide is the shot list to capture them from a sanitized account:**

```text
docs/img/console/
├── README.md                           <-- This Guide
├── 01-runtime-create.png               <-- Target 1
├── 02-gateway-create.png               <-- Target 2
├── 03-gateway-inbound-auth.png         <-- Target 3
├── 04-target-mcpserver.png             <-- Target 4
└── 05-gateway-targets-ready.png         <-- Target 5
```

---

## Integration Pointers

For the AI guardrail side of the story, [docs/scenarios/ai-guardrail-design.md](../../../docs/scenarios/ai-guardrail-design.md) describes the enforcement points conceptually, and [docs/scenarios/ai-guardrail-runbook.md](../../../docs/scenarios/ai-guardrail-runbook.md) lists the console surfaces worth showing during a guardrail demo (the Gateways list, the Bedrock Guardrails detector categories, and the CloudWatch decision metrics). Note there is no policy-authoring console screen — policy provisioning is CLI/SDK only, so no screenshot exists for it.
