# Vulnerable MCP Server - TypeScript/Cloudflare Workers Implementation

This is a TypeScript port of the Python vulnerable MCP server, designed to run on Cloudflare Workers.

## Overview

This implementation converts all 31 tools from the Python version to TypeScript, with the following considerations:

- **Mocked Tools**: Tools that require system access (nmap, PowerShell, file I/O) return simulated responses
- **Real API Calls**: Tools using external APIs (Shodan, VirusTotal, ipify) work via the Fetch API
- **HTTP Transport Only**: Uses simple HTTP JSON-RPC endpoints (stdio not available in Workers)
- **Same Vulnerabilities**: All intentional security vulnerabilities are preserved for educational purposes

## Project Structure

```
.
├── src/
│   └── index.ts          # Single file with all tools and MCP server logic (~2200 lines)
├── package.json          # Dependencies and scripts
├── tsconfig.json         # TypeScript configuration
├── wrangler.toml         # Cloudflare Workers configuration
├── .env.example          # Environment variables template
└── README_TYPESCRIPT.md  # This file
```

## Setup

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment Variables (Optional)

For tools that use external APIs:

```bash
# Copy the example file
cp .env.example .env

# Edit .env and add your API keys
# SHODAN_API_KEY=your_key_here
# VT_API_KEY=your_key_here
```

For local development, you can use `.env`. For production deployment, use Wrangler secrets (see Deployment section).

## Development

### Run Locally

```bash
npm run dev
```

This starts the Wrangler development server at `http://localhost:8787`.

### Test the Server

**Get Server Info:**
```bash
curl http://localhost:8787
```

**List Available Tools:**
```bash
curl -X POST http://localhost:8787 \
  -H "Content-Type: application/json" \
  -d '{"method": "tools/list", "id": 1}'
```

**Call a Tool:**
```bash
# Example: whats_my_ip
curl -X POST http://localhost:8787 \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/call",
    "params": {
      "name": "whats_my_ip",
      "arguments": {}
    },
    "id": 2
  }'

# Example: ping
curl -X POST http://localhost:8787 \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/call",
    "params": {
      "name": "ping",
      "arguments": {"ip": "8.8.8.8"}
    },
    "id": 3
  }'
```

**List Resources:**
```bash
curl -X POST http://localhost:8787 \
  -H "Content-Type: application/json" \
  -d '{"method": "resources/list", "id": 4}'
```

**Read a Resource:**
```bash
curl -X POST http://localhost:8787 \
  -H "Content-Type: application/json" \
  -d '{
    "method": "resources/read",
    "params": {"uri": "config://settings"},
    "id": 5
  }'
```

## Deployment to Cloudflare Workers

### 1. Login to Cloudflare

```bash
npx wrangler login
```

### 2. Configure Secrets (for API keys)

```bash
# Set Shodan API key
npx wrangler secret put SHODAN_API_KEY
# Enter your key when prompted

# Set VirusTotal API key (if needed)
npx wrangler secret put VT_API_KEY
# Enter your key when prompted
```

### 3. Deploy

```bash
npm run deploy
```

This will deploy your worker to Cloudflare. You'll get a URL like:
`https://vuln-mcp-worker.<your-subdomain>.workers.dev`

### 4. Test Deployed Worker

```bash
# Replace with your actual worker URL
curl https://vuln-mcp-worker.<your-subdomain>.workers.dev
```

## MCP Protocol Endpoints

The server implements the following MCP JSON-RPC methods:

| Method | Description |
|--------|-------------|
| `initialize` | Initialize MCP connection |
| `tools/list` | List all available tools |
| `tools/call` | Execute a specific tool |
| `resources/list` | List available resources |
| `resources/read` | Read a specific resource |

## Tools Inventory

### Basic Tools (3)
1. `scan_running_hashes` - Mock PowerShell/VirusTotal scanning
2. `example_usage` - Usage examples
3. `send_empty_data` - Returns null (empty response testing)

### Network Tools (5)
4. `scan_ip_with_nmap` - Mock nmap scan
5. `whats_my_ip` - Real IP lookup via ipify.org
6. `ping` - Mock ICMP ping
7. `scan_with_shodan` - Real Shodan API integration
8. `ip_analyzer_plus` - Malicious IP analysis with command injection

### Poisoning/Injection Tools (4)
9. `get_ip_traffic_details` - Tool poisoning (requests file content)
10. `get_hostname_tags` - Tool shadowing vulnerability
11. `send_email` - Hidden prompt injection in response
12. `get_user_details` - Base64 encoded instructions

### E-commerce Vulnerability Tools (9)
13. `fetch_supplier_catalog` - SSRF vulnerability
14. `price_optimizer` - Hidden exfiltration instructions
15. `process_refund` - Command injection
16. `get_order_invoice` - Path traversal
17. `validate_webhook_signature` - Insecure deserialization (mocked)
18. `generate_shipping_label` - OAuth/URL execution
19. `marketing_etl_import` - Credential exposure
20. `system_healthcheck` - Information disclosure
21. `get_customer_information` - Customer data handling

### Content/Marketing Tools (5)
22. `harvest_supplier_reviews` - Indirect prompt injection
23. `summarize_support_tickets` - Indirect prompt injection
24. `import_product_descriptions` - Indirect prompt injection
25. `generate_seo_brief` - Direct prompt poisoning
26. `curate_ugc_for_homepage` - UGC-based injection

### Payment Vulnerability Tools (4)
27. `generate_promo_page` - Prompt injection with exfil
28. `process_card_payment` - PCI/PII exposure
29. `save_card_for_reuse` - Insecure card storage
30. `refund_to_card` - Command injection + nested JSON

### Customer Tools (1)
31. `get_customer_info_detailed` - Detailed customer data

## Resources

1. `file://documents/{name}` - Mock document reading
2. `config://settings` - Application configuration

## Key Differences from Python Version

### Mocked Tools (Platform Limitations)

The following tools are **simulated** because Cloudflare Workers doesn't support:

- **System Commands**: `process_refund`, `refund_to_card`, `generate_shipping_label`
- **File I/O**: `get_order_invoice`, `process_card_payment`, `save_card_for_reuse`, `generate_promo_page`
- **Binaries**: `scan_running_hashes` (PowerShell), `scan_ip_with_nmap` (nmap)
- **ICMP**: `ping`
- **Deserialization**: `validate_webhook_signature` (pickle/yaml)

These tools return realistic mock responses with comments explaining the limitation.

### Real API Calls (Working)

The following tools make **actual HTTP requests**:

- `whats_my_ip` - ipify.org API
- `scan_with_shodan` - Shodan API (requires API key)
- `fetch_supplier_catalog` - Any URL (SSRF demo)
- `harvest_supplier_reviews` - Any URL
- `summarize_support_tickets` - Any URL
- `import_product_descriptions` - Any URL
- `curate_ugc_for_homepage` - Any URL

### Architecture Changes

1. **Single File**: All code in `src/index.ts` (matching Python's structure)
2. **HTTP Only**: No stdio or SSE transport (only HTTP JSON-RPC)
3. **No MCP SDK Transport**: Direct HTTP handler implementation
4. **Fetch API**: All network requests use standard Fetch API

## Security Warnings

⚠️ **Educational Purpose Only** ⚠️

This server intentionally contains multiple security vulnerabilities:

- **Command Injection**: Tools that simulate command execution
- **Path Traversal**: Unsafe path handling
- **SSRF**: Fetching arbitrary URLs
- **Prompt Injection**: Hidden instructions in tool descriptions and responses
- **PCI/PII Exposure**: Logging sensitive payment data
- **Information Disclosure**: Exposing system information
- **Credential Exposure**: Hardcoded secrets and env dumps

**DO NOT** deploy this in production or use it for any real application. It is designed exclusively for:

- Security research
- Vulnerability testing
- Educational demonstrations
- LLM security testing

## Troubleshooting

### TypeScript Errors

```bash
# Check for type errors
npx tsc --noEmit
```

### Wrangler Issues

```bash
# Clear Wrangler cache
rm -rf ~/.wrangler

# Update Wrangler
npm install --save-dev wrangler@latest
```

### API Keys Not Working

Make sure secrets are set correctly:

```bash
# List secrets
npx wrangler secret list

# Delete and re-add if needed
npx wrangler secret delete SHODAN_API_KEY
npx wrangler secret put SHODAN_API_KEY
```

## Development Commands

```bash
# Install dependencies
npm install

# Run local dev server
npm run dev

# Deploy to Cloudflare
npm run deploy

# View live logs
npm run tail

# Type check
npx tsc --noEmit
```

## License

This is a security research/educational project. Use at your own risk.

## Original Python Version

See [vul_mcp.py](./vul_mcp.py) for the original Python implementation.
