# OAuth Guardian 🛡️

> A CLI tool and npm package that audits OAuth 2.0 implementations against OWASP, NIST, and RFC specifications to identify security vulnerabilities and compliance gaps.

[![Version](https://img.shields.io/badge/version-0.1.0--alpha-blue)](https://github.com/asg5704/oauth-guardian)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue)](https://www.typescriptlang.org/)

---

## ⚠️ Development Status

**This project is in active development (Phase 1 - MVP).**

Currently implemented:
- ✅ Project foundation and TypeScript setup
- ✅ CLI framework with commander
- ✅ Type definitions for checks, config, and reports
- ✅ HTTP client with OAuth metadata discovery
- ✅ Base check class for security audits

Not yet implemented:
- ⏳ Security checks (PKCE, state, redirect URI, etc.)
- ⏳ Audit engine
- ⏳ Report generation (JSON, HTML, Markdown, etc.)
- ⏳ Configuration system

See [docs/phase-1.md](docs/phase-1.md) for detailed development progress.

---

## Table of Contents

- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [CLI Usage](#cli-usage)
  - [Programmatic Usage](#programmatic-usage)
- [Project Status](#project-status)
- [Development](#development)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)

---

## The Problem

OAuth 2.0 implementations are frequently misconfigured, leading to critical security vulnerabilities:

- **Missing PKCE** implementation (leaving mobile/SPA apps vulnerable)
- **Insecure token storage** (localStorage instead of HttpOnly cookies)
- **Weak redirect URI validation** (enabling open redirect attacks)
- **CSRF vulnerabilities** (missing state parameter)
- **Non-compliant NIST authentication assurance levels**
- **OWASP Top 10 authentication failures**

Manual security audits are time-consuming, error-prone, and don't scale across teams.

---

## The Solution

OAuth Guardian provides **automated security auditing** for OAuth 2.0 implementations:

- 🔍 **Automated Testing** - Test OAuth flows against industry standards
- 📋 **Compliance Validation** - Verify NIST 800-63B and OWASP compliance
- 📊 **Actionable Reports** - Generate detailed reports with remediation guidance
- 🔄 **CI/CD Integration** - Fail builds on critical security issues
- 🎯 **Developer-Friendly** - Clear error messages and fix suggestions

---

## Features

### Planned Security Checks

**OAuth 2.0 / RFC Compliance**
- ✅ PKCE (Proof Key for Code Exchange) implementation
- ✅ State parameter usage (CSRF protection)
- ✅ Redirect URI validation
- ✅ Secure token storage
- ✅ Token lifecycle management
- ✅ Scope validation
- ✅ Client authentication

**NIST 800-63B Compliance**
- ✅ Authentication Assurance Levels (AAL1/AAL2/AAL3)
- ✅ Session management validation
- ✅ Authenticator lifecycle checks

**OWASP Top 10**
- ✅ Broken access control
- ✅ Cryptographic failures
- ✅ Injection vulnerabilities
- ✅ Security misconfiguration
- ✅ Authentication failures

### Report Formats

- 📄 **JSON** - Machine-readable for CI/CD
- 🌐 **HTML** - Visual reports with charts
- 📝 **Markdown** - Documentation-friendly
- 📊 **CSV** - Spreadsheet analysis
- 🔍 **SARIF** - IDE integration (VS Code, etc.)
- 💻 **Terminal** - Colorized CLI output

---

## Installation

**Requirements:**
- Node.js >= 18.0.0
- npm or yarn

### Global Installation (Coming Soon)

```bash
npm install -g oauth-guardian
```

### Development Installation

```bash
# Clone the repository
git clone https://github.com/asg5704/oauth-guardian.git
cd oauth-guardian

# Install dependencies
npm install

# Build the project
npm run build

# Run the CLI
node dist/cli.js https://auth.example.com
```

---

## Usage

### CLI Usage

**Basic syntax:**
```bash
oauth-guardian <target-url> [options]
```

**Available options:**

```
Arguments:
  target                  Target URL to audit (e.g., https://auth.example.com)

Options:
  -V, --version           output the version number
  -c, --config <path>     Path to configuration file
  -f, --format <format>   Report format (json, html, markdown, csv, sarif)
                          (default: "terminal")
  -o, --output <path>     Output file path (stdout if not specified)
  --fail-on <severity>    Fail with exit code 1 on this severity level
                          (default: "critical")
  --checks <checks>       Comma-separated list of checks to run
  --skip-checks <checks>  Comma-separated list of checks to skip
  --nist-level <level>    Target NIST assurance level (AAL1, AAL2, AAL3)
  -v, --verbose           Enable verbose logging (default: false)
  --no-color              Disable colored output
  -h, --help              display help for command
```

**Examples:**

```bash
# Audit an OAuth server
oauth-guardian https://auth.example.com

# Generate JSON report
oauth-guardian https://auth.example.com --format json --output report.json

# Test with specific NIST level
oauth-guardian https://auth.example.com --nist-level AAL2

# Fail on high severity issues
oauth-guardian https://auth.example.com --fail-on high

# Run specific checks only
oauth-guardian https://auth.example.com --checks pkce,state,redirect-uri

# Verbose mode
oauth-guardian https://auth.example.com --verbose
```

### Programmatic Usage

```typescript
import { OAuthAuditor, ReportFormat } from "oauth-guardian";

const auditor = new OAuthAuditor({
  target: "https://auth.example.com",
  oauth: {
    pkce: true,
    state: true,
    redirectUri: true,
  },
  reporting: {
    format: ReportFormat.JSON,
    includeRemediation: true,
  },
});

const results = await auditor.run();

if (results.hasFailures("critical")) {
  console.error("Critical security issues found!");
  process.exit(1);
}
```

---

## Project Status

### Current Phase: Phase 1 - MVP (Week 1 Complete)

**Completed:**
- ✅ Project setup and TypeScript configuration
- ✅ Type definitions for checks, config, and reports
- ✅ HTTP client with OAuth metadata discovery
- ✅ Base check class with helper methods
- ✅ CLI framework with commander

**Next Steps (Week 2):**
- ⏳ Implement first OAuth checks (PKCE, state, redirect URI)
- ⏳ Create audit engine
- ⏳ JSON and terminal reporters

See [docs/phase-1.md](docs/phase-1.md) for detailed progress tracking.

---

## Development

### Prerequisites

- Node.js >= 18.0.0
- TypeScript 5.9+
- npm or yarn

### Setup

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Watch mode (auto-rebuild on changes)
npm run dev

# Clean build artifacts
npm run clean
```

### Project Structure

```
oauth-guardian/
├── src/
│   ├── types/           # TypeScript type definitions
│   │   ├── check.ts     # Check result types
│   │   ├── config.ts    # Configuration types
│   │   └── report.ts    # Report types
│   ├── auditor/         # Main audit engine
│   │   └── http-client.ts  # HTTP client wrapper
│   ├── checks/          # Security checks
│   │   ├── base-check.ts   # Abstract base class
│   │   ├── oauth/       # OAuth 2.0 checks
│   │   ├── nist/        # NIST 800-63B checks
│   │   └── owasp/       # OWASP checks
│   ├── reporters/       # Report generators
│   ├── config/          # Configuration system
│   ├── rules/           # Custom rules engine
│   ├── cli.ts           # CLI entry point
│   └── index.ts         # Programmatic API
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   └── __mocks__/
├── templates/           # Report templates
├── docs/                # Documentation
│   ├── README.md        # Main project docs
│   └── phase-1.md       # Development progress
└── examples/            # Usage examples
```

### Scripts

```bash
npm run build     # Compile TypeScript to dist/
npm run dev       # Watch mode compilation
npm run start     # Run the CLI
npm run clean     # Remove build artifacts
npm test          # Run tests (not yet implemented)
```

---

## Architecture

### Type System

OAuth Guardian is built with a strict TypeScript type system:

- **CheckResult**: Represents the outcome of a security check
- **CheckContext**: Provides runtime context to checks
- **AuditorConfig**: Configuration for the audit engine
- **Report**: Structured audit report with findings

### Check System

All security checks extend `BaseCheck`:

```typescript
abstract class BaseCheck {
  abstract readonly id: string;
  abstract readonly name: string;
  abstract readonly category: CheckCategory;
  abstract execute(context: CheckContext): Promise<CheckResult>;
}
```

Checks have access to helper methods:
- `pass()` - Create passing result
- `fail()` - Create failing result with severity
- `warning()` - Create warning result
- `skip()` - Skip check with reason
- `error()` - Handle check errors

### HTTP Client

The `HttpClient` class provides:
- OAuth metadata discovery (`.well-known` endpoints)
- Request/response logging
- Timeout handling
- Safe JSON parsing
- URL accessibility checking

---

## Contributing

Contributions are welcome! This project is in active development.

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-check`)
3. **Make your changes**
4. **Test your changes** (`npm run build && node dist/cli.js <url>`)
5. **Commit your changes** (`git commit -m 'Add amazing security check'`)
6. **Push to the branch** (`git push origin feature/amazing-check`)
7. **Open a Pull Request**

### Contribution Ideas

- 🔍 **Implement security checks** (see `docs/README.md` for planned checks)
- 📊 **Add report formats** (PDF, email, Slack notifications)
- 🧪 **Write tests** (unit tests, integration tests)
- 📝 **Improve documentation**
- 🐛 **Fix bugs** (check GitHub issues)
- 🎨 **Enhance CLI UX** (better output, progress indicators)

### Code Style

- Use TypeScript strict mode
- Follow existing code patterns
- Add JSDoc comments for public APIs
- Include tests for new features
- Update documentation

### Questions?

- Open an issue on GitHub
- Check the [project documentation](docs/README.md)

---

## Roadmap

### Phase 1: MVP (Weeks 1-3) - In Progress

- [x] **Week 1**: Foundation & Project Setup ✅
- [ ] **Week 2**: Core OAuth Checks & Basic Reporting
- [ ] **Week 3**: Configuration System & HTML Reports

### Phase 2: NIST Compliance (Weeks 4-5)

- [ ] Authentication Assurance Level checks
- [ ] Session management validation
- [ ] Enhanced reporting with compliance scorecards

### Phase 3: Advanced Features (Weeks 6-8)

- [ ] Token lifecycle checks
- [ ] Custom rules engine
- [ ] Additional report formats (CSV, Markdown, SARIF)

### Phase 4: Testing & Documentation (Weeks 9-10)

- [ ] 80%+ test coverage
- [ ] Comprehensive documentation
- [ ] CI/CD pipeline

### Phase 5: Launch (Weeks 11-12)

- [ ] npm package publishing
- [ ] GitHub repository setup
- [ ] Public announcement

See [docs/README.md](docs/README.md) for the complete implementation roadmap.

---

## Real-World Expertise

This project is built by [Alexander Garcia](https://github.com/asg5704), who:

- Implemented OAuth 2.0 at massive scale (200M+ authentications at VA.gov)
- Hand-wrote custom OAuth 2.0 SDK with PKCE support
- Built authentication infrastructure serving millions of Veterans
- Deep understanding of security constraints in government systems

---

## Resources

### OAuth 2.0 Specifications

- [RFC 6749 - OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 8252 - OAuth 2.0 for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

### NIST Guidelines

- [NIST 800-63B - Digital Identity Guidelines (Authentication)](https://pages.nist.gov/800-63-3/sp800-63b.html)

### OWASP Resources

- [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP OAuth 2.0 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)

---

## License

MIT License - See [LICENSE](LICENSE) file for details.

---

## Contact

**Maintainer**: Alexander Garcia

- GitHub: [@asg5704](https://github.com/asg5704)
- Email: asg5704@gmail.com

**Repository**: [https://github.com/asg5704/oauth-guardian](https://github.com/asg5704/oauth-guardian)

**Issues**: [https://github.com/asg5704/oauth-guardian/issues](https://github.com/asg5704/oauth-guardian/issues)

---

<div align="center">

**Built with ❤️ for the security community**

[Report Bug](https://github.com/asg5704/oauth-guardian/issues) · [Request Feature](https://github.com/asg5704/oauth-guardian/issues) · [Documentation](docs/README.md)

</div>
