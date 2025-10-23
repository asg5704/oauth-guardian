# OAuth Guardian - Product Roadmap

> **Last Updated**: 2025-10-23
> **Current Phase**: Phase 2 Complete ✅
> **Next Milestone**: Phase 2.5 - Local Scanning Mode (or Phase 3)

---

## Vision

OAuth Guardian will become the **industry-standard tool** for OAuth 2.0 security auditing, supporting both remote server analysis and local code repository scanning across multiple programming languages.

### Core Principles

1. **Security First**: Catch vulnerabilities before they reach production
2. **Developer Experience**: Clear, actionable feedback with fix suggestions
3. **Standards Compliance**: Validate against OWASP, NIST, and RFC specifications
4. **CI/CD Native**: Seamless integration into development workflows
5. **Multi-Mode Operation**: Work with live servers OR local codebases

---

## Timeline Overview

| Phase | Timeline | Status | Focus |
|-------|----------|--------|-------|
| **Phase 1** | Weeks 1-3 | ✅ Complete | MVP - OAuth 2.0 Core Checks |
| **Phase 2** | Weeks 4-5 | ✅ Complete | NIST 800-63B Compliance + Enhanced Reporting |
| **Phase 2.5** | Week 6 | ⏳ Up Next | Local Scanning Mode (Optional) |
| **Phase 3** | Weeks 7-9 | ⏳ Planned | OWASP + Advanced Features |
| **Phase 4** | Weeks 10-11 | ⏳ Planned | Testing & Documentation |
| **Phase 5** | Week 12 | ⏳ Planned | Public Launch |

---

## Phase 1: MVP Foundation ✅

**Status**: Complete
**Timeline**: Weeks 1-3 (Completed)
**Delivered**: Full OAuth 2.0 audit system with 4 checks and 3 report formats

### Achievements

- ✅ **Week 1**: Foundation & Type System
  - TypeScript strict mode configuration
  - Type definitions (CheckResult, CheckContext, Report)
  - CLI framework with Commander.js
  - HTTP client with OAuth metadata discovery
  - Base check class with helper methods

- ✅ **Week 2**: Core Security Checks
  - PKCE (Proof Key for Code Exchange) validation
  - State parameter enforcement (CSRF protection)
  - Redirect URI validation
  - Token storage security checks
  - Audit engine with check registration
  - JSON and Terminal reporters

- ✅ **Week 3**: Configuration & Reporting
  - YAML configuration system with Zod validation
  - HTML report generation with Handlebars
  - Category-based check filtering
  - Configuration file override logic
  - 118 unit tests with 75% coverage

### Metrics

- **Checks**: 4 OAuth 2.0 security checks
- **Report Formats**: 3 (JSON, HTML, Terminal)
- **Tests**: 118 passing
- **Coverage**: ~75%
- **Lines of Code**: ~3,500 source + 4,500 tests

---

## Phase 2: NIST 800-63B Compliance ✅

**Status**: Complete
**Timeline**: Weeks 4-5 (Completed 2025-10-23)
**Delivered**: 6 NIST compliance checks, AAL validation, session management, enhanced reporting with visual analytics

### Week 4: AAL Checks & Session Management ✅

- [x] **AAL Detection** - Discover supported authentication assurance levels
- [x] **AAL1 Compliance** - Single/multi-factor authentication validation
- [x] **AAL2 Compliance** - Multi-factor with cryptographic authenticators
- [x] **AAL3 Compliance** - Hardware-based cryptographic authentication
- [x] **Session Management** - Timeout, binding, reauthentication, termination
- [x] **Authenticator Lifecycle** - Registration, binding, expiration, revocation
- [x] **Base NIST Check Class** - ACR/AMR analysis, AAL detection helpers
- [x] **36 additional unit tests** for NIST base class
- [x] **39 additional unit tests** for session/authenticator checks

### Week 5: Enhanced Reporting ✅

- [x] **NIST Compliance Scorecards**
  - [x] AAL compliance status per level (AAL1, AAL2, AAL3)
  - [x] Per-level metrics (passed, failed, warnings)
  - [x] Overall NIST compliance score
  - [x] Highest AAL achieved display
  - [x] Category-based grouping (OAuth, NIST, OWASP)

- [x] **Visual Charts & Analytics**
  - [x] Doughnut chart: Pass/Fail/Warning/Skipped distribution with percentages
  - [x] Bar chart: Findings by severity level (Critical → Info)
  - [x] ~~Radar chart: Compliance across categories~~ (removed as redundant)
  - [x] Chart.js 4.4.0 integration via CDN (no npm dependency)
  - [x] Interactive tooltips and responsive design

- [x] **Report Enhancements**
  - [x] Print-friendly HTML styles (@media print)
  - [x] Collapsible remediation sections (HTML5 `<details>` tags)
  - [x] Responsive chart layouts with CSS Grid
  - [x] NIST AAL compliance dashboard
  - ❌ Interactive filtering/sorting (deferred to Phase 3)
  - ❌ Export to PDF functionality (deferred to Phase 3)
  - ❌ Dark mode support (deferred to Phase 3)

### Metrics (Final)

- **Checks**: 10 total (4 OAuth + 6 NIST)
- **Report Formats**: 3 enhanced (JSON with NIST metrics, HTML with charts, Terminal with categories)
- **Tests**: 349 (320 passing, 29 need adjustment)
- **Coverage**: ~77%
- **Lines of Code**: ~8,500+ source + 10,500+ tests
- **HTML Report Size**: 56KB with full analytics

---

## Phase 2.5: Local Scanning Mode 🎯

**Status**: Planned
**Timeline**: Week 6 (Post-Phase 2, Pre-Phase 3)
**Goal**: Enable scanning of local code repositories without running OAuth server

### Vision: Dual-Mode Architecture

OAuth Guardian will support **two complementary modes**:

#### Mode 1: Remote Discovery (Current)
```bash
# Audit a live OAuth provider
oauth-guardian https://accounts.google.com
```

**Strengths**:
- ✅ Most accurate - tests actual server behavior
- ✅ Validates runtime configuration
- ✅ Discovers real-world metadata
- ✅ Works with any OAuth provider

**Limitations**:
- ❌ Requires running server
- ❌ Can't scan pre-deployment
- ❌ Limited to discoverable metadata

#### Mode 2: Local Repository Scan (New)
```bash
# Scan local codebase
oauth-guardian scan ./my-oauth-server
oauth-guardian scan . --language nodejs
oauth-guardian scan . --metadata .well-known/openid-configuration
```

**Strengths**:
- ✅ Pre-deployment security scanning
- ✅ Works during development
- ✅ No server required
- ✅ CI/CD integration
- ✅ Catches config issues early

**Use Cases**:
- Developer writes OAuth implementation → scans locally before committing
- CI pipeline clones repo → runs scan → fails build if issues found
- Security audit of legacy codebase → no need to deploy server
- Configuration validation → check metadata files offline

### Implementation Phases

#### Phase 2.5.1: Metadata File Support (Week 6, Days 1-2)

**Goal**: Support scanning with local metadata files

```bash
oauth-guardian scan . --metadata ./oauth-metadata.json
oauth-guardian scan . --metadata ./.well-known/openid-configuration
```

**Implementation**:
- [ ] Create `ConfigurationSource` abstraction layer
- [ ] Implement `LocalMetadataSource` class
- [ ] Add `scan` command to CLI
- [ ] Modify checks to work with local metadata
- [ ] Update documentation with examples
- [ ] Write 10-15 integration tests

**Deliverable**: Can scan using local metadata files (JSON/YAML)

**Effort**: 1-2 days

#### Phase 2.5.2: Node.js Auto-Detection (Week 6, Days 3-4)

**Goal**: Automatically extract OAuth config from Node.js/TypeScript codebases

```bash
oauth-guardian scan . --auto-detect
```

**Detection Strategy**:
1. **Package.json Analysis**
   - Scan dependencies for OAuth libraries:
     - `passport`, `passport-oauth2`
     - `express-oauth2-server`
     - `@node-oauth/oauth2-server`
     - `openid-client`

2. **Environment File Parsing**
   - `.env`, `.env.local`, `.env.production`
   - Extract: `CLIENT_ID`, `CLIENT_SECRET`, `TOKEN_ENDPOINT`, etc.

3. **Config File Detection**
   - `config/default.json`, `config/production.json`
   - `oauth.config.js`, `auth.config.ts`

4. **Code Pattern Matching**
   - AST parsing with `@babel/parser`
   - Find OAuth configuration objects
   - Extract endpoint URLs, PKCE settings, etc.

**Implementation**:
- [ ] Install AST parsing dependencies (`@babel/parser`, `@babel/traverse`)
- [ ] Create `NodeJsParser` class
- [ ] Implement `.env` file parser
- [ ] Implement config file discovery
- [ ] Add code pattern matching
- [ ] Write 15-20 unit tests
- [ ] Test with real Node.js OAuth projects

**Example Detection**:
```typescript
// Parser finds this in user's code:
const oauthConfig = {
  authorizationURL: 'https://provider.com/authorize',
  tokenURL: 'https://provider.com/token',
  pkce: true,
  state: true,
  redirectURIs: ['http://localhost:3000/callback']
};

// Converts to internal metadata format
const metadata = {
  authorization_endpoint: 'https://provider.com/authorize',
  token_endpoint: 'https://provider.com/token',
  code_challenge_methods_supported: ['S256'],
  // ... etc
};
```

**Deliverable**: Auto-detect OAuth config in Node.js/TypeScript projects

**Effort**: 2-3 days

#### Phase 2.5.3: Multi-Language Support (Future - Post-Week 6)

**Goal**: Support Python, Java, Go, Ruby, PHP

**Python** (Django, Flask):
```bash
oauth-guardian scan . --language python
```
- Detect: `authlib`, `django-oauth-toolkit`, `flask-oauthlib`
- Parse: `settings.py`, `config.py`, `.env`

**Java/Spring**:
```bash
oauth-guardian scan . --language java
```
- Detect: `spring-security-oauth2`, `spring-boot-starter-oauth2-client`
- Parse: `application.yml`, `application.properties`

**Go**:
```bash
oauth-guardian scan . --language go
```
- Detect: `golang.org/x/oauth2`, `github.com/coreos/go-oidc`
- Parse: YAML config files, environment variables

**Ruby** (Rails):
- Detect: `omniauth`, `doorkeeper`
- Parse: `config/initializers/oauth.rb`

**PHP** (Laravel):
- Detect: `league/oauth2-client`, `laravel/passport`
- Parse: `config/services.php`, `.env`

**Effort**: 1-2 weeks (can be done incrementally)

### Configuration Schema Extension

Add YAML config options for local scanning:

```yaml
# oauth-guardian.config.yml
mode: local  # or 'remote'

local:
  path: ./src
  language: nodejs  # auto-detect if not specified

  # Optional: specify metadata file directly
  metadata: ./.well-known/openid-configuration

  # Optional: additional paths to scan
  include:
    - ./config
    - ./lib/auth

  # Optional: paths to exclude
  exclude:
    - ./node_modules
    - ./dist
    - ./test
```

### CI/CD Integration Examples

**GitHub Actions**:
```yaml
name: OAuth Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npm install -g oauth-guardian
      - run: oauth-guardian scan . --fail-on high
```

**GitLab CI**:
```yaml
oauth-scan:
  script:
    - npm install -g oauth-guardian
    - oauth-guardian scan . --format json --output oauth-report.json
  artifacts:
    reports:
      junit: oauth-report.json
```

### Success Metrics

- [ ] Can scan 3+ major OAuth frameworks (Express, Django, Spring)
- [ ] Detects 80%+ of OAuth config in test repositories
- [ ] Integration test suite with real-world projects
- [ ] Documentation with language-specific examples
- [ ] CI/CD templates for GitHub/GitLab

---

## Phase 3: OWASP & Advanced Features ⏳

**Status**: Planned
**Timeline**: Weeks 7-9
**Goal**: Add OWASP Top 10 checks and advanced auditing capabilities

### Week 7: OWASP Top 10 Integration

- [ ] **Broken Access Control Checks**
  - Insufficient scope validation
  - Token privilege escalation
  - Insecure direct object references in OAuth flows

- [ ] **Cryptographic Failures**
  - Weak token signing algorithms (HS256 vs RS256)
  - Missing token encryption
  - Insecure random number generation (state, PKCE)

- [ ] **Injection Vulnerabilities**
  - OAuth parameter injection
  - Open redirect vulnerabilities
  - SSRF via metadata URLs

- [ ] **Security Misconfiguration**
  - Permissive CORS policies
  - Exposed client secrets
  - Debug mode enabled in production

### Week 8: Token Lifecycle Management

- [ ] **Token Expiration Validation**
  - Access token lifetime checks
  - Refresh token rotation
  - Token revocation support

- [ ] **Token Storage Security**
  - Secure storage mechanisms (HttpOnly cookies)
  - Token leakage prevention
  - Browser storage audit (localStorage vs sessionStorage)

### Week 9: Custom Rules Engine

- [ ] **Rule Definition Language**
  - YAML-based custom rule definitions
  - Pattern matching DSL
  - Severity and remediation customization

- [ ] **Rule Categories**
  - Organization-specific policies
  - Industry compliance rules
  - Custom security patterns

Example custom rule:
```yaml
rules:
  - id: custom-token-lifetime
    name: "Enforce 15-minute access token lifetime"
    category: custom
    severity: high
    condition:
      metadata.access_token_ttl > 900
    message: "Access tokens must expire within 15 minutes"
    remediation: "Set access_token_ttl to 900 seconds or less"
```

### Additional Report Formats

- [ ] **CSV Export** - Spreadsheet analysis
- [ ] **Markdown** - Documentation integration
- [ ] **SARIF** - IDE integration (VS Code, IntelliJ)
- [ ] **JUnit XML** - CI/CD test reporting
- [ ] **Slack/Email** - Automated notifications

---

## Phase 4: Testing & Polish ⏳

**Status**: Planned
**Timeline**: Weeks 10-11
**Goal**: Production-ready quality and comprehensive documentation

### Week 10: Testing & Quality

- [ ] **Test Coverage Goals**
  - 85%+ statement coverage
  - 80%+ branch coverage
  - 100% coverage for critical security checks

- [ ] **Integration Testing**
  - Test against 10+ real OAuth providers
  - Multi-language repository scanning
  - End-to-end CLI workflows

- [ ] **Performance Optimization**
  - Parallel check execution
  - Caching for repeated scans
  - Reduced memory footprint
  - Bundle size optimization

- [ ] **Security Hardening**
  - Input validation and sanitization
  - Dependency vulnerability scanning
  - SSRF protection in HTTP client

### Week 11: Documentation & Polish

- [ ] **Comprehensive Documentation**
  - API reference documentation
  - Check catalog with examples
  - Integration guides (CI/CD)
  - Troubleshooting guide
  - Video tutorials

- [ ] **Developer Experience**
  - Improved error messages
  - Progress indicators for long scans
  - Auto-update notifications
  - Shell completions (bash, zsh, fish)

- [ ] **Accessibility**
  - Screen reader support in terminal
  - Color-blind friendly output
  - Configurable verbosity levels

---

## Phase 5: Public Launch ⏳

**Status**: Planned
**Timeline**: Week 12
**Goal**: Release OAuth Guardian to the security community

### Week 12: Launch Preparation

- [ ] **npm Package Publishing**
  - Semantic versioning setup
  - Automated release pipeline
  - Package size optimization
  - README badges and shields

- [ ] **Repository Setup**
  - GitHub repository public release
  - Issue templates
  - Pull request templates
  - Contributing guidelines
  - Code of conduct

- [ ] **Marketing & Outreach**
  - Blog post announcement
  - Twitter/LinkedIn posts
  - Reddit r/netsec, r/programming posts
  - Hacker News submission
  - Dev.to article

- [ ] **Documentation Site**
  - Static site with Docusaurus or VitePress
  - Interactive examples
  - Live demo playground
  - Check catalog browser

- [ ] **Community Building**
  - Discord/Slack community
  - GitHub Discussions
  - Monthly office hours
  - Contribution bounties

---

## Success Metrics

### Phase 1 Metrics ✅
- ✅ 4 OAuth checks implemented
- ✅ 3 report formats
- ✅ 118 tests passing
- ✅ 75% code coverage
- ✅ Clean TypeScript compilation

### Phase 2 Target Metrics (Week 5) ✅
- ✅ 10 total security checks (4 OAuth + 6 NIST)
- ✅ 6 NIST AAL checks (Detection, AAL1, AAL2, AAL3, Session, Authenticators)
- ✅ 3 enhanced report formats (JSON, HTML with charts, Terminal)
- ✅ 320 tests passing (349 total, 29 need adjustment)
- 🟡 77% code coverage (close to 80% target)

### Phase 2.5 Target Metrics (Week 6)
- 🎯 Dual-mode architecture implemented
- 🎯 Node.js auto-detection working
- 🎯 CI/CD integration examples
- 🎯 Documentation for local scanning

### Phase 3 Target Metrics (Week 9)
- 🎯 15+ security checks
- 🎯 5+ OWASP checks
- 🎯 Custom rules engine
- 🎯 7 report formats
- 🎯 500+ tests

### Phase 5 Launch Metrics (Week 12)
- 🎯 85% code coverage
- 🎯 10+ real-world providers tested
- 🎯 Documentation site live
- 🎯 npm package published
- 🎯 100+ GitHub stars in first month

---

## Long-Term Vision (6-12 months)

### Advanced Features

- **Cloud Provider Integration**
  - AWS Cognito validation
  - Azure AD B2C checks
  - Google Cloud Identity Platform
  - Okta custom checks

- **Runtime Monitoring**
  - Prometheus metrics export
  - Real-time OAuth flow monitoring
  - Anomaly detection
  - Security event correlation

- **Enterprise Features**
  - Team collaboration dashboards
  - Historical trend analysis
  - Compliance reporting (SOC 2, GDPR)
  - Policy management interface

- **IDE Extensions**
  - VS Code extension
  - IntelliJ IDEA plugin
  - Real-time code analysis
  - Inline security suggestions

### Community Growth

- 1,000+ GitHub stars
- 50+ contributors
- Monthly releases
- Conference talks (OWASP, DevSecOps)
- Security research publications

---

## Questions & Feedback

Have ideas for the roadmap? Open an issue or discussion on GitHub!

- 💡 **Feature Requests**: [GitHub Issues](https://github.com/asg5704/oauth-guardian/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/asg5704/oauth-guardian/discussions)
- 📧 **Email**: asg5704@gmail.com

---

**Last Updated**: 2025-10-21
**Maintained by**: [@asg5704](https://github.com/asg5704)
