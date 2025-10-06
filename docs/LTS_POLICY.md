# Long-Term Support (LTS) Policy for QASP v1.0

## Overview
QASP v1.0 LTS branch (`lts/v1`) provides stable maintenance and security updates for production deployments requiring extended support beyond the main development branch.

## Versioning Strategy
- **LTS Version**: v1.x.y where x increments for feature backports and y for patches/security fixes
- **Backport Criteria**: Only critical bug fixes and security patches are backported to LTS from main development branches
- **Compatibility**: LTS maintains API compatibility within major version (1.x)

## Patch Release Cadence
- **Quarterly Releases**: QASP LTS releases occur every 3 months on the 15th of February, May, August, and November
- **Exceptional Releases**: Security vulnerabilities (CVE) trigger immediate out-of-cadence patches
- **Advance Notice**: LTS release schedule announced 4 weeks in advance via repository issues and changelog

## Security Update Workflow
1. **CVE Monitoring**: Automated weekly scans using Trivy vulnerability database and Dependabot alerts
2. **Triage Process**:
   - Security team reviews CVEs and determines impact on QASP components
   - Prioritization: Critical (fix in <7 days), High (<30 days), Medium (<90 days)
3. **Patch Development**:
   - Fixes developed on feature branches targeting `lts/v1`
   - Automated tests and formal verification required
4. **Release Process**:
   - Patches create new LTS version (1.x.y+1)
   - Signed release artifacts published to GitHub Releases
   - Security advisory posted if CVSS >= 7.0

## Maintenance Timeline
- **Support Period**: 3 years from v1.0 release date
- **End of Life**: After 3 years, only critical security patches considered case-by-case

## Backport Process
- Hotfixes merged to main development branches must include backport labels (`backport/lts-v1`)
- Automated tooling (`tools/generate_patch.py`) assists in creating backport PRs
- Review requires approval from at least 2 maintainers

## Automation
- Weekly security scans run via GitHub Actions
- Vulnerability reports auto-generated in `reports/lts_security_YYYY_MM_DD.md`
- Enable issues creation from Dependabot PRs for known security updates

## Contact
For LTS-specific issues, create issues with label `lts/v1` and CC `security-team@qasp.org`
