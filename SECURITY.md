# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 12.x    | :white_check_mark: |
| 11.x    | :white_check_mark: |
| < 11.0  | :x:                |

## Reporting a Vulnerability

Please report security vulnerabilities through the official GitHub Security Advisories:
https://github.com/NationalSecurityAgency/ghidra/security/advisories

For more information about Ghidra security, see the [Security Advisories][security] page.

## Known CVE Remediation Status

This document tracks the remediation status of known CVEs that have affected or could potentially affect Ghidra.

### Addressed CVEs

| CVE ID | Description | Status | Version Fixed | Notes |
|--------|-------------|--------|---------------|-------|
| CVE-2023-22671 | Command injection via `eval` in launch.sh | Fixed | 10.2.3 | Removed `eval` usage from launch scripts |
| CVE-2024-31083 | X.org server regression causing crashes | Documented | 12.0 | Requires xwayland 23.2.6+ or xorg-server 21.1.13+ |
| CVE-2021-44228 | Apache Log4j2 Remote Code Execution (Log4Shell) | Mitigated | 10.1.2+ | Using Log4j 2.17.1 |
| CVE-2021-45046 | Apache Log4j2 Deserialization vulnerability | Mitigated | 10.1.2+ | Using Log4j 2.17.1 |

### Current Dependency Security Status

Ghidra 12.0 uses the following security-relevant dependencies:

| Dependency | Version | CVE Status |
|------------|---------|------------|
| Apache Log4j | 2.17.1 | Patched for CVE-2021-44228, CVE-2021-45046 |
| Google Guava | 32.1.3-jre | Current secure version |
| Bouncy Castle | 1.80 | Current secure version |
| Apache Commons Compress | 1.27.1 | Current secure version |
| Apache Commons IO | 2.19.0 | Current secure version |

### Java Runtime Requirements

Ghidra 12.0 requires JDK 21 or later. The following historical Java CVEs from the CISA Known Exploited Vulnerabilities catalog do NOT affect Ghidra when running on JDK 21:

- CVE-2016-3427, CVE-2015-4902, CVE-2015-2590 (Java SE vulnerabilities in older versions)
- CVE-2013-2423, CVE-2013-2465, CVE-2013-0431, CVE-2013-0422 (JRE vulnerabilities in older versions)
- CVE-2012-5076, CVE-2012-4681, CVE-2012-1723, CVE-2012-0507 (Java SE vulnerabilities in older versions)
- CVE-2011-3544, CVE-2010-0840 (JRE vulnerabilities in older versions)

**Recommendation:** Always use the latest LTS version of JDK 21 or later to ensure you have the latest security patches.

### Platform-Specific Security Notes

#### X.org/XWayland (Linux)

CVE-2024-31083 introduced a regression in X.org software that can cause Ghidra to crash. If you experience crashes (particularly causing a full logout), ensure your X server is updated:

- xwayland: 23.2.6 or later
- xorg-server: 21.1.13 or later

See [WhatsNew.md](Ghidra/Configurations/Public_Release/src/global/docs/WhatsNew.md) for details.

## Security Best Practices

When using Ghidra for malware analysis or reverse engineering:

1. **Isolate your environment**: Run Ghidra in a sandboxed or virtualized environment when analyzing untrusted binaries
2. **Keep dependencies updated**: Regularly update your JDK and system libraries
3. **Review scripts before running**: Be cautious when running third-party Ghidra scripts
4. **Use the latest version**: Always use the latest stable release of Ghidra

## CISA KEV Compliance

This security documentation was created as part of a comprehensive CVE remediation effort based on the CISA Known Exploited Vulnerabilities (KEV) catalog. For federal systems, ensure compliance with BOD 22-01 requirements for vulnerability remediation.

## References

- [Ghidra Security Advisories][security]
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Apache Log4j Security](https://logging.apache.org/log4j/2.x/security.html)

[security]: https://github.com/NationalSecurityAgency/ghidra/security/advisories
