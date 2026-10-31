## Summary of Changes

Describe what this Pull Request adds, fixes, or improves in **LiveTrack-Pro**.

## Related Issue

Closes #

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Security hardening (authentication, encryption, IDOR, rate limiting)
- [ ] Cross-platform client update (Android Kotlin, iOS PWA, Termux CLI, Windows, Linux, macOS)
- [ ] Documentation or CI/CD improvement

## Mandatory Ethical & Security Verification Checklist

- [ ] **Zero Covert Recording**: I confirm this PR introduces no remote or background microphone activation without explicit physical user consent and a persistent OS/UI notification.
- [ ] **IDOR & Ownership Guards**: All new or modified endpoints verify device ownership.
- [ ] **No Hardcoded Secrets**: No API keys, JWT secrets, or encryption keys are hardcoded.
- [ ] **Automated Tests Pass**: npm test and npm run migrate pass locally with 0 errors.
- [ ] **Dashboard Typecheck Passes**: cd dashboard && npm run build completes with 0 TypeScript errors.
