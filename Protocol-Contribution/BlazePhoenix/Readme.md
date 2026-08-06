# BlazePhoenix Protocol

This directory documents my independent security research, responsible disclosures and accepted protocol improvements submitted to the BlazePhoenix ecosystem. All findings included here were publicly disclosed after validation and remediation by the protocol team.

---

# 📊 Contribution Summary

- **Total Valid Findings:** 7  
- **Severity Breakdown:**
  - 🟥 High: 2  
  - 🟧 Medium: 3  
  - 🟨 Low / Informational: 2  

---

# 🚀 Findings Overview

| # | Finding | Severity |
|---|---------|----------|
| 1 | Expired lock boost persists indefinitely for idle pure stakers, allowing excess reward capture | 🔴 High |
| 2 | Router's uniform hop input rescaling silently undoes the Solver's input side capacity clamp | 🔴 High |
| 3 | Just-in-time stakers can capture previously accrued borrower interest by entering before maintenance realizes it |  🟠 Med |
| 4 | Self-Beneficiary exclusion in `_sweepExpiredLocks` allows expired boost to persist and misallocate rewards | 🟠 Med |
| 5 | Protocol Fee Evasion via Crafted `route.totalOut` | 🟠 Med |
| 6 | V4 Pool-Key mismatch duplicates solver candidates and falsifies registry freshness | 🟡 Low |
| 7 | Block-Number-Based Vitality Aging Produces Chain-Dependent Fitness Scoring | 🟡 Low |

---

# 🏅 Public Recognition

The protocol publicly credited my contributions through:

- Security Hall of Fame
- Technical Whitepaper
- Version History
- Official Release Documentation

---

# 🔗 References

- **Repository:** [Repo Link](https://github.com/blazephoenixxyz-crypto)
- **Security Hall of Fame:**
      - [BlazePhoenix Staking](https://github.com/blazephoenixxyz-crypto/Blaze-Phoenix-Staking)
      - [BlazePhoenix DEX V1](https://github.com/blazephoenixxyz-crypto/Blaze-Phoenix-Dex-v1/blob/BlazePhoenix/FinalVersion/SECURITY_HALL_OF_FAME.md)
      - [BlazePhoenix DEX](https://github.com/blazephoenixxyz-crypto/Blaze-Phoenix-Dex/blob/main/SECURITY_HALL_OF_FAME.md)

---
