# Soulbound Security – SBF Protocol

## Overview

This directory documents my security review, threat analysis, mitigation design process and implementation contribution for the SBF Protocol maintained by Soulbound Security.

## Contribution

My work included:

* Reviewing the model.
* Identifying security considerations.
* Evaluating multiple mitigation approaches and their associated trade-offs.
* Designing and implementing the final approved approach.
* Submitting a protocol improvement pull request for review.

## Outcome

# 📊 Contribution Summary

- **Total Valid Findings:** 3  
- **Severity Breakdown:**
  - 🟥 High: 1  
  - 🟧 Medium: 2  
  - 🟨 Low / Informational: 0
 
# 🚀 Findings Overview

| # | Finding | Severity |
|---|---------|----------|
| 1 | ClaimPool.useGasFund bricks documented Aave Yield integration due to "Push vs Pull" token architecture mismatch | 🔴 High |
| 2 | Architectural bypass of Canonical identity derivation | 🟠 Med  |
| 3 | ClaimPool.useGasFund allows Gas Manager to completely drain protocol redemption balances via arbitrary target calls and Cross-Token Target Spoofing |  🟠 Med |  

## References
* Repo: [LINK](https://github.com/SoulboundSecurity/sbf-protocol)

