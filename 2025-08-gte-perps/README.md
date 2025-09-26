## 📊 Submissions Summary

- **Total Findings Submitted:** 7  
- **Severity Breakdown:**
  - 🟥 High: 2  
  - 🟧 Medium: 3  
  - 🟨 Low / Quality: 2  

---

## 📂 Structure

- `2025-08-gte-perps/` → Findings from GTE Perps contest.  
- (Future folders) → Each audit contest or project will be stored in its own folder.

Each folder contains:
- `README.md` with structured findings (Root cause → Impact → PoC → Mitigation).  
- PoC test files (if relevant).  

---

## ✅ Why this repo?

- Demonstrates **real-world competitive audit participation**.  
- Shows ability to find **logic issues, DoS vectors, economic inefficiencies, and misaligned incentives**.  
- Includes both **valid and rejected-but-still-valid case studies** to highlight bias in judging processes.  

---

## 🚀 Findings Overview

| #   | Title                                                                 | Severity |
|-----|-----------------------------------------------------------------------|----------|
| 1   | Misaligned rewards in Distributor:addRewards due to positional params | High     |
| 2   | DoS in Launchpad `_swapRemaining` (wrong payer msg.sender)            | Medium   |
| 3   | Gas DoS when matching many orders at same price (Book.sol)            | Medium   |
| 4   | Inconsistent denominators skewing `getImpactPrice` (Market.sol)       | High     |
| 5   | Gas DoS across multiple price levels (CLOBLib)                        | Medium   |
| 6   | Fragile 1-second swap deadline                                        | Low      |
| 7   | Unbounded loop in backstop liquidation                                | Low      |

---
