---
title: Apache Vast.ai + Open WebUI Runbook
author: Greg Stein
date: 2026-05-04
version: 1.0
---

# Apache Vast.ai + Open WebUI Runbook

**Goal:** Provide a private, self-hosted LLM (Granite 4.1:30B) for Apache staff and committers with strong data privacy.

**Last Updated:** May 4, 2026  
**Owner:** Apache Infrastructure (AKM + Greg Stein)

---

## 1. Prerequisites

- Apache.org account with **Manager** role in the Vast.ai “apache” organization (invited by AKM).
- Billing is handled centrally by AKM — no individual credit card required.
- Target model: **Granite 4.1:30B** (observed usage: ~26 GB VRAM, ~40 GB disk).

---

## 2. Create / Start an Instance on Vast.ai

1. Log into [vast.ai](https://vast.ai) with your Apache.org account.
2. Left nav → **Instances** → **Create Instance**.
3. In the template search box (upper left), type **Ollama** and select the **Open WebUI** template.
4. Set filters in the left sidebar:
   - Container disk size: **80 GB**
   - Per-GPU RAM (VRAM): **≥ 40 GB**
5. Sort offers by **Price (increasing)**.
6. Choose a suitable cheap instance (e.g., RTX 8000 with ≥48 GB VRAM).
7. Click **Rent** (on-demand).
8. Wait until the instance status changes to **Open**.

> **Note:** If an instance prompts for a custom certificate you do not trust, cancel and rent a different one.

---

## 3. Launch Open WebUI

1. Click the **Open** button on your running instance.
2. Select **Open WebUI** from the list of available applications.
3. Wait for the interface to fully load (you can monitor progress in the **Logs** tab).
4. On first launch, create the admin account:
   - **Name:** Your Name
   - **Email:** yourname@apache.org
   - **Password:** Use a strong Chrome-generated password (store securely in Apache shared password manager)

---

## 4. Download and Configure the Model

1. In Open WebUI, go to the model selector in the top navigation.
2. Click **Download new model**.
3. Paste: `granite4.1:30b`
4. Wait for the download to complete.
5. (Recommended) Open the sidebar (upper-left icon) → use the three-dot menu on any model → **Keep in sidebar**.
6. Select **Granite 4.1:30B** as the active model.

**Observed Resource Usage:**
- VRAM: ~26 GB out of 48 GB
- Disk: ~40 GB out of 80 GB

---

## 5. Daily Usage

- Go to Vast.ai → **Instances** → click **Open** on the desired instance → launch **Open WebUI**.
- All chats and data remain on the instance (strong privacy benefit for Apache).

---

## 6. Stopping & Restarting

- In Vast.ai console → click **Stop** on the instance.
- To resume: click **Start** (same button).
- The instance returns with all models and data intact thanks to container persistence.

---

## 7. Security & Account Notes

- AKM (organization owner) invited you as Manager.
- Consider enabling 2FA or OAuth on the Vast.ai Apache organization if available.
- Access should be limited to Apache staff and committers.
- Policy around models, API keys, and data handling is still under development.

---

## 8. Future Sizing Guidance

For Granite 4.1:30B use:
- Minimum **40–48 GB VRAM** per GPU
- Minimum **80 GB** container disk
- Any cheap instance meeting the above is sufficient.

---

## Open Items / Future Work

- Define formal access policy (who can be invited, invitation process)
- Decide on API key handling and external integrations
- Explore multi-user setup in Open WebUI
- Backup / snapshot strategy for the instance
- Evaluate smaller quantized models for cost/performance trade-offs

---

**End of Runbook**
