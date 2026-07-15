# MalAnalyzer - What I Need From You (design -> build handoff)

> Design is frozen (`DECISION-LOG.md` D0). This is the honest list of what I need from your side to start M0 and reach a usable product in ~6 weeks. Nothing here is a research question - they're setup/access/decisions. If any item is hard to provide, say so and I'll adapt the plan around it; none of them changes the architecture.

## A. To start writing M0 code this week (the real blockers)
1. **A git host + an empty repo** (GitHub / GitLab / self-hosted Gitea) and the **project/org name** you want. (The name also feeds the later trademark/governance decision, RH-13 - pick one you'd keep.)
2. **A Linux dev host** (bare-metal or a VM - 8+ cores, 32 GB is plenty for the static wedge) with a **rootless container runtime** (Podman >=4, or rootless Docker). *Why Linux:* the worker's empty-netns + seccomp posture is the product and only exists on Linux. A macOS/Windows laptop is fine as your editor, but the containers run on Linux. **No `/dev/kvm` needed - detonation is Phase-2.**
3. **Toolchains** (I'll pin exact versions in the repo): Go, Rust, Python 3.12+, Node 20+. If you have a preferred internal base image / registry, point me at it.
4. **A one-line ratify** of the product bets you now own (all in `DECISION-LOG.md`): static-only v1, MACO config-extraction as the differentiator, greenfield-on-Temporal. A nod is enough - I don't need a document.

## B. Sample data (to build and test against - needed by M1)
5. **A malware sample source** for the test corpus - the cleanest is an **abuse.ch MalwareBazaar API key** (free, per-family pulls), or an internal sample set if you have one. For air-gapped dev, a curated offline set copied to the dev host.
6. **A goodware set** for false-positive testing. Recommended: I build it from redistributable-licensed distro packages and **ship hashes, not bytes** (RM-25 - avoids the copyright trap). I just need your OK on that approach, or a goodware corpus if you already have one.
7. **A few known-family samples** (e.g., a couple of common commodity RATs/loaders) so the **MACO config-extraction differentiator (M2)** has something real to extract. MalwareBazaar covers this.

## C. The one human who ends the review loop (needed by ~week 5)
8. **A real analyst** - SOC/IR or reverse-engineer - who will run a real sample end-to-end at ~6 weeks and tell us what's useful and what's noise. This is the ground truth that replaces further design review. Even 2 hours of their time at M2 is the most valuable thing on this list.

## D. Roles & decisions (not blocking M0 code, but soon)
9. **Who owns the release-engineering track** (ADR-024) - reproducible builds, signing, the license gate. Can be you part-time or a second person; just needs an owner so it doesn't become an end-of-project wall.
10. **Governance baseline** (RH-13, before you take outside contributions, not before first code): a call on neutral trademark holder / DCO-vs-CLA / a binding open-core boundary. I can draft options when you want them.

## E. Phase-2 - flagged now so you can plan/budget, needed later (NOT now)
11. **A separate, KVM-capable Linux bare-metal node** for the detonation plane (escape-containment requires it - A1). Phase-2 capex.
12. **A detonation specialist** hire - the long pole; post it when Phase-2 is funded, not now.
13. **Legal counsel** - engaged when a copyleft engine (detonation/emulation/Volatility) or a commercial edition enters, or before any public distribution; hand them `LICENSING-BRIEF.md` + the FTO / model-weight / content-corpus asks (RH-12/11, RM-25). A **ship-gate**, not a start-gate.

---

**Bottom line:** to start Monday I need **A1-A4** (repo, a Linux+Podman host, toolchains, your ratify nod). **B** unblocks M1, **C** unblocks the 6-week goal, **D/E** are parallel/later. Tell me which of A-C you can hand over and I'll sequence the first commit around it.
