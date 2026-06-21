# Contributing to ESP32-P4 Ghidra Plugin

Thank you for contributing. This document covers the development workflow,
commit conventions, and PR checklist.

---

## Development Model: Trunk-Based Development

`main` is the trunk and must always be deployable. All work lands on `main`
via short-lived branches — never directly.

| Branch prefix | Purpose | Max lifetime |
|---------------|---------|--------------|
| `feature/<kebab-name>` | New functionality | 1–2 days |
| `fix/<kebab-name>` | Bug fixes | 1 day |
| `docs/<kebab-name>` | Documentation only | 1 day |

There are **no long-running release branches**. Releases are tags on `main`.

### Branch lifecycle

```bash
# 1. Branch off main
git checkout main && git pull
git checkout -b feature/add-esp32p5-variant

# 2. Make small, focused commits (see Conventional Commits below)
git commit -m "feat(lang): add RV32.pspec variant for ESP32-P5"

# 3. Push and open a PR
git push -u origin feature/add-esp32p5-variant
# → squash-merge into main → delete branch
```

Keep PRs small. If a feature takes more than two days, split it or use a
feature flag in the Java plugin layer.

---

## Commit Messages — Conventional Commits

Format: `type(scope): description` with the **subject line ≤ 72 characters**.
Body and footer lines wrapped at **72 characters**.

```
type(scope): short imperative description         ← ≤72 chars
<blank line>
Optional body — explain WHY, not what.
Wrap at 72 chars.
<blank line>
Optional footer: Closes #42, BREAKING CHANGE: …
```

### Types

| Type | When to use |
|------|-------------|
| `feat` | New instruction, script, or feature |
| `fix` | Bug in Sleigh pattern, Java, or script |
| `docs` | README, CONTRIBUTING, comments |
| `build` | Gradle, extension manifest, packaging |
| `refactor` | Code restructure with no behavior change |
| `test` | Headless test scripts or CI checks |
| `chore` | Dependency bumps, file renames |
| `perf` | Performance improvement |
| `style` | Whitespace / formatting only |
| `ci` | GitHub Actions or workflow files |

### Scopes

| Scope | Covers |
|-------|--------|
| `lang` | Sleigh files (`.sinc`, `.slaspec`, `.cspec`, `.ldefs`) |
| `plugin` | Java plugin source (`src/main/java/`) |
| `scripts` | Ghidra scripts (`ghidra_scripts/`) |
| `docs` | Documentation files |
| `build` | Build system (`build.gradle`, `settings.gradle`) |
| `ci` | Workflow / automation |

### Examples

```
feat(lang): add xespv2p2 PIE arithmetic patterns for 0x1B opcode
fix(lang): correct vst.128.ip op2531 field to 0x41
feat(scripts): add LoadESP32P4SVD peripheral label script
fix(plugin): null-check in ESP32P4Analyzer peripheral lookup
docs: add PIE SIMD confirmed-ops table to README
build: include riscv32.dwarf in extension zip
chore(scripts): update LoadESP32P4SVD default SVD path
```

### Breaking changes

Add `!` after the type/scope, or include a `BREAKING CHANGE:` footer:

```
feat(lang)!: rename ESP32-P4 language ID to RISCV:LE:32:ESP32P4

BREAKING CHANGE: existing Ghidra projects must be re-imported with
the new language ID.
```

---

## Pull Request Checklist

Before requesting review, confirm every item:

- [ ] Branch name matches `feature/`, `fix/`, or `docs/` prefix
- [ ] All commit subjects follow Conventional Commits (≤ 72 chars)
- [ ] Sleigh compiles without new warnings in **our** files:
      `cd data/languages && sleigh -a .`
      (upstream `riscv.*.sinc` warnings are pre-existing and expected)
- [ ] Java compiles without new warnings:
      `gradle compileJava`
- [ ] Headless import succeeds with no new ERRORs:
      `analyzeHeadless … -processor "RISCV:LE:32:ESP32-P4" -noanalysis`
- [ ] Upstream files (`riscv.*.sinc`, `andestar_v5.instr.sinc`) are
      **not modified** unless strictly necessary
- [ ] Every new source file carries the Apache 2.0 SPDX header
- [ ] `dist/` and `*.sla` are **not committed** (covered by `.gitignore`)

---

## Releases

Releases follow [SemVer](https://semver.org): `vMAJOR.MINOR.PATCH`.

Only maintainers create release tags:

```bash
git tag -s v1.0.0 -m "release: v1.0.0"
git push origin v1.0.0
```

GitHub Releases are created from the tag with the built ZIP attached.
The ZIP is produced by:

```bash
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra buildExtension
```

---

## Getting Started

See [README.md](README.md) for build instructions, requirements, and
installation steps. Once you can run `gradle buildExtension` and the
headless import test passes, you are ready to contribute.

---

## Code of Conduct

Be respectful and constructive. Critique ideas, not people. Harassment,
discrimination, or personal attacks will not be tolerated and may result
in removal from the project.
