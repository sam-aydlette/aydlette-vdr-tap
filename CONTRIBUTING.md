# Contributing to aydlette-vdr-tap

This plugin implements the method of "Vulnerability Evidence as a Product"
(samaydlette.com/research/vulnerability-evidence.html). The paper's Appendix A (requirements) and Appendix B (conformance
tests) are the source of truth. [`specs/spec-aydlette-vdr-v0.md`](specs/spec-aydlette-vdr-v0.md) maps each one to the
code and the test that proves it.

## Definition of done

"Done" has three levels. A change meets the first, a release meets the first two, and the method is done when all three
hold.

### 1. A change is done when

- [ ] **Its behavior is specified.** The acceptance criterion it satisfies is in the spec. A new behavior gets a new
      criterion first, with status `Proposed` or `In Development`.
- [ ] **A test proves it and cites it.** The test carries `@pytest.mark.spec("<ACID>")`, and the criterion's status is
      `Implemented` in the same change. A criterion is `Implemented` only when a test cites it, and a requirement only
      when all its criteria are. `tests/test_spec.py` enforces this.
- [ ] **Both test suites pass.** This repo's, and aydlette-vdr-aws-tap's, since the adapter imports from this one.
- [ ] **Types and format are clean.** mypy reports no errors in this plugin, and the files you touched pass
      `ruff format --check`.
- [ ] **The validator passes:** `validate_plugin --level loads --strict`.
- [ ] **It ran on a real grid.** The collectors and Searches ran in a TAP session against real data, and you read the
      output. Unit tests have missed real bugs here: an S3 redirect read as an open path, and resources that share a
      name.
- [ ] **The docs match.** The README is updated when a Search, collector, model or profile field changes.
- [ ] **The commit discloses AI assistance** where there was any: end the message with
      `Assisted-by: <tool> (<model>)`. Never use `Co-Authored-By` for an AI.

### 2. A release is done when

- [ ] **No criterion is unaccounted.** Every criterion is `Implemented`, or its status and note say why not:
      `In Development` (built, untested), `Backlog` (not built) or `Proposed` (a person's act or a live drill). The
      Paper Coverage table in the spec is current.
- [ ] **It installs from a clone.** `boot/ci.boot.json` installs every dependency from a pinned repository and commit,
      not an editable path, and the record's digest is refreshed.
- [ ] **The repository checks pass:** `validate_plugin --repo --strict` from the repository root. They need:
  - `.github/workflows/ci.yml` and `nightly.yml`, calling TAP's reusable `plugin-ci.yml` pinned by commit SHA;
  - a `CODEOWNERS` file naming a human owner;
  - release-please configuration (optional).
- [ ] **`validate_plugin --level runs --strict` passes in that CI.** It needs a grid writer with a named actor, which
      a development session may not grant.
- [ ] **It is versioned and documented.** `plugin_version` is bumped, the CHANGELOG has an entry, the README's links are
      absolute, and its "Not in" section is current.
- [ ] **The maintainer has reviewed the code.** The README says the method, design and review are Sam Aydlette's, so
      that must be true of every release.

### 3. The method is done when

- [ ] **All 74 Appendix B tests are `Implemented`,** or excluded with a reason in the spec.
- [ ] **Every path is tested on a grid, not only on pure data.** That includes the advisory path: findings with CVE
      records, enriched with KEV, EPSS and SSVC by vuln_mosaic, run through all four Searches and the fedramp_20x_vdr
      bridge. `tests/test_grid_cve.py` does this, and it must pass, not skip: run it in a session with vuln_mosaic
      installed beside this plugin (see "Running the checks").
- [ ] **Coverage on a real environment shows only real gaps.** `aydlette-coverage` on a live system reports missing
      tags and services that are off, never gaps the tooling caused.
- [ ] **Someone other than the author has reviewed it,** against the paper, not against this implementation.

## Working on the spec

The spec follows TAP's template (`specs/spec-req-template.md` in TAP), and TAP's requirement-traceability rules
(`spec-tap-requirement-traceability.md`):

1. Add or change the acceptance criterion in the spec, with status `Proposed`, `In Development` or `Backlog`.
2. Build it, and mark the test that proves it: `@pytest.mark.spec("req-aydlette-vdr-<area>-<n>")`.
3. Set the criterion to `Implemented` in the same change. If every criterion of the requirement is now `Implemented`,
   set the requirement to `Implemented` too.
4. If the criterion is an Appendix B test, update its row and the counts in the Paper Coverage table.

`tests/test_spec.py` fails when these get out of step. Never renumber an existing criterion: a test cites it by ID.
Never set `Verified` yourself; TAP reserves that status for requirements with two independent kinds of evidence.

When the paper changes, update the quoted requirement text, the provenance line (the paper's commit) and any criterion
whose meaning changed.

## Running the checks

From a TAP checkout with this plugin at `_dev-plugins/aydlette_vdr` (TAP's development workspace), inside the web
container:

```bash
# tests (both repos)
.venv/bin/pytest -q -p no:cacheprovider --strict-markers _dev-plugins/aydlette_vdr/tap_plugin _dev-plugins/aydlette_vdr_aws/tap_plugin

# types: one -m per module, excluding migrations and tests
M=$(find _dev-plugins/aydlette_vdr/tap_plugin -name "*.py" -not -path "*/migrations/*" -not -path "*/tests/*" \
  | sed "s|^_dev-plugins/aydlette_vdr/||; s|/|.|g; s|\.py$||; s|\.__init__$||; s|^|-m |" | tr "\n" " ")
.venv/bin/mypy --cache-dir /tmp/mypy --config-file pyproject.toml $M

# format, from the plugin's own root
(cd _dev-plugins/aydlette_vdr && /app/.venv/bin/ruff format --no-cache --check .)

# validator
.venv/bin/python manage.py validate_plugin _dev-plugins/aydlette_vdr/tap_plugin/aydlette_vdr --level loads --strict
.venv/bin/python manage.py validate_plugin _dev-plugins/aydlette_vdr --repo --strict

# seed changed Search nodes into the session's grid (an existing batch needs --force-batches <batch id>)
.venv/bin/python manage.py import_plugin_grift aydlette_vdr --bundle searches
```

The CVE grid tests (`tests/test_grid_cve.py`) drive vuln_mosaic's real enrichment. vuln_mosaic is not a dependency of
this plugin, so this plugin's CI record does not install it and those tests skip there. Run them in a session whose
boot record also installs vuln_mosaic, and check that pytest reports them passed, not skipped:

```bash
.venv/bin/pytest -q -p no:cacheprovider --strict-markers -rs _dev-plugins/aydlette_vdr/tap_plugin/aydlette_vdr/tests/test_grid_cve.py
```

The first database-backed run creates the test database, which takes about half an hour with many plugins installed;
add `--reuse-db` to keep it between runs.

The pure core (`method/`) has no TAP or Django import, so its tests also run outside TAP:

```bash
uv run --no-project --python 3.14 --with pytest python -m pytest -q tap_plugin/aydlette_vdr/tests/test_conformance.py \
  tap_plugin/aydlette_vdr/tests/test_reconcile.py tap_plugin/aydlette_vdr/tests/test_coverage.py \
  tap_plugin/aydlette_vdr/tests/test_environmental.py tap_plugin/aydlette_vdr/tests/test_spec.py
```

## Licensing

Code is Apache-2.0 (`LICENSE`) and documentation is CC BY 4.0 (`LICENSES/CC-BY-4.0.txt`). By contributing, you agree to license your work
under the same terms.
