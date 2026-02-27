# Failing Target Suite

This suite provides deterministic failing targets for end-to-end `veripatch` runs.

## Targets

- `name_error`: undefined variable in `math_utils.add`
- `slugify_bug`: incorrect slug formatting in `text_utils.slugify`
- `median_bug`: median implementation does not sort input

Each target directory includes:

- source file with a known bug
- `tests/` with one failing unit test
- `pp.json` policy scoped to source-file fixes only

## Validate suite is failing

```bash
python examples/failing_targets/run_baseline.py
```

You should see all targets report `FAILS (expected)`.

## Run veripatch on one target

```bash
cd examples/failing_targets/name_error
pp run "python -m unittest discover -s tests -v" --policy pp.json --provider local --json
```

## Run all targets (manual)

```bash
for t in name_error slugify_bug median_bug; do
  (
    cd "examples/failing_targets/$t"
    pp run "python -m unittest discover -s tests -v" --policy pp.json --provider local --json
  )
done
```
