# Release validation

The baseline is the supplied `enovation_app_13_2.zip`, not the older GitHub
application. Changes to publication settings are intentionally separated
from the recommendation algorithms.

## Verified locally

- Exact equality of complete JSON payloads for 157 App_2 requests: all 102
  technology/scenario pairs, available seed modes, all eight target classes,
  several importance weights, a five-seed request and local TBox fallback.
- Exact equality of the options catalog, instance lists and subtype choices.
- Exact equality for 25 hybrid requests (five centres, five fusion weights).
- All recommendation functions have identical Python syntax trees, excluding
  `run_sparql`, whose only function-body change redacts exception details in logs.
- WP3/WP5 source, configs, frozen graph views and splits match the ZIP
  (ignoring UTF-8 BOM encoding markers). The published ontology still produces
  the same 2,917 instance triples. Only 15 unused contact literals were removed.
- Fifteen HTTP security/contract tests pass, and all three browser scripts
  pass JavaScript syntax checks. All Python files parse successfully.
- The application requirements resolve without known vulnerabilities in the
  dependency advisory check performed for this release. Flask 3.1.3,
  Requests 2.33.0 and Waitress 3.0.2 replace the affected ZIP versions;
  RDFLib remains at 7.0.0.

## Method and limits

Payload comparisons ran the original and candidate code in separate Python
3.12 environments, using their respective application dependency versions
and the same ontology content except for the removed contact literals.
The test adapter executes SPARQL locally; it sorts binding rows consistently
and evaluates the two projected EXISTS checks separately because RDFLib 7.0
does not support those projections reliably. Production queries still run
unchanged on Fuseki. These comparisons are regression checks, not a new
validation of the thesis's relevance metrics.

The App recommendation algorithm is unchanged by syntax-tree comparison;
its full SPARQL workload was not replayed for all reference cases. Heavy KGE
training/HPO and missing historical evaluators were not rerun. No claim is
made that all possible queries or infrastructure failure modes were tested.
The historical provenance and reproducibility limitations from the supplied
package remain documented in the full thesis repository's `THESIS_TRACEABILITY.md`.

Run the maintained HTTP tests from the repository root:

```sh
python -m pip install -r requirements-dev.txt
python -m pytest tests -q
```

Capture complete payloads with `python tools/capture_regression.py . snapshot.json.gz`.
Run the same script against an untouched extracted ZIP and the candidate,
then compare the decoded JSON objects. Keep generated snapshots outside Git.
The standalone App_2 repository skips hybrid cases because it intentionally
does not contain the other applications.
