# Flexible semantic recommendations

App_2 recommends ontology individuals from a target class and up to five
weighted seeds. Each seed can identify an individual, a subtype, or a whole
class. Results include scores and the semantic paths supporting them.

## Run locally

Use Python 3.12 or newer. From the repository root:

```sh
python -m venv .venv
# Activate .venv using the command for your shell.
python -m pip install -r requirements.txt
python -m App_2.run_waitress
```

Open <http://localhost:5000>. Configure `FUSEKI_ENDPOINT` in your shell before
starting the server. The default is a local Fuseki dataset at
`http://localhost:3030/enovation/sparql`. `.env.example` documents settings;
the application does not automatically load `.env` files.

## Code map

| File | Responsibility |
| --- | --- |
| `app.py` | HTTP routes, input validation, class catalog and UI option caches |
| `enovation_recommender.py` | SPARQL access, graph/schema caches, criterion discovery, scoring and explanations |
| `templates/index.html` | Query builder, result cards and browser-local query/feedback history |
| `run_waitress.py` | Production WSGI entry point; serial request processing protects shared caches |
| `../ontology.ttl` | Versioned schema fallback; it does not replace the live ABox |

The engine loads the instance graph from Fuseki, discovers schema criteria
with constrained breadth-first traversal, measures instance support, and
combines normalized criterion scores with the seed weights. The release
retains `MAX_PATH_LENGTH = 4`, `LENGTH_DECAY_ALPHA = 0.4`, class re-entry
constraints and the original ranking/explanation calculations.

## HTTP API

| Route | Purpose |
| --- | --- |
| `GET /` | Application page |
| `GET /healthz` | Process liveness; does not claim Fuseki availability |
| `GET /api/options` | Available seed/target types and legacy choices |
| `GET /api/instances?class_key=Technology` | Individuals belonging to a catalog class |
| `GET /api/class-values?class_key=Facility&mode=type` | Individual or subtype choices |
| `POST /api/recommend` | Flexible recommendations |
| `GET /api/recommend?tech=...&scen=...` | Legacy technology/scenario query |
| `POST /api/feedback` | Append a feedback record to a server-local file |

For `POST /api/recommend`, use class keys from `/api/options` and value URIs
from `/api/class-values`. Example body:

```json
{
  "target_type": "TrainingCentre",
  "seeds": [{"type": "Technology", "mode": "class", "importance": 2}]
}
```

## Render

The existing hosted service uses an empty Root Directory and the compatible
commands below; they can remain in place for this update:

```text
Build: pip install -r requirements.txt && pip install gunicorn
Start: gunicorn --chdir App_2 app:app --bind 0.0.0.0:$PORT
```

Deploy only the standalone `ManosMarkoulakis/App_2` repository.
For a new service using the bundled Waitress launcher, use:

```text
Build Command: pip install -r requirements.txt
Start Command: python -m App_2.run_waitress
Health Check Path: /healthz
```

Set `FUSEKI_ENDPOINT` privately in Render's Environment settings before
deploying. `PORT` and `RENDER` are supplied by Render. A successful deployment
also requires non-empty `/api/options` and a real recommendation, not just a
successful homepage response. The launcher also supports `python App_2/app.py`
for existing services using that command.

Keep one process and one request thread while using the existing mutable
in-memory caches. Restart after changing the Fuseki dataset. Feedback files
on an ephemeral filesystem can disappear after a restart/redeployment; set
`FEEDBACK_FILE` to an existing writable persistent directory if retention is
required. The application neither provisions storage nor stores client IPs
in its feedback records.

## Extending the application

Start with the type allowlists in `app.py` for UI choices. Scoring changes
belong in `enovation_recommender.py`; compare full payloads on the same dataset
before changing path discovery, normalization or tie-breaking. Changes to
Fuseki data can change results even when source code is unchanged.
