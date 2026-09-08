from flask import Flask, request, jsonify, render_template
import json
import math
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

if __package__:
    from .enovation_recommender import (
        KnowledgeBaseUnavailableError, build_flexible_ui_payload,
        build_ui_payload, run_sparql,
    )
else:
    from enovation_recommender import (
        KnowledgeBaseUnavailableError, build_flexible_ui_payload,
        build_ui_payload, run_sparql,
    )

# Flask app + feedback log location.
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
ROOT_DIR = Path(__file__).resolve().parents[1]
FEEDBACK_FILE = Path(os.getenv("FEEDBACK_FILE", str(ROOT_DIR / "feedback_log.jsonl")))
EN_NS = "http://www.semanticweb.org/eNOVATION-ontology#"

INSTANCE_CACHE: Dict[str, List[Dict[str, str]]] = {}
SUBCLASS_CACHE: Dict[str, List[Dict[str, str]]] = {}
CLASS_CATALOG_CACHE: Optional[Dict[str, object]] = None
CLASS_MODE_CACHE: Dict[str, Dict[str, object]] = {}

# Curated default UI types for the thesis prototype.
# Instances remain subclass-aware; only the top-level type choices are restricted.
CORE_SEED_TYPE_ORDER = [
    "Technology",
    "Scenario",
    "ThreatAgent",
    "TrainingCourse",
    "Service",
    "SOP",
    "Standard",
    "Facility",
    "TrainingMethod",
    "Audience",
    "TCDiscipline",
    "TCType",
    "Incident",
    "TRLEnumeration",
    "ResponseAction",
    "TrainingCentre",
    "CBRNNetwork",
    "Resource",
]

CORE_TARGET_TYPE_ORDER = [
    "TrainingCentre",
    "TrainingCourse",
    "Technology",
    "SOP",
    "Facility",
    "Scenario",
    "Incident",
    "Exercise",
]

CORE_SEED_TYPE_KEYS = set(CORE_SEED_TYPE_ORDER)
CORE_TARGET_TYPE_KEYS = set(CORE_TARGET_TYPE_ORDER)

TYPE_MODE_PREFERRED_KEYS = {
    "Exercise",
    "Facility",
    "Incident",
    "Service",
    "Standard",
}

# Audience subclasses are meaningful semantically, but in the current UI they are
# better represented through direct audience selections rather than a mode switch.
TYPE_MODE_DISABLED_KEYS = {
    "Audience",
}

TYPE_KEY_ALIASES = {
    "ResponceAction": "ResponseAction",
}


def _local_name(uri: str) -> str:
    if "#" in uri:
        return uri.rsplit("#", 1)[-1]
    return uri.rsplit("/", 1)[-1]


def _humanize_local_name(name: str) -> str:
    out = []
    prev_lower = False
    for ch in name.replace("_", " "):
        if ch.isupper() and prev_lower:
            out.append(" ")
        out.append(ch)
        prev_lower = ch.islower()
    return "".join(out).strip()


def _require_sparql_bindings(data: Dict[str, object], query_name: str) -> List[Dict[str, object]]:
    bindings = data.get("results", {}).get("bindings") if isinstance(data, dict) else None
    if bindings is None:
        raise KnowledgeBaseUnavailableError(f"Fuseki query failed or returned malformed data for {query_name}.")
    return list(bindings)


def _fetch_class_catalog() -> Dict[str, object]:
    """Greedy class catalog: all EN classes (with labels + instance counts)."""
    global CLASS_CATALOG_CACHE
    if CLASS_CATALOG_CACHE is not None:
        return CLASS_CATALOG_CACHE

    q_classes = f"""
    PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX owl:  <http://www.w3.org/2002/07/owl#>
    PREFIX skos: <http://www.w3.org/2004/02/skos/core#>

    SELECT DISTINCT ?class ?label ?definition ?comment WHERE {{
      {{
        ?class a owl:Class .
      }} UNION {{
        ?class a rdfs:Class .
      }}
      FILTER(STRSTARTS(STR(?class), "{EN_NS}"))
      OPTIONAL {{
        ?class rdfs:label ?label .
        FILTER(LANG(?label) = "" || LANGMATCHES(LANG(?label), "en"))
      }}
      OPTIONAL {{
        ?class skos:definition ?definition .
        FILTER(LANG(?definition) = "" || LANGMATCHES(LANG(?definition), "en"))
      }}
      OPTIONAL {{
        ?class rdfs:comment ?comment .
        FILTER(LANG(?comment) = "" || LANGMATCHES(LANG(?comment), "en"))
      }}
    }}
    """

    q_counts = f"""
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX owl:  <http://www.w3.org/2002/07/owl#>

    SELECT ?class (COUNT(DISTINCT ?s) AS ?count) WHERE {{
      ?s a owl:NamedIndividual ;
         a ?type .
      ?type rdfs:subClassOf* ?class .
      FILTER(STRSTARTS(STR(?class), "{EN_NS}"))
    }}
    GROUP BY ?class
    """

    class_data = run_sparql(q_classes)
    count_data = run_sparql(q_counts)
    class_bindings = _require_sparql_bindings(class_data, "class catalog")
    count_bindings = _require_sparql_bindings(count_data, "class instance counts")

    counts: Dict[str, int] = {}
    for b in count_bindings:
        uri = b["class"]["value"]
        try:
            counts[uri] = int(b["count"]["value"])
        except Exception:
            counts[uri] = 0

    by_uri: Dict[str, Dict[str, object]] = {}
    for b in class_bindings:
        uri = b["class"]["value"]
        label = b.get("label", {}).get("value")
        definition = b.get("definition", {}).get("value")
        comment = b.get("comment", {}).get("value")
        description = definition or comment or "There is no definition for this class."
        if uri not in by_uri:
            local = _local_name(uri)
            by_uri[uri] = {
                "key": local,
                "class_uri": uri,
                "label": label or _humanize_local_name(local),
                "description": description,
                "instance_count": counts.get(uri, 0),
                "disabled": counts.get(uri, 0) == 0,
                "disabled_reason": "No instances available for this class." if counts.get(uri, 0) == 0 else "",
            }
        elif label and not by_uri[uri].get("label"):
            by_uri[uri]["label"] = label
        elif description and by_uri[uri].get("description") == "There is no definition for this class.":
            by_uri[uri]["description"] = description

    items = list(by_uri.values())
    items.sort(key=lambda x: (str(x["label"]).lower(), str(x["key"]).lower()))

    key_to_uri = {item["key"]: item["class_uri"] for item in items}
    CLASS_CATALOG_CACHE = {"items": items, "key_to_uri": key_to_uri}
    return CLASS_CATALOG_CACHE


def _fetch_instances_for_class(class_uri: str) -> List[Dict[str, str]]:
    """Return NamedIndividual instances for class_uri (including subclass-typed instances)."""
    if class_uri in INSTANCE_CACHE:
        return INSTANCE_CACHE[class_uri]

    query = f"""
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX owl: <http://www.w3.org/2002/07/owl#>

    SELECT DISTINCT ?s ?label
      (EXISTS {{
        ?s ?pOut ?o .
        ?pOut a owl:ObjectProperty .
        FILTER(STRSTARTS(STR(?pOut), "{EN_NS}"))
      }} AS ?hasOutgoing)
      (EXISTS {{
        ?i ?pIn ?s .
        ?pIn a owl:ObjectProperty .
        FILTER(STRSTARTS(STR(?pIn), "{EN_NS}"))
      }} AS ?hasIncoming)
    WHERE {{
      ?s a ?type .
      ?type rdfs:subClassOf* <{class_uri}> .
      ?s a owl:NamedIndividual .
      OPTIONAL {{
        ?s rdfs:label ?label .
        FILTER(LANG(?label) = "" || LANGMATCHES(LANG(?label), "en"))
      }}
    }}
    ORDER BY LCASE(STR(?label))
    """
    data = run_sparql(query)
    bindings = _require_sparql_bindings(data, f"instances for {class_uri}")
    items = []
    for b in bindings:
        uri = b["s"]["value"]
        label = b.get("label", {}).get("value") or _humanize_local_name(_local_name(uri))
        has_outgoing = b.get("hasOutgoing", {}).get("value") == "true"
        has_incoming = b.get("hasIncoming", {}).get("value") == "true"
        disabled = not (has_outgoing or has_incoming)
        items.append(
            {
                "uri": uri,
                "label": label,
                "disabled": disabled,
                "disabled_reason": "No object-property links available for this individual." if disabled else "",
            }
        )
    INSTANCE_CACHE[class_uri] = items
    return items


def _fetch_subclasses_for_class(class_uri: str) -> List[Dict[str, str]]:
    """Return named EN subclasses for class_uri."""
    if class_uri in SUBCLASS_CACHE:
        return SUBCLASS_CACHE[class_uri]

    query = f"""
    PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX owl:  <http://www.w3.org/2002/07/owl#>

    SELECT DISTINCT ?sub ?label WHERE {{
      ?sub rdfs:subClassOf+ <{class_uri}> .
      {{
        ?sub a owl:Class .
      }} UNION {{
        ?sub a rdfs:Class .
      }}
      FILTER(STRSTARTS(STR(?sub), "{EN_NS}"))
      FILTER(?sub != <{class_uri}>)
      OPTIONAL {{
        ?sub rdfs:label ?label .
        FILTER(LANG(?label) = "" || LANGMATCHES(LANG(?label), "en"))
      }}
    }}
    ORDER BY LCASE(STR(?label)) LCASE(STR(?sub))
    """
    data = run_sparql(query)
    bindings = _require_sparql_bindings(data, f"subclasses for {class_uri}")
    catalog = _fetch_class_catalog()
    by_uri = {item["class_uri"]: item for item in catalog["items"]}
    items = []
    seen = set()
    for b in bindings:
        uri = b["sub"]["value"]
        if uri in seen:
            continue
        seen.add(uri)
        local = _local_name(uri)
        label = b.get("label", {}).get("value") or _humanize_local_name(local)
        count = int(by_uri.get(uri, {}).get("instance_count", 0))
        disabled = count == 0
        items.append(
            {
                "uri": uri,
                "key": local,
                "label": label,
                "instance_count": count,
                "disabled": disabled,
                "disabled_reason": "No instances available for this class." if disabled else "",
            }
        )
    SUBCLASS_CACHE[class_uri] = items
    return items


def _normalize_compare_text(value: str) -> str:
    return "".join(ch.lower() for ch in value if ch.isalnum())


def _build_class_mode_metadata(item: Dict[str, object]) -> Dict[str, object]:
    class_uri = str(item["class_uri"])
    class_key = str(item["key"])
    if class_uri in CLASS_MODE_CACHE:
        return CLASS_MODE_CACHE[class_uri]

    individuals = _fetch_instances_for_class(class_uri)
    subclasses = _fetch_subclasses_for_class(class_uri)
    selectable_individuals = [x for x in individuals if not x.get("disabled")]
    selectable_subclasses = [x for x in subclasses if not x.get("disabled")]

    available_seed_modes: List[str] = []
    if selectable_individuals:
        available_seed_modes.append("individual")
        available_seed_modes.append("class")
    if selectable_subclasses and class_key not in TYPE_MODE_DISABLED_KEYS:
        individual_norm = {_normalize_compare_text(x["label"]) for x in selectable_individuals}
        subclass_norm = {_normalize_compare_text(x["label"]) for x in selectable_subclasses}
        lists_equivalent = bool(individual_norm) and individual_norm == subclass_norm
        if not lists_equivalent:
            available_seed_modes.append("type")

    if "individual" in available_seed_modes:
        default_seed_mode = "individual"
    elif available_seed_modes:
        default_seed_mode = available_seed_modes[0]
    else:
        default_seed_mode = "individual"

    if class_key in TYPE_MODE_PREFERRED_KEYS and "type" in available_seed_modes:
        default_seed_mode = "type"

    available_target_modes: List[str] = ["individual"] if selectable_individuals else []

    disabled_reason = ""
    if int(item.get("instance_count", 0)) == 0:
        disabled_reason = "No instances available for this class."
    elif not available_seed_modes and not available_target_modes:
        disabled_reason = "No selectable values available for this class."

    metadata = {
        "available_seed_modes": available_seed_modes,
        "available_target_modes": available_target_modes,
        "show_seed_mode_switch": len(available_seed_modes) > 0,
        "show_target_mode_switch": len(available_target_modes) > 1,
        "default_seed_mode": default_seed_mode,
        "default_target_mode": "individual" if "individual" in available_target_modes else (available_target_modes[0] if available_target_modes else "individual"),
        "individual_count": len(individuals),
        "subclass_count": len(subclasses),
        "selectable_individual_count": len(selectable_individuals),
        "selectable_subclass_count": len(selectable_subclasses),
        "disabled": bool(disabled_reason),
        "disabled_reason": disabled_reason,
    }
    CLASS_MODE_CACHE[class_uri] = metadata
    return metadata


def _filter_condition_types(items: List[Dict[str, object]]) -> List[Dict[str, object]]:
    by_key = {str(item["key"]): item for item in items}
    return [by_key[key] for key in CORE_SEED_TYPE_ORDER if key in by_key]


def _filter_target_types(items: List[Dict[str, object]]) -> List[Dict[str, object]]:
    by_key = {str(item["key"]): item for item in items}
    return [by_key[key] for key in CORE_TARGET_TYPE_ORDER if key in by_key]


def _resolve_catalog_key(raw_key: Optional[str]) -> Optional[str]:
    if not raw_key:
        return raw_key
    return TYPE_KEY_ALIASES.get(raw_key, raw_key)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/healthz")
def health():
    """Process liveness; /api/options additionally checks the knowledge base."""
    return jsonify({"status": "ok"})


@app.before_request
def validate_json_object():
    """Reject malformed API input before it reaches application code."""
    if request.method == "POST":
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Expected a JSON object"}), 400


@app.after_request
def response_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response


@app.route("/api/options", methods=["GET"])
def api_options():
    """Fetch dynamic options.

    Backward-compatible fields:
    - technologies
    - scenarios

    New flexible-flow fields:
    - seed_types
    - target_types
    """
    try:
        catalog = _fetch_class_catalog()
        seed_types = []
        for item in _filter_condition_types(list(catalog["items"])):
            enriched = dict(item)
            enriched.update(_build_class_mode_metadata(item))
            seed_types.append(enriched)
        target_types = [
            {
                "key": item["key"],
                "label": item["label"],
                "class_uri": item["class_uri"],
                **_build_class_mode_metadata(item),
            }
            for item in _filter_target_types(list(catalog["items"]))
        ]

        # Keep old UI contract while we migrate frontend.
        tech_labels = [x["label"] for x in _fetch_instances_for_class(f"{EN_NS}Technology") if not x.get("disabled")]
        scen_labels = [x["label"] for x in _fetch_instances_for_class(f"{EN_NS}Scenario") if not x.get("disabled")]
    except KnowledgeBaseUnavailableError as e:
        print(f"Error fetching dynamic options: {e}")
        seed_types = []
        target_types = []
        tech_labels = []
        scen_labels = []
    except Exception as e:
        print(f"Error fetching dynamic options: {e}")
        seed_types = []
        target_types = []
        tech_labels = []
        scen_labels = []

    return jsonify(
        {
            "technologies": tech_labels,
            "scenarios": scen_labels,
            "seed_types": seed_types,
            "target_types": target_types,
        }
    )


@app.route("/api/instances", methods=["GET"])
def api_instances():
    """Fetch instances for a selected seed/target class key."""
    class_key = request.args.get("class_key") or request.args.get("seed_type") or request.args.get("target_type")
    if not class_key:
        return jsonify({"error": "Missing class_key"}), 400
    class_key = _resolve_catalog_key(class_key)

    class_uri = request.args.get("class_uri")
    # The URI is interpolated into SPARQL: accept catalog entries only.
    catalog = _fetch_class_catalog()
    if class_uri and class_uri not in catalog["key_to_uri"].values():
        return jsonify({"error": "Unknown class URI"}), 400
    if not class_uri:
        class_uri = catalog["key_to_uri"].get(class_key)
    if not class_uri:
        return jsonify({"error": f"Unknown class key/uri: {class_key}"}), 400

    try:
        instances = _fetch_instances_for_class(class_uri)
    except KnowledgeBaseUnavailableError as e:
        print(f"Knowledge base unavailable while fetching instances for {class_key}: {e}")
        return jsonify({"error": "Knowledge base unavailable. Please check Fuseki and retry."}), 503
    except Exception as e:
        print(f"Error fetching instances for {class_key}: {e}")
        return jsonify({"error": "Could not fetch instances"}), 500

    return jsonify({"class_key": class_key, "class_uri": class_uri, "instances": instances})


@app.route("/api/class-values", methods=["GET"])
def api_class_values():
    """Fetch selectable values for a class in individual or type mode."""
    class_key = request.args.get("class_key")
    mode = request.args.get("mode", "individual")
    if not class_key:
        return jsonify({"error": "Missing class_key"}), 400
    class_key = _resolve_catalog_key(class_key)
    if mode not in {"individual", "type"}:
        return jsonify({"error": f"Unsupported mode: {mode}"}), 400

    catalog = _fetch_class_catalog()
    class_uri = catalog["key_to_uri"].get(class_key)
    if not class_uri:
        return jsonify({"error": f"Unknown class key: {class_key}"}), 400

    try:
        if mode == "type":
            values = _fetch_subclasses_for_class(class_uri)
        else:
            values = _fetch_instances_for_class(class_uri)
    except KnowledgeBaseUnavailableError as e:
        print(f"Knowledge base unavailable while fetching class values for {class_key}/{mode}: {e}")
        return jsonify({"error": "Knowledge base unavailable. Please check Fuseki and retry."}), 503
    except Exception as e:
        print(f"Error fetching class values for {class_key}/{mode}: {e}")
        return jsonify({"error": "Could not fetch class values"}), 500

    return jsonify({"class_key": class_key, "class_uri": class_uri, "mode": mode, "values": values})


@app.route("/api/recommend", methods=["GET", "POST"])
def api_recommend():
    try:
        if request.method == "GET":
            tech = request.args.get("tech")
            scen = request.args.get("scen")
            if not tech or not scen:
                return jsonify({"error": "Missing 'tech' or 'scen' parameter"}), 400
            results = build_ui_payload(tech, scen)
            return jsonify({"results": results})

        data = request.get_json(force=True) or {}
        seeds = data.get("seeds", [])
        if not isinstance(seeds, list) or not all(isinstance(seed, dict) for seed in seeds):
            return jsonify({"error": "Seeds must be a list of objects"}), 400
        if not isinstance(data.get("target_type"), str):
            return jsonify({"error": "Invalid target_type"}), 400
        target_type = _resolve_catalog_key(data.get("target_type"))
        target_mode = "individual"
        if not seeds or not target_type:
            return jsonify({"error": "Missing seeds or target_type"}), 400

        catalog = _fetch_class_catalog()
        target_type_uri = catalog["key_to_uri"].get(target_type)
        if not target_type_uri:
            return jsonify({"error": f"Unknown target type: {target_type}"}), 400

        prepared_seeds = []
        for seed in seeds[:5]:
            if not isinstance(seed.get("type"), str) or not isinstance(seed.get("mode"), str):
                return jsonify({"error": "Invalid seed payload"}), 400
            try:
                importance = float(seed.get("importance", 2.0))
            except (TypeError, ValueError):
                return jsonify({"error": "Invalid seed importance"}), 400
            if not math.isfinite(importance) or importance < 0:
                return jsonify({"error": "Invalid seed importance"}), 400
            if not isinstance(seed.get("value_uri", ""), str):
                return jsonify({"error": "Invalid seed value URI"}), 400
            seed_type = _resolve_catalog_key(seed.get("type"))
            seed_mode = seed.get("mode")
            seed_type_uri = catalog["key_to_uri"].get(seed_type)
            if not seed_type or not seed_mode or not seed_type_uri:
                return jsonify({"error": "Invalid seed payload"}), 400

            value_uri = seed.get("value_uri") or ""
            if seed_mode == "class":
                value_uri = seed_type_uri
            elif seed_mode not in {"individual", "type"}:
                return jsonify({"error": f"Unsupported seed mode: {seed_mode}"}), 400

            prepared_seeds.append(
                {
                    "type": seed_type,
                    "type_uri": seed_type_uri,
                    "mode": seed_mode,
                    "label": seed.get("label", ""),
                    "value_uri": value_uri,
                    "importance": seed.get("importance", 2.0),
                }
            )

        results = build_flexible_ui_payload(
            {
                "seeds": prepared_seeds,
                "target_type": target_type,
                "target_type_uri": target_type_uri,
                "target_mode": target_mode,
            }
        )
        return jsonify({"results": results})
    except KnowledgeBaseUnavailableError as e:
        print("[/api/recommend] KNOWLEDGE BASE ERROR:", e)
        return jsonify({"error": "Knowledge base unavailable. Please check Fuseki and retry."}), 503
    except Exception as e:
        print("[/api/recommend] ERROR:", e)
        return jsonify({"error": "Internal error in recommender"}), 500


@app.route("/api/feedback", methods=["POST"])
def api_feedback():
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    tech = data.get("tech")
    scen = data.get("scen")
    query_title = data.get("query_title")
    center_label = data.get("center_label") or data.get("result_label")
    rating = data.get("rating")
    scores = data.get("scores", {})

    if not (center_label and rating):
        return jsonify({"error": "Missing required fields"}), 400

    # Minimal feedback record for later analysis.
    record = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "tech": tech,
        "scenario": scen,
        "query_title": query_title,
        "center_label": center_label,
        "rating": rating,
        "scores": scores,
    }

    try:
        with FEEDBACK_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:
        print("[/api/feedback] ERROR writing file:", e)
        return jsonify({"error": "Could not save feedback"}), 500

    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # Supports existing Render services that start this file directly.
    from waitress import serve

    serve(app, host="0.0.0.0" if os.getenv("RENDER") else "127.0.0.1",
          port=int(os.getenv("PORT", "5000")), threads=1)
