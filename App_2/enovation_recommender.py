"""Flexible eNOVATION CBRN recommender for App_2."""

import logging
import os
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from rdflib import Graph as RDFGraph
from rdflib import Namespace, OWL, RDF, RDFS, URIRef

logger = logging.getLogger(__name__)

EN_NS = "http://www.semanticweb.org/eNOVATION-ontology#"
EN = Namespace(EN_NS)
FUSEKI_ENDPOINT = os.getenv("FUSEKI_ENDPOINT", "http://localhost:3030/enovation/sparql")
MAX_PATH_LENGTH = 4
LENGTH_DECAY_ALPHA = 0.4
INCLUDE_GLOBALLY_MISSING_IN_SCORE = False
SHOW_GLOBALLY_MISSING_IN_ANALYSIS = False
ALLOW_SAME_CLASS_REENTRY = False
ALLOW_SIBLING_CLASS_REENTRY = False
ALLOW_LOCAL_TBOX_FALLBACK = os.getenv("APP2_ALLOW_LOCAL_TBOX_FALLBACK", "1") == "1"
CLASS_URI_ALIASES = {
    f"{EN_NS}ResponceAction": f"{EN_NS}ResponseAction",
}
DISPLAY_LABEL_ALIASES = {
    "UCSC Catholic University of the Sacred Heart for the Fondazione Policlinico Gemelli": "UCSC Catholic University",
}
SEMANTIC_FAMILY_ORDER = [
    f"{EN_NS}TrainingCentre",
    f"{EN_NS}TrainingCourse",
    f"{EN_NS}Technology",
    f"{EN_NS}Incident",
    f"{EN_NS}ThreatAgent",
    f"{EN_NS}Scenario",
    f"{EN_NS}ResponseAction",
    f"{EN_NS}SOP",
    f"{EN_NS}Service",
    f"{EN_NS}Facility",
    f"{EN_NS}Standard",
    f"{EN_NS}Exercise",
    f"{EN_NS}CBRNNetwork",
    f"{EN_NS}TrainingMethod",
    f"{EN_NS}Audience",
    f"{EN_NS}TCDiscipline",
    f"{EN_NS}TCType",
    f"{EN_NS}Certificate",
    f"{EN_NS}DomainOfUse",
    f"{EN_NS}DecontaminationMethod",
    f"{EN_NS}Resource",
    f"{EN_NS}Organisation",
]

_GRAPH_CACHE: Optional[Dict[str, Any]] = None
_TBOX_CACHE: Optional[Dict[str, Any]] = None
_CRITERION_CACHE: Dict[Tuple[str, str, int], List[Dict[str, Any]]] = {}
_CRITERION_MATCH_CACHE: Dict[Tuple[str, Tuple[Any, ...]], Dict[str, List[Dict[str, Any]]]] = {}
_CRITERION_GLOBAL_SUPPORT_CACHE: Dict[Tuple[Tuple[Any, ...], str], bool] = {}
_URI_CACHE: Dict[str, Optional[str]] = {}


class KnowledgeBaseUnavailableError(RuntimeError):
    """Raised when Fuseki data cannot be read reliably for the current request."""


def run_sparql(query: str) -> Dict[str, Any]:
    headers = {"Accept": "application/sparql-results+json"}
    params = {"query": query}
    try:
        resp = requests.get(FUSEKI_ENDPOINT, params=params, headers=headers, timeout=60)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as exc:
        logger.warning("SPARQL request failed (%s).", type(exc).__name__)
        return {}


def sparql_escape_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _get_val(binding: Dict[str, Any], name: str, default: Optional[str] = None) -> Optional[str]:
    value = binding.get(name)
    return value.get("value", default) if value else default


def _require_sparql_bindings(
    payload: Dict[str, Any],
    query_name: str,
    *,
    non_empty: bool = False,
) -> List[Dict[str, Any]]:
    bindings = payload.get("results", {}).get("bindings")
    if bindings is None:
        raise KnowledgeBaseUnavailableError(f"Fuseki query failed or returned malformed data for {query_name}.")
    if non_empty and not bindings:
        raise KnowledgeBaseUnavailableError(f"Fuseki query returned no bindings for required dataset slice: {query_name}.")
    return bindings


def _local_name(uri: str) -> str:
    if "#" in uri:
        return uri.rsplit("#", 1)[-1]
    return uri.rsplit("/", 1)[-1]


def _canonical_class_uri(uri: str) -> str:
    return CLASS_URI_ALIASES.get(uri, uri)


def _humanize_local_name(name: str) -> str:
    out: List[str] = []
    prev_lower = False
    for ch in name.replace("_", " "):
        if ch.isupper() and prev_lower:
            out.append(" ")
        out.append(ch)
        prev_lower = ch.islower()
    return "".join(out).strip()


def _label_or_name(uri: str, explicit_label: Optional[str]) -> str:
    label = explicit_label or _humanize_local_name(_local_name(uri))
    return DISPLAY_LABEL_ALIASES.get(label, label)


def _normalize_label_lookup(label: str) -> str:
    return " ".join(label.split())


def get_uri_for_label(label: str) -> Optional[str]:
    if not label:
        return None
    if label in _URI_CACHE:
        return _URI_CACHE[label]

    normalized_label = _normalize_label_lookup(label)
    escaped = sparql_escape_literal(normalized_label)
    query = f"""
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    SELECT DISTINCT ?s WHERE {{
      ?s rdfs:label ?l .
      FILTER(LCASE(STR(?l)) = LCASE("{escaped}"))
    }} LIMIT 1
    """
    data = run_sparql(query)
    bindings = data.get("results", {}).get("bindings")
    if bindings:
        uri = bindings[0]["s"]["value"]
        _URI_CACHE[label] = uri
        return uri

    prefix = normalized_label.split("(", 1)[0].strip()
    if len(prefix) >= 5:
        escaped_prefix = sparql_escape_literal(prefix)
        query_prefix = f"""
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        SELECT DISTINCT ?s WHERE {{
          ?s rdfs:label ?l .
          FILTER(CONTAINS(LCASE(STR(?l)), LCASE("{escaped_prefix}")))
        }} LIMIT 1
        """
        data_prefix = run_sparql(query_prefix)
        bindings_prefix = data_prefix.get("results", {}).get("bindings")
        if bindings_prefix:
            uri = bindings_prefix[0]["s"]["value"]
            _URI_CACHE[label] = uri
            return uri

        if bindings is None and bindings_prefix is None:
            raise KnowledgeBaseUnavailableError(
                f"Fuseki query failed or returned malformed data for label lookup: {label}."
            )

    if bindings is None:
        raise KnowledgeBaseUnavailableError(
            f"Fuseki query failed or returned malformed data for label lookup: {label}."
        )

    return None


def _fetch_graph_cache() -> Dict[str, Any]:
    global _GRAPH_CACHE
    if _GRAPH_CACHE is not None:
        return _GRAPH_CACHE

    q_classes = f"""
    PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX owl:  <http://www.w3.org/2002/07/owl#>

    SELECT DISTINCT ?class ?label ?parent WHERE {{
      {{ ?class a owl:Class . }} UNION {{ ?class a rdfs:Class . }}
      FILTER(STRSTARTS(STR(?class), "{EN_NS}"))
      OPTIONAL {{
        ?class rdfs:label ?label .
        FILTER(LANG(?label) = "" || LANGMATCHES(LANG(?label), "en"))
      }}
      OPTIONAL {{
        ?class rdfs:subClassOf ?parent .
        FILTER(STRSTARTS(STR(?parent), "{EN_NS}"))
      }}
    }}
    """

    q_properties = f"""
    PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
    PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX owl:  <http://www.w3.org/2002/07/owl#>

    SELECT DISTINCT ?p ?label WHERE {{
      ?p a owl:ObjectProperty .
      FILTER(STRSTARTS(STR(?p), "{EN_NS}"))
      OPTIONAL {{
        ?p rdfs:label ?label .
        FILTER(LANG(?label) = "" || LANGMATCHES(LANG(?label), "en"))
      }}
    }}
    """

    q_inverse = f"""
    PREFIX owl: <http://www.w3.org/2002/07/owl#>
    SELECT DISTINCT ?p ?inv WHERE {{
      {{ ?p owl:inverseOf ?inv . }} UNION {{ ?inv owl:inverseOf ?p . }}
      FILTER(STRSTARTS(STR(?p), "{EN_NS}"))
      FILTER(STRSTARTS(STR(?inv), "{EN_NS}"))
    }}
    """

    q_individuals = f"""
    PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX owl:  <http://www.w3.org/2002/07/owl#>

    SELECT DISTINCT ?s ?label ?type WHERE {{
      ?s a owl:NamedIndividual ;
         a ?type .
      FILTER(STRSTARTS(STR(?s), "{EN_NS}"))
      FILTER(STRSTARTS(STR(?type), "{EN_NS}"))
      OPTIONAL {{
        ?s rdfs:label ?label .
        FILTER(LANG(?label) = "" || LANGMATCHES(LANG(?label), "en"))
      }}
    }}
    """

    q_triples = f"""
    PREFIX owl: <http://www.w3.org/2002/07/owl#>
    SELECT DISTINCT ?s ?p ?o WHERE {{
      ?s ?p ?o .
      ?p a owl:ObjectProperty .
      FILTER(STRSTARTS(STR(?p), "{EN_NS}"))
      FILTER(isIRI(?o))
      FILTER(STRSTARTS(STR(?s), "{EN_NS}"))
      FILTER(STRSTARTS(STR(?o), "{EN_NS}"))
    }}
    """

    class_data = run_sparql(q_classes)
    prop_data = run_sparql(q_properties)
    inverse_data = run_sparql(q_inverse)
    individual_data = run_sparql(q_individuals)
    triple_data = run_sparql(q_triples)

    class_bindings = _require_sparql_bindings(class_data, "graph classes", non_empty=True)
    prop_bindings = _require_sparql_bindings(prop_data, "graph properties", non_empty=True)
    inverse_bindings = _require_sparql_bindings(inverse_data, "graph inverse properties")
    individual_bindings = _require_sparql_bindings(individual_data, "graph individuals", non_empty=True)
    triple_bindings = _require_sparql_bindings(triple_data, "graph triples", non_empty=True)

    class_labels: Dict[str, str] = {}
    direct_parents: Dict[str, Set[str]] = defaultdict(set)
    for binding in class_bindings:
        class_uri = _canonical_class_uri(binding["class"]["value"])
        class_labels.setdefault(class_uri, _label_or_name(class_uri, _get_val(binding, "label")))
        parent_uri = _get_val(binding, "parent")
        if parent_uri:
            direct_parents[class_uri].add(_canonical_class_uri(parent_uri))
    for class_uri in list(class_labels):
        direct_parents.setdefault(class_uri, set())

    ancestors_map: Dict[str, Set[str]] = {}
    for class_uri in class_labels:
        ancestors = {class_uri}
        stack = list(direct_parents.get(class_uri, set()))
        while stack:
            parent = stack.pop()
            if parent in ancestors:
                continue
            ancestors.add(parent)
            stack.extend(direct_parents.get(parent, set()))
        ancestors_map[class_uri] = ancestors

    descendants: Dict[str, Set[str]] = {class_uri: set() for class_uri in class_labels}
    for class_uri, ancestors in ancestors_map.items():
        for ancestor in ancestors:
            if ancestor in descendants:
                descendants[ancestor].add(class_uri)

    class_depth_map = {class_uri: max(0, len(ancestors) - 1) for class_uri, ancestors in ancestors_map.items()}

    inverse_map: Dict[str, str] = {}
    for binding in inverse_bindings:
        prop_uri = binding["p"]["value"]
        inv_uri = binding["inv"]["value"]
        inverse_map[prop_uri] = inv_uri
        inverse_map[inv_uri] = prop_uri

    properties: Dict[str, Dict[str, Any]] = {}
    for binding in prop_bindings:
        prop_uri = binding["p"]["value"]
        prop = properties.setdefault(
            prop_uri,
            {
                "uri": prop_uri,
                "label": _label_or_name(prop_uri, _get_val(binding, "label")),
                "inverse": inverse_map.get(prop_uri),
            },
        )

    individuals: Dict[str, Dict[str, Any]] = {}
    for binding in individual_bindings:
        ind_uri = binding["s"]["value"]
        ind = individuals.setdefault(
            ind_uri,
            {
                "uri": ind_uri,
                "label": _label_or_name(ind_uri, _get_val(binding, "label")),
                "direct_types": set(),
                "all_types": set(),
            },
        )
        type_uri = _canonical_class_uri(binding["type"]["value"])
        if type_uri in class_labels:
            ind["direct_types"].add(type_uri)

    for ind in individuals.values():
        all_types: Set[str] = set()
        for direct_type in ind["direct_types"]:
            all_types.update(ancestors_map.get(direct_type, {direct_type}))
        ind["all_types"] = all_types

    observed_direct_types_by_type: Dict[str, Set[str]] = defaultdict(set)
    for class_uri in class_labels:
        observed_direct_types_by_type[class_uri].add(class_uri)
    for ind in individuals.values():
        direct_types = set(ind["direct_types"])
        if not direct_types:
            continue
        for class_uri in ind["all_types"]:
            compatible_direct_types = {
                direct_type
                for direct_type in direct_types
                if class_uri in ancestors_map.get(direct_type, {direct_type})
            }
            if compatible_direct_types:
                observed_direct_types_by_type[class_uri].update(compatible_direct_types)

    individual_uris = set(individuals)
    forward_adj: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
    reverse_adj: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
    connected_individuals: Set[str] = set()

    for binding in triple_bindings:
        subj = binding["s"]["value"]
        prop = binding["p"]["value"]
        obj = binding["o"]["value"]
        if subj not in individual_uris or obj not in individual_uris:
            continue
        forward_adj[subj][prop].add(obj)
        reverse_adj[obj][prop].add(subj)
        connected_individuals.add(subj)
        connected_individuals.add(obj)

    adjacency: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for subj, props in forward_adj.items():
        for prop_uri, targets in props.items():
            prop_label = properties.get(prop_uri, {}).get("label", _humanize_local_name(_local_name(prop_uri)))
            inverse_uri = properties.get(prop_uri, {}).get("inverse")
            inverse_label = properties.get(inverse_uri, {}).get("label") if inverse_uri else None
            for obj in sorted(targets):
                adjacency[subj].append(
                    {
                        "neighbor": obj,
                        "property": prop_uri,
                        "traversal_direction": "forward",
                        "display_label": prop_label,
                        "display_direction": "forward",
                    }
                )
                adjacency[obj].append(
                    {
                        "neighbor": subj,
                        "property": prop_uri,
                        "traversal_direction": "reverse",
                        "display_label": inverse_label or prop_label,
                        "display_direction": "forward" if inverse_label else "reverse",
                    }
                )

    for node_uri in list(adjacency):
        adjacency[node_uri].sort(
            key=lambda edge: (
                edge["display_label"].lower(),
                individuals.get(edge["neighbor"], {}).get("label", edge["neighbor"]).lower(),
                edge["neighbor"],
            )
        )

    _GRAPH_CACHE = {
        "class_labels": class_labels,
        "direct_parents": direct_parents,
        "ancestors": ancestors_map,
        "descendants": descendants,
        "class_depth": class_depth_map,
        "properties": properties,
        "individuals": individuals,
        "forward_adj": {node: {prop: sorted(targets) for prop, targets in props.items()} for node, props in forward_adj.items()},
        "reverse_adj": {node: {prop: sorted(sources) for prop, sources in props.items()} for node, props in reverse_adj.items()},
        "adjacency": {node: edges for node, edges in adjacency.items()},
        "connected_individuals": connected_individuals,
        "observed_direct_types_by_type": {
            class_uri: set(class_set) for class_uri, class_set in observed_direct_types_by_type.items()
        },
    }
    return _GRAPH_CACHE


def _class_label(class_uri: str, graph: Dict[str, Any]) -> str:
    return graph["class_labels"].get(class_uri, _humanize_local_name(_local_name(class_uri)))


def _node_label(node_uri: str, graph: Dict[str, Any]) -> str:
    label = graph["individuals"].get(node_uri, {}).get("label", _humanize_local_name(_local_name(node_uri)))
    return DISPLAY_LABEL_ALIASES.get(label, label)


def _is_subclass_of(class_uri: str, ancestor_uri: str, graph: Dict[str, Any]) -> bool:
    return ancestor_uri in graph["ancestors"].get(class_uri, {class_uri})


def _members_of_class(class_uri: str, graph: Dict[str, Any]) -> List[str]:
    members = []
    for node_uri, data in graph["individuals"].items():
        if class_uri in data["all_types"] and node_uri in graph["connected_individuals"]:
            members.append(node_uri)
    members.sort(key=lambda uri: _node_label(uri, graph).lower())
    return members


def _pick_most_specific_class(node_uri: str, selected_class_uri: str, graph: Dict[str, Any]) -> str:
    direct_types = [
        t
        for t in graph["individuals"].get(node_uri, {}).get("direct_types", set())
        if _is_subclass_of(t, selected_class_uri, graph)
    ]
    if not direct_types:
        return selected_class_uri
    return max(direct_types, key=lambda class_uri: graph["class_depth"].get(class_uri, 0))


def _seed_start_classes_for_individual(node_uri: str, selected_class_uri: str, graph: Dict[str, Any]) -> List[str]:
    direct_types = sorted(
        (
            class_uri
            for class_uri in graph["individuals"].get(node_uri, {}).get("direct_types", set())
            if _is_subclass_of(class_uri, selected_class_uri, graph)
        ),
        key=lambda class_uri: (
            -graph["class_depth"].get(class_uri, 0),
            _class_label(class_uri, graph).lower(),
            class_uri,
        ),
    )
    start_classes: List[str] = [selected_class_uri]
    for class_uri in direct_types:
        if class_uri not in start_classes:
            start_classes.append(class_uri)
    return start_classes


def _pick_node_class(node_uri: str, graph: Dict[str, Any]) -> str:
    direct_types = list(graph["individuals"].get(node_uri, {}).get("direct_types", set()))
    if direct_types:
        return max(direct_types, key=lambda class_uri: graph["class_depth"].get(class_uri, 0))
    all_types = list(graph["individuals"].get(node_uri, {}).get("all_types", set()))
    if all_types:
        return max(all_types, key=lambda class_uri: graph["class_depth"].get(class_uri, 0))
    return ""


def _semantic_family_class(class_uri: str, graph: Dict[str, Any]) -> str:
    if not class_uri:
        return ""

    ancestors = graph["ancestors"].get(class_uri, {class_uri})
    for family_uri in SEMANTIC_FAMILY_ORDER:
        if family_uri in ancestors:
            return family_uri
    return class_uri


def _would_reenter_semantic_family(family_history: Tuple[str, ...], next_family: str) -> bool:
    if not next_family or not family_history:
        return False
    if next_family == family_history[-1]:
        return False
    return next_family in family_history


def _classes_conflict_in_path(
    left_class: str,
    right_class: str,
    ancestors_map: Dict[str, Set[str]],
    direct_parents_map: Dict[str, Set[str]],
) -> bool:
    if not left_class or not right_class:
        return False
    if left_class == right_class:
        return not ALLOW_SAME_CLASS_REENTRY

    left_ancestors = ancestors_map.get(left_class, {left_class})
    right_ancestors = ancestors_map.get(right_class, {right_class})

    # Never allow re-entering the same ancestor/descendant branch.
    if left_class in right_ancestors or right_class in left_ancestors:
        return True

    left_parents = direct_parents_map.get(left_class, set())
    right_parents = direct_parents_map.get(right_class, set())
    if left_parents and right_parents and left_parents.intersection(right_parents):
        return not ALLOW_SIBLING_CLASS_REENTRY

    return False


def _would_reenter_class_branch(
    class_history: Tuple[str, ...],
    next_class: str,
    ancestors_map: Dict[str, Set[str]],
    direct_parents_map: Dict[str, Set[str]],
) -> bool:
    if not next_class or not class_history:
        return False
    return any(
        _classes_conflict_in_path(previous_class, next_class, ancestors_map, direct_parents_map)
        for previous_class in class_history
        if previous_class
    )


def _step_token(step: Dict[str, Any]) -> str:
    token = step["display_label"]
    if step["display_direction"] == "reverse":
        token = f"{token}^-1"
    return token


def _path_signature(start_class: str, steps: List[Dict[str, Any]], graph: Dict[str, Any]) -> str:
    parts = [_class_label(start_class, graph)]
    current_class = start_class
    for step in steps:
        parts.append(_step_token(step))
        current_class = step["target_class"]
        parts.append(_class_label(current_class, graph))
    return " -> ".join(parts)


def _canonical_traversal_options(step: Dict[str, Any], graph: Dict[str, Any]) -> Tuple[Tuple[str, str], ...]:
    """Treat direct and inverse assertions as one semantic traversal family.

    We keep both options traversable in the template so recall is preserved even
    if only one orientation is asserted for a given node pair.
    """
    property_uri = step["traversal_property"]
    traversal_direction = step["traversal_direction"]
    options = {(property_uri, traversal_direction)}

    inverse_uri = graph["properties"].get(property_uri, {}).get("inverse")
    if inverse_uri:
        inverse_direction = "reverse" if traversal_direction == "forward" else "forward"
        options.add((inverse_uri, inverse_direction))

    return tuple(sorted(options))


def _path_signature_key(start_class: str, steps: List[Dict[str, Any]], graph: Dict[str, Any]) -> Tuple[Any, ...]:
    key: List[Any] = [start_class]
    for step in steps:
        key.append(
            (
                _canonical_traversal_options(step, graph),
                step["target_class"],
            )
        )
    return tuple(key)


def _node(value: str) -> Dict[str, Any]:
    return {"kind": "node", "label": value}


def _pred(value: str, direction: str) -> Dict[str, Any]:
    return {"kind": "pred", "label": value, "dir": direction}


def _render_path_tokens(path_steps: List[Dict[str, Any]], graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not path_steps:
        return []
    rendered = [_node(_node_label(path_steps[0]["from_node"], graph))]
    for step in path_steps:
        rendered.append(_pred(step["display_label"], step["display_direction"]))
        rendered.append(_node(_node_label(step["to_node"], graph)))
    return rendered


def _render_explanation_text(rendered_steps: List[Dict[str, Any]]) -> str:
    if not rendered_steps:
        return ""
    parts = [rendered_steps[0]["label"]]
    for idx in range(1, len(rendered_steps), 2):
        if idx + 1 >= len(rendered_steps):
            break
        pred = rendered_steps[idx]["label"]
        node = rendered_steps[idx + 1]["label"]
        parts.append(pred)
        parts.append(node)
    return " ".join(part for part in parts if part)


def _path_score(length: int) -> float:
    if length <= 0:
        return 0.0
    return LENGTH_DECAY_ALPHA ** (length - 1)


def _ontology_path() -> Path:
    return Path(__file__).resolve().parents[1] / "ontology.ttl"


def _first_graph_label(graph: RDFGraph, uri: URIRef) -> str:
    for obj in graph.objects(uri, RDFS.label):
        text = str(obj).strip()
        if text:
            return text
    return _humanize_local_name(_local_name(str(uri)))


def _rdf_list_members(graph: RDFGraph, head: Any) -> List[URIRef]:
    members: List[URIRef] = []
    current = head
    visited: Set[Any] = set()
    while current and current != RDF.nil and current not in visited:
        visited.add(current)
        first = next(graph.objects(current, RDF.first), None)
        if isinstance(first, URIRef):
            members.append(first)
        current = next(graph.objects(current, RDF.rest), None)
    return members


def _expand_class_expr(graph: RDFGraph, expr: Any) -> List[URIRef]:
    if isinstance(expr, URIRef):
        return [expr]
    union = next(graph.objects(expr, OWL.unionOf), None)
    if union is not None:
        return [member for member in _rdf_list_members(graph, union) if isinstance(member, URIRef)]
    return []


def _build_tbox_maps(
    classes: Set[str],
    class_labels: Dict[str, str],
    direct_parents: Dict[str, Set[str]],
    properties: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    for class_uri in classes:
        direct_parents.setdefault(class_uri, set())
        class_labels.setdefault(class_uri, _humanize_local_name(_local_name(class_uri)))

    ancestors_map: Dict[str, Set[str]] = {}
    for class_uri in classes:
        ancestors = {class_uri}
        stack = list(direct_parents.get(class_uri, set()))
        while stack:
            parent_uri = stack.pop()
            if parent_uri in ancestors:
                continue
            ancestors.add(parent_uri)
            stack.extend(direct_parents.get(parent_uri, set()))
        ancestors_map[class_uri] = ancestors

    descendants_map: Dict[str, Set[str]] = {class_uri: set() for class_uri in classes}
    for class_uri, ancestors in ancestors_map.items():
        for ancestor_uri in ancestors:
            if ancestor_uri in descendants_map:
                descendants_map[ancestor_uri].add(class_uri)

    class_depth_map = {class_uri: max(0, len(ancestors) - 1) for class_uri, ancestors in ancestors_map.items()}

    properties_by_domain: Dict[str, List[str]] = defaultdict(list)
    for prop_uri, meta in properties.items():
        for domain_uri in meta.get("domains", ()):
            properties_by_domain[domain_uri].append(prop_uri)

    for domain_uri in properties_by_domain:
        properties_by_domain[domain_uri] = sorted(
            set(properties_by_domain[domain_uri]),
            key=lambda uri: (properties.get(uri, {}).get("label", uri).lower(), uri),
        )

    return {
        "class_labels": class_labels,
        "direct_parents": {uri: set(parents) for uri, parents in direct_parents.items()},
        "ancestors": ancestors_map,
        "descendants": descendants_map,
        "class_depth": class_depth_map,
        "properties": properties,
        "properties_by_domain": dict(properties_by_domain),
    }


def _fetch_tbox_cache_from_fuseki() -> Optional[Dict[str, Any]]:
    required_property_uris = {
        f"{EN_NS}usesTechnology",
        f"{EN_NS}providesTrainingCourse",
        f"{EN_NS}trainsOnTechnology",
        f"{EN_NS}usesSOP",
        f"{EN_NS}isSOPFollowedBy",
        f"{EN_NS}isResponseActionOf",
        f"{EN_NS}isBasedOnIncident",
        f"{EN_NS}involvesThreat",
        f"{EN_NS}adressesThreat",
        f"{EN_NS}connectsWithNetwork",
        f"{EN_NS}hasFacility",
    }

    q_classes = f"""
    PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX owl:  <http://www.w3.org/2002/07/owl#>

    SELECT DISTINCT ?class ?label ?parent WHERE {{
      {{ ?class a owl:Class . }} UNION {{ ?class a rdfs:Class . }}
      FILTER(STRSTARTS(STR(?class), "{EN_NS}"))
      OPTIONAL {{
        ?class rdfs:label ?label .
        FILTER(LANG(?label) = "" || LANGMATCHES(LANG(?label), "en"))
      }}
      OPTIONAL {{
        ?class rdfs:subClassOf ?parent .
        FILTER(isIRI(?parent))
        FILTER(STRSTARTS(STR(?parent), "{EN_NS}"))
      }}
    }}
    """

    q_properties = f"""
    PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX owl:  <http://www.w3.org/2002/07/owl#>

    SELECT DISTINCT ?p ?label ?inv ?domain ?range WHERE {{
      ?p a owl:ObjectProperty .
      FILTER(STRSTARTS(STR(?p), "{EN_NS}"))
      OPTIONAL {{
        ?p rdfs:label ?label .
        FILTER(LANG(?label) = "" || LANGMATCHES(LANG(?label), "en"))
      }}
      OPTIONAL {{
        {{ ?p owl:inverseOf ?inv . }} UNION {{ ?inv owl:inverseOf ?p . }}
        FILTER(STRSTARTS(STR(?inv), "{EN_NS}"))
      }}
      OPTIONAL {{
        ?p rdfs:domain ?domainExpr .
        {{
          FILTER(isIRI(?domainExpr))
          BIND(?domainExpr AS ?domain)
        }} UNION {{
          ?domainExpr owl:unionOf/rdf:rest*/rdf:first ?domain .
        }}
        FILTER(STRSTARTS(STR(?domain), "{EN_NS}"))
      }}
      OPTIONAL {{
        ?p rdfs:range ?rangeExpr .
        {{
          FILTER(isIRI(?rangeExpr))
          BIND(?rangeExpr AS ?range)
        }} UNION {{
          ?rangeExpr owl:unionOf/rdf:rest*/rdf:first ?range .
        }}
        FILTER(STRSTARTS(STR(?range), "{EN_NS}"))
      }}
    }}
    """

    class_data = run_sparql(q_classes)
    prop_data = run_sparql(q_properties)
    class_bindings = _require_sparql_bindings(class_data, "tbox classes", non_empty=True)
    prop_bindings = _require_sparql_bindings(prop_data, "tbox properties", non_empty=True)

    classes: Set[str] = set()
    class_labels: Dict[str, str] = {}
    direct_parents: Dict[str, Set[str]] = defaultdict(set)
    for binding in class_bindings:
        class_uri = _canonical_class_uri(binding["class"]["value"])
        classes.add(class_uri)
        class_labels.setdefault(class_uri, _label_or_name(class_uri, _get_val(binding, "label")))
        parent_uri = _get_val(binding, "parent")
        if parent_uri:
            direct_parents[class_uri].add(_canonical_class_uri(parent_uri))

    properties: Dict[str, Dict[str, Any]] = {}
    inverse_map: Dict[str, str] = {}
    for binding in prop_bindings:
        prop_uri = binding["p"]["value"]
        label = _label_or_name(prop_uri, _get_val(binding, "label"))
        meta = properties.setdefault(
            prop_uri,
            {
                "uri": prop_uri,
                "label": label,
                "inverse": None,
                "domains": set(),
                "ranges": set(),
            },
        )
        inv_uri = _get_val(binding, "inv")
        if inv_uri:
            inverse_map[prop_uri] = inv_uri
            inverse_map[inv_uri] = prop_uri
        domain_uri = _get_val(binding, "domain")
        if domain_uri:
            canon_domain = _canonical_class_uri(domain_uri)
            if canon_domain in classes:
                meta["domains"].add(canon_domain)
        range_uri = _get_val(binding, "range")
        if range_uri:
            canon_range = _canonical_class_uri(range_uri)
            if canon_range in classes:
                meta["ranges"].add(canon_range)

    filtered_properties: Dict[str, Dict[str, Any]] = {}
    for prop_uri, meta in properties.items():
        if not meta["domains"] or not meta["ranges"]:
            continue
        filtered_properties[prop_uri] = {
            "uri": prop_uri,
            "label": meta["label"],
            "inverse": inverse_map.get(prop_uri),
            "domains": tuple(sorted(meta["domains"], key=lambda uri: class_labels.get(uri, uri).lower())),
            "ranges": tuple(sorted(meta["ranges"], key=lambda uri: class_labels.get(uri, uri).lower())),
        }
    for prop_uri, meta in properties.items():
        if prop_uri in filtered_properties:
            continue
        inverse_uri = inverse_map.get(prop_uri)
        if not inverse_uri or inverse_uri not in filtered_properties:
            continue
        filtered_properties[prop_uri] = {
            "uri": prop_uri,
            "label": meta["label"],
            "inverse": inverse_uri,
            "domains": tuple(filtered_properties[inverse_uri]["ranges"]),
            "ranges": tuple(filtered_properties[inverse_uri]["domains"]),
        }

    if not filtered_properties:
        return None
    if not required_property_uris.issubset(set(filtered_properties)):
        return None

    return _build_tbox_maps(classes, class_labels, direct_parents, filtered_properties)


def _fetch_tbox_cache_from_local() -> Dict[str, Any]:
    rdf_graph = RDFGraph()
    rdf_graph.parse(_ontology_path(), format="turtle")

    classes: Set[str] = set()
    class_labels: Dict[str, str] = {}
    direct_parents: Dict[str, Set[str]] = defaultdict(set)

    for cls in rdf_graph.subjects(RDF.type, OWL.Class):
        if isinstance(cls, URIRef) and str(cls).startswith(EN_NS):
            class_uri = _canonical_class_uri(str(cls))
            classes.add(class_uri)
            class_labels.setdefault(class_uri, _first_graph_label(rdf_graph, cls))
    for cls in rdf_graph.subjects(RDF.type, RDFS.Class):
        if isinstance(cls, URIRef) and str(cls).startswith(EN_NS):
            class_uri = _canonical_class_uri(str(cls))
            classes.add(class_uri)
            class_labels.setdefault(class_uri, _first_graph_label(rdf_graph, cls))

    for cls, parent in rdf_graph.subject_objects(RDFS.subClassOf):
        if not (isinstance(cls, URIRef) and isinstance(parent, URIRef)):
            continue
        cls_uri = _canonical_class_uri(str(cls))
        parent_uri = _canonical_class_uri(str(parent))
        if cls_uri not in classes or parent_uri not in classes:
            continue
        direct_parents[cls_uri].add(parent_uri)

    inverse_map: Dict[str, str] = {}
    for left, right in rdf_graph.subject_objects(OWL.inverseOf):
        if not (isinstance(left, URIRef) and isinstance(right, URIRef)):
            continue
        left_uri = str(left)
        right_uri = str(right)
        if not (left_uri.startswith(EN_NS) and right_uri.startswith(EN_NS)):
            continue
        left_uri = _canonical_class_uri(left_uri)
        right_uri = _canonical_class_uri(right_uri)
        inverse_map[left_uri] = right_uri
        inverse_map[right_uri] = left_uri

    properties: Dict[str, Dict[str, Any]] = {}
    for prop in rdf_graph.subjects(RDF.type, OWL.ObjectProperty):
        if not isinstance(prop, URIRef):
            continue
        prop_uri = str(prop)
        if not prop_uri.startswith(EN_NS):
            continue

        domain_classes: Set[str] = set()
        range_classes: Set[str] = set()
        for domain_expr in rdf_graph.objects(prop, RDFS.domain):
            for domain_uri in _expand_class_expr(rdf_graph, domain_expr):
                domain_str = _canonical_class_uri(str(domain_uri))
                if domain_str in classes:
                    domain_classes.add(domain_str)
        for range_expr in rdf_graph.objects(prop, RDFS.range):
            for range_uri in _expand_class_expr(rdf_graph, range_expr):
                range_str = _canonical_class_uri(str(range_uri))
                if range_str in classes:
                    range_classes.add(range_str)

        if not domain_classes or not range_classes:
            continue

        properties[prop_uri] = {
            "uri": prop_uri,
            "label": _first_graph_label(rdf_graph, prop),
            "inverse": inverse_map.get(prop_uri),
            "domains": tuple(sorted(domain_classes, key=lambda uri: class_labels.get(uri, uri).lower())),
            "ranges": tuple(sorted(range_classes, key=lambda uri: class_labels.get(uri, uri).lower())),
        }
    for prop in rdf_graph.subjects(RDF.type, OWL.ObjectProperty):
        if not isinstance(prop, URIRef):
            continue
        prop_uri = str(prop)
        if not prop_uri.startswith(EN_NS) or prop_uri in properties:
            continue
        inverse_uri = inverse_map.get(prop_uri)
        if not inverse_uri or inverse_uri not in properties:
            continue
        properties[prop_uri] = {
            "uri": prop_uri,
            "label": _first_graph_label(rdf_graph, prop),
            "inverse": inverse_uri,
            "domains": tuple(properties[inverse_uri]["ranges"]),
            "ranges": tuple(properties[inverse_uri]["domains"]),
        }
    return _build_tbox_maps(classes, class_labels, direct_parents, properties)


def _fetch_tbox_cache() -> Dict[str, Any]:
    global _TBOX_CACHE
    if _TBOX_CACHE is not None:
        return _TBOX_CACHE

    fuseki_tbox = _fetch_tbox_cache_from_fuseki()
    if fuseki_tbox is not None:
        _TBOX_CACHE = fuseki_tbox
        return _TBOX_CACHE

    if ALLOW_LOCAL_TBOX_FALLBACK:
        logger.warning("Fuseki TBox was incomplete; falling back to the local ontology.ttl snapshot.")
        _TBOX_CACHE = _fetch_tbox_cache_from_local()
        return _TBOX_CACHE

    raise KnowledgeBaseUnavailableError(
        "Could not build a complete TBox from Fuseki. Local TBox fallback is disabled."
    )
    return _TBOX_CACHE


def _tbox_class_label(class_uri: str, tbox: Dict[str, Any]) -> str:
    return tbox["class_labels"].get(class_uri, _humanize_local_name(_local_name(class_uri)))


def _tbox_is_subclass_of(class_uri: str, ancestor_uri: str, tbox: Dict[str, Any]) -> bool:
    return ancestor_uri in tbox["ancestors"].get(class_uri, {class_uri})


def _schema_family_class(class_uri: str, tbox: Dict[str, Any]) -> str:
    if not class_uri:
        return ""
    ancestors = tbox["ancestors"].get(class_uri, {class_uri})
    for family_uri in SEMANTIC_FAMILY_ORDER:
        if family_uri in ancestors:
            return family_uri
    return class_uri


def _criterion_matching_options(property_uri: str, tbox: Dict[str, Any]) -> Tuple[Tuple[str, str], ...]:
    options = {(property_uri, "forward")}
    inverse_uri = tbox["properties"].get(property_uri, {}).get("inverse")
    if inverse_uri:
        options.add((inverse_uri, "reverse"))
    return tuple(sorted(options))


def _criterion_signature(
    start_class: str,
    steps: List[Dict[str, Any]],
    tbox: Dict[str, Any],
    start_label: Optional[str] = None,
) -> str:
    parts = [start_label or _tbox_class_label(start_class, tbox)]
    current_class = start_class
    for step in steps:
        parts.append(step["property_label"])
        current_class = step["target_class"]
        parts.append(_tbox_class_label(current_class, tbox))
    return " -> ".join(parts)


def _criterion_key(start_class: str, steps: List[Dict[str, Any]]) -> Tuple[Any, ...]:
    key: List[Any] = [start_class]
    for step in steps:
        key.append((step["property_uri"], step["target_class"]))
    return tuple(key)


def _schema_steps_for_class(current_class: str, target_root: str, tbox: Dict[str, Any], graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    applicable_steps: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()
    effective_classes = set(graph.get("observed_direct_types_by_type", {}).get(current_class, {current_class}))
    effective_classes.add(current_class)
    schema_source_classes: Set[str] = set()
    for effective_class in effective_classes:
        if effective_class not in tbox["class_labels"]:
            continue
        for candidate_class in tbox["ancestors"].get(effective_class, {effective_class}):
            schema_source_classes.add(candidate_class)

    for ancestor_uri in sorted(schema_source_classes, key=lambda uri: tbox["class_depth"].get(uri, 0), reverse=True):
        for property_uri in tbox["properties_by_domain"].get(ancestor_uri, []):
            prop_meta = tbox["properties"].get(property_uri, {})
            for range_class in prop_meta.get("ranges", ()):
                matching_options = _criterion_matching_options(property_uri, tbox)
                property_label = prop_meta.get("label", _humanize_local_name(_local_name(property_uri)))
                key = (property_uri, range_class)
                if key in seen:
                    continue
                seen.add(key)
                applicable_steps.append(
                    {
                        "property_uri": property_uri,
                        "property_label": property_label,
                        "target_class": range_class,
                        "matching_options": matching_options,
                    }
                )

    applicable_steps.sort(
        key=lambda step: (
            step["property_label"].lower(),
            _tbox_class_label(step["target_class"], tbox).lower(),
            step["target_class"],
        )
    )
    return applicable_steps


def _extract_seed_criteria(
    start_class: str,
    target_root: str,
    tbox: Dict[str, Any],
    graph: Dict[str, Any],
    max_length: int = MAX_PATH_LENGTH,
) -> List[Dict[str, Any]]:
    cache_key = (start_class, target_root, max_length)
    if cache_key in _CRITERION_CACHE:
        return _CRITERION_CACHE[cache_key]

    criteria_by_key: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    initial_class_history = (start_class,) if start_class else tuple()
    queue: deque[Tuple[str, List[Dict[str, Any]], Tuple[str, ...]]] = deque()
    queue.append((start_class, [], initial_class_history))

    while queue:
        current_class, steps, class_history = queue.popleft()
        depth = len(steps)

        if depth > 0 and _tbox_is_subclass_of(current_class, target_root, tbox):
            key = _criterion_key(start_class, steps)
            if key not in criteria_by_key:
                criteria_by_key[key] = {
                    "criterion_key": key,
                    "start_class": start_class,
                    "target_root": target_root,
                    "final_class": current_class,
                    "length": depth,
                    "weight_raw": _path_score(depth),
                    "steps": steps,
                    "signature": _criterion_signature(start_class, steps, tbox),
                }
            continue

        if depth >= max_length:
            continue

        for schema_step in _schema_steps_for_class(current_class, target_root, tbox, graph):
            next_class = schema_step["target_class"]
            next_is_target = _tbox_is_subclass_of(next_class, target_root, tbox)
            next_can_specialize_to_target = (not next_is_target) and _tbox_is_subclass_of(target_root, next_class, tbox)
            terminal_class = target_root if next_can_specialize_to_target else next_class

            if _would_reenter_class_branch(
                class_history,
                terminal_class,
                tbox["ancestors"],
                tbox["direct_parents"],
            ):
                continue

            if next_is_target or next_can_specialize_to_target:
                terminal_steps = steps + [
                    {
                        "property_uri": schema_step["property_uri"],
                        "property_label": schema_step["property_label"],
                        "matching_options": schema_step["matching_options"],
                        "target_class": terminal_class,
                    }
                ]
                key = _criterion_key(start_class, terminal_steps)
                if key not in criteria_by_key:
                    criteria_by_key[key] = {
                        "criterion_key": key,
                        "start_class": start_class,
                        "target_root": target_root,
                        "final_class": terminal_class,
                        "length": len(terminal_steps),
                        "weight_raw": _path_score(len(terminal_steps)),
                        "steps": terminal_steps,
                        "signature": _criterion_signature(start_class, terminal_steps, tbox),
                    }
                continue

            next_steps = steps + [
                {
                    "property_uri": schema_step["property_uri"],
                    "property_label": schema_step["property_label"],
                    "matching_options": schema_step["matching_options"],
                    "target_class": next_class,
                }
            ]

            next_class_history = class_history + ((next_class,) if next_class else tuple())
            queue.append((next_class, next_steps, next_class_history))

    criteria = list(criteria_by_key.values())
    criteria.sort(
        key=lambda item: (
            item["length"],
            item["signature"].lower(),
        )
    )
    _CRITERION_CACHE[cache_key] = criteria
    return criteria


def _extract_seed_criteria_for_start_classes(
    start_classes: List[str],
    target_root: str,
    tbox: Dict[str, Any],
    graph: Dict[str, Any],
    max_length: int = MAX_PATH_LENGTH,
    canonical_start_class: Optional[str] = None,
    display_start_label: Optional[str] = None,
) -> List[Dict[str, Any]]:
    anchor_start_class = canonical_start_class or (start_classes[0] if start_classes else "")
    merged_criteria: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for start_class in start_classes:
        for criterion in _extract_seed_criteria(start_class, target_root, tbox, graph, max_length):
            canonical_key = _criterion_key(anchor_start_class, criterion["steps"])
            if canonical_key not in merged_criteria:
                merged_criteria[canonical_key] = {
                    **criterion,
                    "criterion_key": canonical_key,
                    "start_class": anchor_start_class,
                    "signature": _criterion_signature(
                        anchor_start_class,
                        criterion["steps"],
                        tbox,
                        start_label=display_start_label,
                    ),
                    "display_start_label": display_start_label,
                    "actual_start_classes": {criterion["start_class"]},
                }
            else:
                merged_criteria[canonical_key].setdefault("actual_start_classes", set()).add(criterion["start_class"])

    criteria = list(merged_criteria.values())
    criteria.sort(
        key=lambda item: (
            item["length"],
            item["signature"].lower(),
        )
    )
    return criteria


def _criterion_neighbors(node_uri: str, criterion_step: Dict[str, Any], graph: Dict[str, Any]) -> List[str]:
    neighbors: Set[str] = set()
    for property_uri, direction in criterion_step.get("matching_options", ()):
        if direction == "forward":
            neighbors.update(graph["forward_adj"].get(node_uri, {}).get(property_uri, []))
        else:
            neighbors.update(graph["reverse_adj"].get(node_uri, {}).get(property_uri, []))

    target_class = criterion_step["target_class"]
    return sorted(
        neighbor_uri
        for neighbor_uri in neighbors
        if target_class in graph["individuals"].get(neighbor_uri, {}).get("all_types", set())
    )


def _discover_criterion_matches_for_seed_node(seed_node: str, criterion: Dict[str, Any], graph: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    cache_key = (seed_node, criterion["criterion_key"])
    if cache_key in _CRITERION_MATCH_CACHE:
        return _CRITERION_MATCH_CACHE[cache_key]

    if criterion["start_class"] not in graph["individuals"].get(seed_node, {}).get("all_types", set()):
        _CRITERION_MATCH_CACHE[cache_key] = {}
        return {}

    discovered: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def dfs(current_node: str, step_index: int, visited_nodes: Set[str], path_steps: List[Dict[str, Any]]) -> None:
        if step_index >= len(criterion["steps"]):
            if criterion["target_root"] in graph["individuals"].get(current_node, {}).get("all_types", set()):
                discovered[current_node].append(
                    {
                        "seed_node": seed_node,
                        "target_node": current_node,
                        "steps": list(path_steps),
                        "length": len(path_steps),
                    }
                )
            return

        criterion_step = criterion["steps"][step_index]
        for neighbor_uri in _criterion_neighbors(current_node, criterion_step, graph):
            if neighbor_uri in visited_nodes:
                continue
            path_steps.append(
                {
                    "from_node": current_node,
                    "to_node": neighbor_uri,
                    "display_label": criterion_step["property_label"],
                    "display_direction": "forward",
                    "source_class": _pick_node_class(current_node, graph),
                    "target_class": criterion_step["target_class"],
                }
            )
            dfs(neighbor_uri, step_index + 1, visited_nodes | {neighbor_uri}, path_steps)
            path_steps.pop()

    dfs(seed_node, 0, {seed_node}, [])
    _CRITERION_MATCH_CACHE[cache_key] = {target_node: list(paths) for target_node, paths in discovered.items()}
    return _CRITERION_MATCH_CACHE[cache_key]


def _criterion_has_global_instance_support(criterion: Dict[str, Any], graph: Dict[str, Any]) -> bool:
    cache_key = (criterion["criterion_key"], criterion["target_root"])
    if cache_key in _CRITERION_GLOBAL_SUPPORT_CACHE:
        return _CRITERION_GLOBAL_SUPPORT_CACHE[cache_key]

    for seed_node in _members_of_class(criterion["start_class"], graph):
        discovered = _discover_criterion_matches_for_seed_node(seed_node, criterion, graph)
        if discovered:
            _CRITERION_GLOBAL_SUPPORT_CACHE[cache_key] = True
            return True

    _CRITERION_GLOBAL_SUPPORT_CACHE[cache_key] = False
    return False


def _summarize_criterion_paths(
    criterion_model: Dict[str, Any],
    target_node: str,
    target_paths: List[Dict[str, Any]],
    graph: Dict[str, Any],
) -> Dict[str, Any]:
    rendered_paths: List[List[Dict[str, Any]]] = []
    path_texts: Dict[Tuple[Tuple[str, str, str], ...], str] = {}
    for path in target_paths:
        rendered = _render_path_tokens(path["steps"], graph)
        key = tuple((item["kind"], item["label"], str(item.get("dir", ""))) for item in rendered)
        if key in path_texts:
            continue
        rendered_paths.append(rendered)
        path_texts[key] = _render_explanation_text(rendered)

    return {
        "signature": criterion_model["signature"],
        "length": criterion_model["length"],
        "path_count": criterion_model["path_counts"].get(target_node, 0),
        "normalized_path_count": criterion_model["normalized_scores"].get(target_node, 0.0),
        "path_weight": criterion_model["path_weight"],
        "contribution": criterion_model["path_weight"] * criterion_model["normalized_scores"].get(target_node, 0.0),
        "globally_missing": criterion_model["globally_missing"],
        "query_supported": criterion_model["query_supported"],
        "active_for_score": criterion_model["active_for_score"],
        "example_text": next(iter(path_texts.values()), ""),
        "paths": rendered_paths,
    }


def _score_seed_against_candidates_with_criteria(
    seed: Dict[str, Any],
    candidate_nodes: List[str],
    target_root: str,
    graph: Dict[str, Any],
    tbox: Dict[str, Any],
) -> Dict[str, Any]:
    candidate_set = set(candidate_nodes)
    if not candidate_set:
        return {
            "fit_scores": {},
            "criteria_models": [],
            "criterion_summaries": {},
            "has_active_criteria": False,
        }

    criteria = _extract_seed_criteria_for_start_classes(
        seed.get("criterion_start_classes", [seed["start_class"]]),
        target_root,
        tbox,
        graph,
        MAX_PATH_LENGTH,
        canonical_start_class=seed["start_class"],
        display_start_label=seed["type_label"],
    )
    if not criteria:
        return {
            "fit_scores": {},
            "criteria_models": [],
            "criterion_summaries": {},
            "has_active_criteria": False,
        }

    criterion_models: List[Dict[str, Any]] = []
    criterion_summaries: Dict[str, List[Dict[str, Any]]] = {}

    active_length_counts: Dict[int, int] = defaultdict(int)
    for criterion in criteria:
        path_counts: Dict[str, int] = {target_node: 0 for target_node in candidate_nodes}
        target_paths: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for seed_node in seed["seed_nodes"]:
            discovered = _discover_criterion_matches_for_seed_node(seed_node, criterion, graph)
            for target_node, paths in discovered.items():
                if target_node not in candidate_set:
                    continue
                path_counts[target_node] += len(paths)
                target_paths[target_node].extend(paths)

        max_count = max(path_counts.values(), default=0)
        normalized_scores = {
            target_node: (count / max_count if max_count > 0 else 0.0)
            for target_node, count in path_counts.items()
        }
        globally_missing = not _criterion_has_global_instance_support(criterion, graph)
        query_supported = max_count > 0
        active_for_score = INCLUDE_GLOBALLY_MISSING_IN_SCORE or not globally_missing
        if active_for_score:
            active_length_counts[criterion["length"]] += 1
        criterion_model = {
            **criterion,
            "signature": criterion.get("signature")
            or _criterion_signature(
                criterion["start_class"],
                criterion["steps"],
                tbox,
                start_label=criterion.get("display_start_label"),
            ),
            "path_counts": path_counts,
            "normalized_scores": normalized_scores,
            "globally_missing": globally_missing,
            "query_supported": query_supported,
            "active_for_score": active_for_score,
            "effective_weight_raw": 0.0,
            "path_weight": 0.0,
            "target_paths": {target_node: list(paths) for target_node, paths in target_paths.items()},
        }
        criterion_models.append(criterion_model)

    active_weight_raw_total = 0.0
    for criterion_model in criterion_models:
        if not criterion_model["active_for_score"]:
            continue
        same_length_count = active_length_counts.get(criterion_model["length"], 0)
        criterion_model["effective_weight_raw"] = (
            criterion_model["weight_raw"] / same_length_count if same_length_count else 0.0
        )
        active_weight_raw_total += criterion_model["effective_weight_raw"]

    for criterion_model in criterion_models:
        criterion_model["path_weight"] = (
            criterion_model["effective_weight_raw"] / active_weight_raw_total if active_weight_raw_total else 0.0
        )

    fit_scores: Dict[str, float] = {}
    for target_node in candidate_nodes:
        fit_scores[target_node] = sum(
            criterion_model["path_weight"] * criterion_model["normalized_scores"].get(target_node, 0.0)
            for criterion_model in criterion_models
        )

    for target_node in candidate_nodes:
        summaries: List[Dict[str, Any]] = []
        for criterion_model in criterion_models:
            target_paths = criterion_model["target_paths"].get(target_node, [])
            if not target_paths and not criterion_model["globally_missing"] and criterion_model["path_counts"].get(target_node, 0) <= 0:
                summaries.append(
                    {
                        "signature": criterion_model["signature"],
                        "length": criterion_model["length"],
                        "path_count": 0,
                        "normalized_path_count": 0.0,
                        "path_weight": criterion_model["path_weight"],
                        "contribution": 0.0,
                        "globally_missing": False,
                        "query_supported": criterion_model["query_supported"],
                        "active_for_score": criterion_model["active_for_score"],
                        "example_text": "",
                        "paths": [],
                    }
                )
                continue
            summaries.append(_summarize_criterion_paths(criterion_model, target_node, target_paths, graph))

        summaries.sort(
            key=lambda item: (
                -item["contribution"],
                -item["normalized_path_count"],
                item["length"],
                item["signature"].lower(),
            )
        )
        criterion_summaries[target_node] = summaries

    return {
        "fit_scores": fit_scores,
        "criteria_models": criterion_models,
        "criterion_summaries": criterion_summaries,
        "has_active_criteria": any(criterion_model["active_for_score"] for criterion_model in criterion_models),
    }


def _build_result_payload_from_criteria(
    result_uri: str,
    result_label: str,
    representative_node: str,
    prepared_seeds: List[Dict[str, Any]],
    seed_results: List[Dict[str, Any]],
    normalized_seed_weights: List[float],
    graph: Dict[str, Any],
    result_note: str = "",
) -> Dict[str, Any]:
    final_score = 0.0
    seed_fit_clusters: List[Dict[str, Any]] = []
    explanations_simple: List[Dict[str, Any]] = []
    meta_path_groups: List[Dict[str, Any]] = []
    graph_groups: List[Dict[str, Any]] = []

    for idx, seed in enumerate(prepared_seeds):
        seed_fit = seed_results[idx]["fit_scores"].get(representative_node, 0.0)
        final_score += normalized_seed_weights[idx] * seed_fit
        inactive_seed = not seed_results[idx].get("has_active_criteria", False)
        seed_fit_clusters.append(
            {
                "label": seed["fit_label"],
                "score_0_10": None if inactive_seed else round(seed_fit * 10.0, 1),
                "tooltip": (
                    f"{seed['tooltip']} | excluded from final score because all criteria are globally missing"
                    if inactive_seed
                    else seed["tooltip"]
                ),
                "inactive": inactive_seed,
            }
        )

        summaries = seed_results[idx]["criterion_summaries"].get(representative_node, [])
        if not summaries:
            continue

        meta_items: List[Dict[str, Any]] = []
        rendered_group_paths: List[List[Dict[str, Any]]] = []
        for summary in summaries:
            if summary["globally_missing"] and not SHOW_GLOBALLY_MISSING_IN_ANALYSIS:
                continue
            if summary["globally_missing"]:
                status = "globally missing"
            elif not summary["query_supported"]:
                status = "unsupported for query"
            elif summary["path_count"] > 0:
                status = "matched"
            else:
                status = "not matched here"
            meta_items.append(
                {
                    "signature": summary["signature"],
                    "length": summary["length"],
                    "path_count": summary["path_count"],
                    "normalized_path_count": round(summary["normalized_path_count"], 3),
                    "path_weight": round(summary["path_weight"], 3),
                    "contribution_0_10": round(summary["contribution"] * 10.0, 1),
                    "status": status,
                    "example_text": summary["example_text"],
                }
            )

            if summary["path_count"] > 0 and summary["example_text"]:
                explanations_simple.append(
                    {
                        "criterion": seed["fit_title"],
                        "text": summary["example_text"],
                        "entity": summary["signature"],
                    }
                )
            rendered_group_paths.extend(summary["paths"])

        if meta_items:
            meta_path_groups.append({"title": seed["fit_title"], "paths": meta_items})

        if rendered_group_paths:
            unique_paths: List[List[Dict[str, Any]]] = []
            seen_paths: Set[Tuple[Tuple[str, str, str], ...]] = set()
            for rendered_path in rendered_group_paths:
                key = tuple((item["kind"], item["label"], str(item.get("dir", ""))) for item in rendered_path)
                if key in seen_paths:
                    continue
                seen_paths.add(key)
                unique_paths.append(rendered_path)
            graph_groups.append({"title": seed["fit_title"], "paths": unique_paths})

    scores = {
        "final_score_0_1": final_score,
        "final_score_0_10": final_score * 10.0,
        "total_score": final_score * 10.0,
        "seed_fit_clusters": seed_fit_clusters,
    }

    return {
        "center_uri": result_uri,
        "center_label": result_label,
        "region": "",
        "result_note": result_note,
        "scores": scores,
        "metric_chips": [],
        "explanations_simple": explanations_simple,
        "meta_path_groups": meta_path_groups,
        "graph_groups": graph_groups,
        "graph_paths": [],
    }
def _prepare_seed(seed_payload: Dict[str, Any], graph: Dict[str, Any], index: int, duplicate_counts: Dict[str, int]) -> Optional[Dict[str, Any]]:
    type_uri = seed_payload.get("type_uri")
    mode = seed_payload.get("mode")
    if not type_uri or not mode:
        return None

    type_label = _class_label(type_uri, graph)
    value_uri = seed_payload.get("value_uri") or ""
    value_label = seed_payload.get("label") or ""

    if mode == "individual":
        if value_uri not in graph["individuals"]:
            return None
        seed_nodes = [value_uri]
        criterion_start_classes = _seed_start_classes_for_individual(value_uri, type_uri, graph)
        start_class = type_uri
        display_start_class = _pick_most_specific_class(value_uri, type_uri, graph)
        value_label = _node_label(value_uri, graph)
    elif mode == "type":
        selected_class_uri = value_uri or type_uri
        seed_nodes = _members_of_class(selected_class_uri, graph)
        criterion_start_classes = [selected_class_uri]
        start_class = selected_class_uri
        display_start_class = selected_class_uri
        value_label = _class_label(selected_class_uri, graph)
    elif mode == "class":
        seed_nodes = _members_of_class(type_uri, graph)
        criterion_start_classes = [type_uri]
        start_class = type_uri
        display_start_class = type_uri
        value_label = type_label
    else:
        return None

    if not seed_nodes:
        return None

    fit_label = f"{type_label} fit"
    if duplicate_counts.get(type_uri, 0) > 1:
        fit_label = f"{type_label} fit #{index + 1}"

    descriptor = value_label if mode != "class" else f"any {type_label} instance"
    return {
        "index": index,
        "type_uri": type_uri,
        "type_key": seed_payload.get("type"),
        "type_label": type_label,
        "mode": mode,
        "value_uri": value_uri,
        "value_label": value_label,
        "seed_nodes": seed_nodes,
        "start_class": start_class,
        "criterion_start_classes": criterion_start_classes,
        "display_start_class": display_start_class,
        "importance": float(seed_payload.get("importance", 2.0) or 2.0),
        "fit_label": fit_label,
        "fit_title": f"{fit_label} - {descriptor}",
        "tooltip": f"{type_label} / {mode} / {descriptor}",
    }


def build_flexible_ui_payload(query_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    graph = _fetch_graph_cache()
    tbox = _fetch_tbox_cache()

    target_type_uri = query_payload.get("target_type_uri")
    raw_seeds = query_payload.get("seeds", [])
    if not target_type_uri or not raw_seeds:
        return []

    duplicate_counts: Dict[str, int] = defaultdict(int)
    for seed in raw_seeds:
        if seed.get("type_uri"):
            duplicate_counts[seed["type_uri"]] += 1

    prepared_seeds = []
    for index, seed_payload in enumerate(raw_seeds[:5]):
        prepared = _prepare_seed(seed_payload, graph, index, duplicate_counts)
        if prepared:
            prepared_seeds.append(prepared)
    if not prepared_seeds:
        return []

    candidate_nodes = _members_of_class(target_type_uri, graph)
    if not candidate_nodes:
        return []

    seed_results = [
        _score_seed_against_candidates_with_criteria(seed, candidate_nodes, target_type_uri, graph, tbox)
        for seed in prepared_seeds
    ]
    normalized_seed_weights = [
        seed["importance"] if seed_results[idx].get("has_active_criteria") else 0.0
        for idx, seed in enumerate(prepared_seeds)
    ]
    total_importance = sum(normalized_seed_weights)
    normalized_seed_weights = [value / total_importance for value in normalized_seed_weights] if total_importance else [0.0 for _ in prepared_seeds]

    individual_scores = {
        node_uri: sum(
            normalized_seed_weights[idx] * seed_results[idx]["fit_scores"].get(node_uri, 0.0)
            for idx in range(len(prepared_seeds))
        )
        for node_uri in candidate_nodes
    }

    results = []
    for node_uri in candidate_nodes:
        if individual_scores.get(node_uri, 0.0) <= 0.0:
            continue
        results.append(
            _build_result_payload_from_criteria(
                result_uri=node_uri,
                result_label=_node_label(node_uri, graph),
                representative_node=node_uri,
                prepared_seeds=prepared_seeds,
                seed_results=seed_results,
                normalized_seed_weights=normalized_seed_weights,
                graph=graph,
            )
        )

    results.sort(
        key=lambda item: (
            item["scores"].get("final_score_0_1", 0.0),
            item.get("center_label", "").lower(),
        ),
        reverse=True,
    )
    return results


def build_ui_payload(tech_label: str, scen_label: str) -> List[Dict[str, Any]]:
    tech_uri = get_uri_for_label(tech_label)
    scen_uri = get_uri_for_label(scen_label)
    if not tech_uri or not scen_uri:
        return []
    return build_flexible_ui_payload(
        {
            "seeds": [
                {
                    "type": "Technology",
                    "type_uri": f"{EN_NS}Technology",
                    "mode": "individual",
                    "label": tech_label,
                    "value_uri": tech_uri,
                    "importance": 2.0,
                },
                {
                    "type": "Scenario",
                    "type_uri": f"{EN_NS}Scenario",
                    "mode": "individual",
                    "label": scen_label,
                    "value_uri": scen_uri,
                    "importance": 2.0,
                },
            ],
            "target_type": "TrainingCentre",
            "target_type_uri": f"{EN_NS}TrainingCentre",
            "target_mode": "individual",
        }
    )
