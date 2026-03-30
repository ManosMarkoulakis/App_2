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
FUSEKI_ENDPOINT = os.getenv("FUSEKI_ENDPOINT", "http://147.102.6.178:3030/enovation/sparql")
MAX_PATH_LENGTH = 4
LENGTH_DECAY_ALPHA = 0.4
INCLUDE_GLOBALLY_MISSING_IN_SCORE = False
SHOW_GLOBALLY_MISSING_IN_ANALYSIS = False
ALLOW_SAME_CLASS_REENTRY = False
ALLOW_SIBLING_CLASS_REENTRY = False
CLASS_URI_ALIASES = {
    f"{EN_NS}ResponceAction": f"{EN_NS}ResponseAction",
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
_PATH_DISCOVERY_CACHE: Dict[Tuple[str, str, int], Dict[str, List[Dict[str, Any]]]] = {}
_PCRW_CACHE: Dict[Tuple[str, Tuple[Any, ...]], Dict[str, float]] = {}
_URI_CACHE: Dict[str, Optional[str]] = {}


def run_sparql(query: str) -> Dict[str, Any]:
    headers = {"Accept": "application/sparql-results+json"}
    params = {"query": query}
    try:
        resp = requests.get(FUSEKI_ENDPOINT, params=params, headers=headers, timeout=60)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as exc:
        logger.warning("run_sparql failed: %s", exc)
        return {}


def sparql_escape_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _get_val(binding: Dict[str, Any], name: str, default: Optional[str] = None) -> Optional[str]:
    value = binding.get(name)
    return value.get("value", default) if value else default


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
    return explicit_label or _humanize_local_name(_local_name(uri))


def get_uri_for_label(label: str) -> Optional[str]:
    if not label:
        return None
    if label in _URI_CACHE:
        return _URI_CACHE[label]

    escaped = sparql_escape_literal(label)
    query = f"""
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    SELECT DISTINCT ?s WHERE {{
      ?s rdfs:label ?l .
      FILTER(LCASE(STR(?l)) = LCASE("{escaped}"))
    }} LIMIT 1
    """
    data = run_sparql(query)
    bindings = data.get("results", {}).get("bindings", [])
    if bindings:
        uri = bindings[0]["s"]["value"]
        _URI_CACHE[label] = uri
        return uri

    _URI_CACHE[label] = None
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

    class_labels: Dict[str, str] = {}
    direct_parents: Dict[str, Set[str]] = defaultdict(set)
    for binding in class_data.get("results", {}).get("bindings", []):
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
    for binding in inverse_data.get("results", {}).get("bindings", []):
        prop_uri = binding["p"]["value"]
        inv_uri = binding["inv"]["value"]
        inverse_map[prop_uri] = inv_uri
        inverse_map[inv_uri] = prop_uri

    properties: Dict[str, Dict[str, Any]] = {}
    for binding in prop_data.get("results", {}).get("bindings", []):
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
    for binding in individual_data.get("results", {}).get("bindings", []):
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
            observed_direct_types_by_type[class_uri].update(direct_types)

    individual_uris = set(individuals)
    forward_adj: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
    reverse_adj: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
    connected_individuals: Set[str] = set()

    for binding in triple_data.get("results", {}).get("bindings", []):
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
    return graph["individuals"].get(node_uri, {}).get("label", _humanize_local_name(_local_name(node_uri)))


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
        parts.append(f"{pred} {node}")
    return " -> ".join(parts)


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


def _fetch_tbox_cache() -> Dict[str, Any]:
    global _TBOX_CACHE
    if _TBOX_CACHE is not None:
        return _TBOX_CACHE

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
    properties_by_domain: Dict[str, List[str]] = defaultdict(list)
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
        for domain_uri in domain_classes:
            properties_by_domain[domain_uri].append(prop_uri)

    for domain_uri in properties_by_domain:
        properties_by_domain[domain_uri] = sorted(
            set(properties_by_domain[domain_uri]),
            key=lambda uri: (properties.get(uri, {}).get("label", uri).lower(), uri),
        )

    _TBOX_CACHE = {
        "class_labels": class_labels,
        "direct_parents": {uri: set(parents) for uri, parents in direct_parents.items()},
        "ancestors": ancestors_map,
        "descendants": descendants_map,
        "class_depth": class_depth_map,
        "properties": properties,
        "properties_by_domain": dict(properties_by_domain),
    }
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


def _criterion_signature(start_class: str, steps: List[Dict[str, Any]], tbox: Dict[str, Any]) -> str:
    parts = [_tbox_class_label(start_class, tbox)]
    current_class = start_class
    for step in steps:
        parts.append(tbox["properties"].get(step["property_uri"], {}).get("label", _humanize_local_name(_local_name(step["property_uri"]))))
        current_class = step["target_class"]
        parts.append(_tbox_class_label(current_class, tbox))
    return " -> ".join(parts)


def _criterion_key(start_class: str, steps: List[Dict[str, Any]]) -> Tuple[Any, ...]:
    key: List[Any] = [start_class]
    for step in steps:
        key.append((step["property_uri"], step["target_class"]))
    return tuple(key)


def _schema_steps_for_class(current_class: str, tbox: Dict[str, Any], graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    applicable_steps: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()
    effective_classes = set(graph.get("observed_direct_types_by_type", {}).get(current_class, {current_class}))
    effective_classes.add(current_class)

    schema_source_classes: Set[str] = set()
    for effective_class in effective_classes:
        if effective_class not in tbox["class_labels"]:
            continue
        schema_source_classes.add(effective_class)
        schema_source_classes.update(tbox["ancestors"].get(effective_class, {effective_class}))

    for ancestor_uri in sorted(schema_source_classes, key=lambda uri: tbox["class_depth"].get(uri, 0), reverse=True):
        for property_uri in tbox["properties_by_domain"].get(ancestor_uri, []):
            prop_meta = tbox["properties"].get(property_uri, {})
            for range_class in prop_meta.get("ranges", ()):
                key = (property_uri, range_class)
                if key in seen:
                    continue
                seen.add(key)
                applicable_steps.append(
                    {
                        "property_uri": property_uri,
                        "property_label": prop_meta.get("label", _humanize_local_name(_local_name(property_uri))),
                        "target_class": range_class,
                        "matching_options": _criterion_matching_options(property_uri, tbox),
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

        for schema_step in _schema_steps_for_class(current_class, tbox, graph):
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

    criteria = _extract_seed_criteria(seed["start_class"], target_root, tbox, graph, MAX_PATH_LENGTH)
    if not criteria:
        return {
            "fit_scores": {},
            "criteria_models": [],
            "criterion_summaries": {},
            "has_active_criteria": False,
        }

    criterion_models: List[Dict[str, Any]] = []
    criterion_summaries: Dict[str, List[Dict[str, Any]]] = {}

    active_weight_raw_total = 0.0
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
        if INCLUDE_GLOBALLY_MISSING_IN_SCORE or not globally_missing:
            active_weight_raw_total += criterion["weight_raw"]
        criterion_model = {
            **criterion,
            "signature": _criterion_signature(seed.get("display_start_class", seed["start_class"]), criterion["steps"], tbox),
            "path_counts": path_counts,
            "normalized_scores": normalized_scores,
            "globally_missing": globally_missing,
            "path_weight": 0.0,
            "target_paths": {target_node: list(paths) for target_node, paths in target_paths.items()},
        }
        criterion_models.append(criterion_model)

    for criterion_model in criterion_models:
        if criterion_model["globally_missing"] and not INCLUDE_GLOBALLY_MISSING_IN_SCORE:
            criterion_model["path_weight"] = 0.0
        else:
            criterion_model["path_weight"] = (
                criterion_model["weight_raw"] / active_weight_raw_total if active_weight_raw_total else 0.0
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
        "has_active_criteria": bool(criterion_models) if INCLUDE_GLOBALLY_MISSING_IN_SCORE else any(
            not criterion_model["globally_missing"] for criterion_model in criterion_models
        ),
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
            status = "globally missing" if summary["globally_missing"] else ("matched" if summary["path_count"] > 0 else "missing")
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


def _signature_template(steps: List[Dict[str, Any]], graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {
            "traversal_options": _canonical_traversal_options(step, graph),
            "display_label": step["display_label"],
            "display_direction": step["display_direction"],
            "target_class": step["target_class"],
        }
        for step in steps
    ]


def _matching_neighbors(node_uri: str, template_step: Dict[str, Any], graph: Dict[str, Any]) -> List[str]:
    neighbors_set: Set[str] = set()
    traversal_options = template_step.get("traversal_options")
    if traversal_options:
        for property_uri, traversal_direction in traversal_options:
            if traversal_direction == "forward":
                neighbors_set.update(graph["forward_adj"].get(node_uri, {}).get(property_uri, []))
            else:
                neighbors_set.update(graph["reverse_adj"].get(node_uri, {}).get(property_uri, []))
    else:
        property_uri = template_step["traversal_property"]
        if template_step["traversal_direction"] == "forward":
            neighbors_set.update(graph["forward_adj"].get(node_uri, {}).get(property_uri, []))
        else:
            neighbors_set.update(graph["reverse_adj"].get(node_uri, {}).get(property_uri, []))

    target_class = template_step.get("target_class")
    if not target_class:
        return sorted(neighbors_set)
    return sorted(
        neighbor_uri
        for neighbor_uri in neighbors_set
        if target_class in graph["individuals"].get(neighbor_uri, {}).get("all_types", set())
    )


def _pcrw_distribution(
    seed_node: str,
    start_class: str,
    signature_key: Tuple[Any, ...],
    template_steps: List[Dict[str, Any]],
    graph: Dict[str, Any],
) -> Dict[str, float]:
    cache_key = (seed_node, signature_key)
    if cache_key in _PCRW_CACHE:
        return _PCRW_CACHE[cache_key]

    seed_types = graph["individuals"].get(seed_node, {}).get("all_types", set())
    if start_class and start_class not in seed_types:
        _PCRW_CACHE[cache_key] = {}
        return {}

    current_distribution: Dict[str, float] = {seed_node: 1.0}
    for template_step in template_steps:
        next_distribution: Dict[str, float] = defaultdict(float)
        for node_uri, probability in current_distribution.items():
            neighbors = _matching_neighbors(node_uri, template_step, graph)
            if not neighbors:
                continue
            share = probability / len(neighbors)
            for neighbor_uri in neighbors:
                next_distribution[neighbor_uri] += share
        current_distribution = dict(next_distribution)
        if not current_distribution:
            break

    _PCRW_CACHE[cache_key] = current_distribution
    return current_distribution


def _discover_target_paths_for_seed_node(
    seed_node: str,
    target_root: str,
    graph: Dict[str, Any],
    max_length: int = MAX_PATH_LENGTH,
) -> Dict[str, List[Dict[str, Any]]]:
    cache_key = (seed_node, target_root, max_length)
    if cache_key in _PATH_DISCOVERY_CACHE:
        return _PATH_DISCOVERY_CACHE[cache_key]

    discovered: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    queue: deque[Tuple[str, List[Dict[str, Any]], Set[str], Tuple[str, ...]]] = deque()
    seed_class = _pick_node_class(seed_node, graph)
    initial_class_history = (seed_class,) if seed_class else tuple()
    queue.append((seed_node, [], {seed_node}, initial_class_history))

    while queue:
        current_node, steps, visited_nodes, class_history = queue.popleft()
        depth = len(steps)
        if depth > 0 and target_root in graph["individuals"].get(current_node, {}).get("all_types", set()):
            discovered[current_node].append(
                {
                    "seed_node": seed_node,
                    "target_node": current_node,
                    "steps": steps,
                    "length": depth,
                }
            )
            continue

        if depth >= max_length:
            continue

        for edge in graph["adjacency"].get(current_node, []):
            neighbor_uri = edge["neighbor"]
            if neighbor_uri in visited_nodes:
                continue
            target_class = _pick_node_class(neighbor_uri, graph)
            if _would_reenter_class_branch(
                class_history,
                target_class,
                graph["ancestors"],
                graph["direct_parents"],
            ):
                continue
            step = {
                "from_node": current_node,
                "to_node": neighbor_uri,
                "traversal_property": edge["property"],
                "traversal_direction": edge["traversal_direction"],
                "display_label": edge["display_label"],
                "display_direction": edge["display_direction"],
                "source_class": _pick_node_class(current_node, graph),
                "target_class": target_class,
            }
            next_class_history = class_history + ((target_class,) if target_class else tuple())
            queue.append((neighbor_uri, steps + [step], visited_nodes | {neighbor_uri}, next_class_history))

    _PATH_DISCOVERY_CACHE[cache_key] = {target_node: list(paths) for target_node, paths in discovered.items()}
    return _PATH_DISCOVERY_CACHE[cache_key]


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
        # Keep the selected seed type for criterion extraction/scoring, but
        # preserve the most specific matching class for user-facing XAI labels.
        start_class = type_uri
        display_start_class = _pick_most_specific_class(value_uri, type_uri, graph)
        value_label = _node_label(value_uri, graph)
    elif mode == "type":
        selected_class_uri = value_uri or type_uri
        seed_nodes = _members_of_class(selected_class_uri, graph)
        start_class = selected_class_uri
        display_start_class = selected_class_uri
        value_label = _class_label(selected_class_uri, graph)
    elif mode == "class":
        seed_nodes = _members_of_class(type_uri, graph)
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
        "display_start_class": display_start_class,
        "importance": float(seed_payload.get("importance", 2.0) or 2.0),
        "fit_label": fit_label,
        "fit_title": f"{fit_label} - {descriptor}",
        "tooltip": f"{type_label} / {mode} / {descriptor}",
    }


def _summarize_paths_for_target(
    seed: Dict[str, Any],
    target_node: str,
    target_paths: List[Dict[str, Any]],
    meta_path_models: Dict[Tuple[Any, ...], Dict[str, Any]],
    graph: Dict[str, Any],
) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    member_count = max(1, len(seed["seed_nodes"]))

    for path in target_paths:
        key = _path_signature_key(seed["start_class"], path["steps"], graph)
        rendered = _render_path_tokens(path["steps"], graph)
        explanation_text = _render_explanation_text(rendered)
        entry = grouped.setdefault(
            key,
            {
                "signature": _path_signature(seed["start_class"], path["steps"], graph),
                "shortest_length": path["length"],
                "member_support": set(),
                "example_text": explanation_text,
                "example_path": rendered,
                "rendered_paths": {},
            },
        )
        entry["member_support"].add(path["seed_node"])
        if path["length"] < entry["shortest_length"]:
            entry["shortest_length"] = path["length"]
            entry["example_text"] = explanation_text
            entry["example_path"] = rendered
        path_key = tuple((item["kind"], item["label"], str(item.get("dir", ""))) for item in rendered)
        entry["rendered_paths"][path_key] = rendered

    summaries: List[Dict[str, Any]] = []
    for key, entry in grouped.items():
        meta_model = meta_path_models.get(key)
        if not meta_model:
            continue
        support_count = len(entry["member_support"])
        support_ratio = support_count / member_count
        raw_pcrw = meta_model["raw_scores"].get(target_node, 0.0)
        normalized_pcrw = meta_model["normalized_scores"].get(target_node, 0.0)
        path_weight = meta_model["path_weight"]
        contribution = path_weight * normalized_pcrw
        rendered_paths = list(entry["rendered_paths"].values())
        summaries.append(
            {
                "signature": entry["signature"],
                "shortest_length": entry["shortest_length"],
                "support_count": support_count,
                "support_ratio": support_ratio,
                "raw_pcrw": raw_pcrw,
                "normalized_pcrw": normalized_pcrw,
                "path_weight": path_weight,
                "contribution": contribution,
                "text": entry["example_text"],
                "example_path": entry["example_path"],
                "paths": rendered_paths,
            }
        )

    summaries.sort(
        key=lambda item: (
            -item["contribution"],
            -item["normalized_pcrw"],
            -item["support_count"],
            item["shortest_length"],
            item["signature"].lower(),
        )
    )
    return summaries


def _score_seed_against_candidates(seed: Dict[str, Any], candidate_nodes: List[str], target_root: str, graph: Dict[str, Any]) -> Dict[str, Any]:
    candidate_set = set(candidate_nodes)
    if not candidate_set:
        return {"fit_scores": {}, "raw_scores": {}, "path_summaries": defaultdict(list)}

    member_count = len(seed["seed_nodes"])
    target_paths: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    meta_path_models: Dict[Tuple[Any, ...], Dict[str, Any]] = {}

    for seed_node in seed["seed_nodes"]:
        discovered = _discover_target_paths_for_seed_node(seed_node, target_root, graph)
        for target_node, paths in discovered.items():
            if target_node not in candidate_set or not paths:
                continue
            for path in paths:
                target_paths[target_node].append(path)
                meta_key = _path_signature_key(seed["start_class"], path["steps"], graph)
                model = meta_path_models.setdefault(
                    meta_key,
                    {
                        "signature_key": meta_key,
                        "signature": _path_signature(seed["start_class"], path["steps"], graph),
                        "template_steps": _signature_template(path["steps"], graph),
                        "shortest_length": path["length"],
                        "length_prior": _path_score(path["length"]),
                    },
                )
                if path["length"] < model["shortest_length"]:
                    model["shortest_length"] = path["length"]
                    model["length_prior"] = _path_score(path["length"])
                    model["template_steps"] = _signature_template(path["steps"], graph)

    active_meta_paths: List[Dict[str, Any]] = []
    for model in meta_path_models.values():
        aggregated_scores: Dict[str, float] = defaultdict(float)
        for seed_node in seed["seed_nodes"]:
            distribution = _pcrw_distribution(
                seed_node,
                seed["start_class"],
                model["signature_key"],
                model["template_steps"],
                graph,
            )
            for target_node in candidate_nodes:
                if target_node in distribution:
                    aggregated_scores[target_node] += distribution[target_node]
        raw_scores = {
            target_node: (aggregated_scores.get(target_node, 0.0) / member_count if member_count else 0.0)
            for target_node in candidate_nodes
        }
        max_raw = max(raw_scores.values(), default=0.0)
        if max_raw <= 0.0:
            continue
        model["raw_scores"] = raw_scores
        model["normalized_scores"] = {
            target_node: (score / max_raw if max_raw else 0.0)
            for target_node, score in raw_scores.items()
            if score > 0.0
        }
        active_meta_paths.append(model)

    total_length_prior = sum(model["length_prior"] for model in active_meta_paths)
    for model in active_meta_paths:
        model["path_weight"] = model["length_prior"] / total_length_prior if total_length_prior else 0.0

    raw_scores = {
        node_uri: sum(model["raw_scores"].get(node_uri, 0.0) for model in active_meta_paths)
        for node_uri in candidate_nodes
    }
    fit_scores = {}
    for node_uri in candidate_nodes:
        fit_score = sum(model["path_weight"] * model["normalized_scores"].get(node_uri, 0.0) for model in active_meta_paths)
        if fit_score > 0.0:
            fit_scores[node_uri] = fit_score

    path_summaries = {
        target_node: _summarize_paths_for_target(seed, target_node, paths, meta_path_models, graph)
        for target_node, paths in target_paths.items()
        if paths
    }
    return {
        "fit_scores": fit_scores,
        "raw_scores": raw_scores,
        "path_summaries": path_summaries,
    }


def _build_result_payload(
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
    graph_groups: List[Dict[str, Any]] = []
    meta_path_groups: List[Dict[str, Any]] = []
    seen_explanations: Set[Tuple[str, str]] = set()

    for idx, seed in enumerate(prepared_seeds):
        seed_fit = seed_results[idx]["fit_scores"].get(representative_node, 0.0)
        final_score += normalized_seed_weights[idx] * seed_fit
        seed_fit_clusters.append(
            {
                "label": seed["fit_label"],
                "score_0_10": round(seed_fit * 10.0, 1),
                "tooltip": seed["tooltip"],
            }
        )
        if seed_fit <= 0.0:
            continue

        summaries = seed_results[idx]["path_summaries"].get(representative_node, [])
        if not summaries:
            continue

        rendered_group_paths: List[List[Dict[str, Any]]] = []
        meta_paths_for_group: List[Dict[str, Any]] = []
        seen_meta_paths: Set[Tuple[str, int, int, str]] = set()
        for summary in summaries:
            explanation_key = (seed["fit_title"], summary["text"])
            if explanation_key not in seen_explanations:
                seen_explanations.add(explanation_key)
                explanations_simple.append(
                    {
                        "criterion": seed["fit_title"],
                        "text": summary["text"],
                        "entity": summary["signature"],
                    }
                )
            rendered_group_paths.extend(summary["paths"])
            meta_key = (
                summary["signature"],
                summary["shortest_length"],
                summary["support_count"],
                summary["text"],
            )
            if meta_key not in seen_meta_paths:
                seen_meta_paths.add(meta_key)
                meta_paths_for_group.append(
                    {
                        "signature": summary["signature"],
                        "shortest_length": summary["shortest_length"],
                        "support_count": summary["support_count"],
                        "support_ratio": round(summary["support_ratio"], 3),
                        "raw_pcrw": round(summary["raw_pcrw"], 6),
                        "normalized_pcrw": round(summary["normalized_pcrw"], 3),
                        "path_weight": round(summary["path_weight"], 3),
                        "contribution_0_10": round(summary["contribution"] * 10.0, 1),
                        "example_text": summary["text"],
                    }
                )

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
        if meta_paths_for_group:
            meta_path_groups.append({"title": seed["fit_title"], "paths": meta_paths_for_group})

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
