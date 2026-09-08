"""Capture complete payloads against a fixed RDF snapshot, without remote access."""
import argparse
import csv
import gzip
import importlib.util
import itertools
import json
import re
import sys
from functools import lru_cache
from pathlib import Path
from rdflib import Graph, RDF, OWL, URIRef

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

def capture(root):
    graph = Graph().parse(root / 'ontology.ttl', format='turtle')
    @lru_cache(None)
    def query(q):
        if 'AS ?hasOutgoing' in q:
            # RDFLib 7.0 cannot evaluate projected EXISTS. Evaluate the same
            # two existence checks locally; production still sends Fuseki SPARQL.
            simple = re.sub(r'\(EXISTS.*?AS \?hasIncoming\)', '', q, flags=re.DOTALL)
            data = json.loads(graph.query(simple).serialize(format='json'))
            for row in data['results']['bindings']:
                node = URIRef(row['s']['value'])
                for name, edges in [('hasOutgoing',graph.predicate_objects(node)),('hasIncoming',((p,s) for s,p in graph.subject_predicates(node)))]:
                    found = any(str(p).startswith('http://www.semanticweb.org/eNOVATION-ontology#') and (p,RDF.type,OWL.ObjectProperty) in graph for p,_ in edges)
                    row[name]={'type':'literal','datatype':'http://www.w3.org/2001/XMLSchema#boolean','value':str(found).lower()}
        else:
            data = json.loads(graph.query(q).serialize(format='json'))
        # Keep identical SPARQL binding order across separately parsed snapshots.
        data['results']['bindings'].sort(key=lambda x: json.dumps(x, sort_keys=True))
        return data
    rec = load('enovation_recommender', root/'App_2/enovation_recommender.py')
    rec.run_sparql = query
    app = load('review_app', root/'App_2/app.py')
    app.run_sparql = query
    client = app.app.test_client()
    out = {'options':client.get('/api/options').get_json(), 'instances':{}, 'class_values':{}, 'recommendations':{}}
    assert out['options']['target_types'], 'No target types'
    for item in out['options']['seed_types']:
        key = item['key']
        out['instances'][key] = client.get('/api/instances', query_string={'class_key':key}).get_json()
        for mode in ('individual', 'type'):
            out['class_values'][key+'/'+mode] = client.get('/api/class-values', query_string={'class_key':key,'mode':mode}).get_json()
    g = rec._fetch_graph_cache()
    def seed(kind, uri='', mode='individual', importance=2):
        return {'type':kind, 'mode':mode, 'value_uri':uri, 'importance':importance}
    def recommend(key, seeds, target='TrainingCentre'):
        response = client.post('/api/recommend', json={'seeds':seeds,'target_type':target})
        assert response.status_code == 200, (key,response.status_code,response.get_json())
        out['recommendations'][key] = response.get_json()
    techs = rec._members_of_class(rec.EN_NS+'Technology',g)
    scenarios = rec._members_of_class(rec.EN_NS+'Scenario',g)
    for i,(te,sc) in enumerate(itertools.product(techs,scenarios)):
        recommend('grid/'+str(i),[seed('Technology',te),seed('Scenario',sc)])
    print('Captured technology/scenario grid:',len(out['recommendations']),flush=True)
    for item in out['options']['seed_types']:
        key=item['key']
        for mode in item['available_seed_modes']:
            values=out['class_values'].get(key+'/'+mode,{}).get('values',[])
            uri=next((v['uri'] for v in values if not v.get('disabled')), '')
            for target in ['TrainingCentre']:
                recommend('modes/'+key+'/'+mode+'/'+target,[seed(key,uri,mode)],target)
    for target in [i['key'] for i in out['options']['target_types']]:
        recommend('targets/'+target,[seed('Technology',techs[0])],target)
    print('Captured modes and target coverage.',flush=True)
    if techs and scenarios:
        for weight in (0,1,3,5):
            recommend('weights/'+str(weight),[seed('Technology',techs[0],importance=weight),seed('Scenario',scenarios[0])])
        recommend('five-seeds',[seed('Technology',techs[i % len(techs)],importance=i+1) for i in range(5)])
    rec._TBOX_CACHE=rec._fetch_tbox_cache_from_local()
    recommend('local-tbox',[seed('Technology',techs[0]),seed('Scenario',scenarios[0])])
    out['hybrid']={}
    if (root/'App_tech_hybrid/enovation_recommender.py').exists():
        hybrid=load('hybrid_review',root/'App_tech_hybrid/enovation_recommender.py')
        out['hybrid']={str((c,a)):hybrid.build_ui_payload(c,a) for c in hybrid.get_available_centres() for a in hybrid.ALLOWED_ALPHAS}
    print('Captured App_2 cases:',len(out['recommendations']),'hybrid:',len(out['hybrid']),flush=True)
    return out

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('output',type=Path);args=p.parse_args()
    result=capture(args.root.resolve())
    with gzip.open(args.output,'wt',encoding='utf-8') as f: json.dump(result,f,sort_keys=True,ensure_ascii=False)
    print('Snapshot saved.',flush=True)
