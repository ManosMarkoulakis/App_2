"""HTTP boundary regressions; no external Fuseki access is required."""
import importlib
import json
import pytest

web = importlib.import_module('App_2.app')


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(web, 'FEEDBACK_FILE', tmp_path/'feedback.jsonl')
    monkeypatch.setattr(web, '_fetch_class_catalog', lambda: {
        'items': [], 'key_to_uri': {'Technology': web.EN_NS+'Technology',
                                   'TrainingCentre': web.EN_NS+'TrainingCentre'}})
    return web.app.test_client()


def test_liveness_and_homepage(client):
    assert client.get('/healthz').get_json() == {'status':'ok'}
    response=client.get('/')
    assert response.status_code == 200
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert not web.app.debug


@pytest.mark.parametrize('body',[[], 'text', 12, None])
def test_reject_non_object_json(client,body):
    assert client.post('/api/recommend',data=json.dumps(body),content_type='application/json').status_code == 400


def test_reject_large_json(client):
    assert client.post('/api/feedback',json={'x':'x'*70000}).status_code == 413


def test_reject_sparql_injection_before_query(client,monkeypatch):
    def unexpected(*args):
        pytest.fail('Untrusted URI reached SPARQL query builder')
    monkeypatch.setattr(web,'_fetch_instances_for_class',unexpected)
    response=client.get('/api/instances',query_string={'class_key':'Technology','class_uri':web.EN_NS+'Technology> . SERVICE <http://example.invalid/>'})
    assert response.status_code == 400


def test_catalog_uri_preserves_instances_contract(client,monkeypatch):
    expected=[{'uri':web.EN_NS+'Example','label':'Example'}]
    monkeypatch.setattr(web,'_fetch_instances_for_class',lambda uri:expected)
    response=client.get('/api/instances',query_string={'class_key':'Technology','class_uri':web.EN_NS+'Technology'})
    assert response.status_code == 200
    assert response.get_json()['instances'] == expected


@pytest.mark.parametrize('weight',['NaN','Infinity',-1,{},[]])
def test_reject_invalid_importance(client,weight):
    response=client.post('/api/recommend',json={'target_type':'TrainingCentre','seeds':[{'type':'Technology','mode':'class','importance':weight}]})
    assert response.status_code == 400


def test_valid_request_keeps_original_payload(client,monkeypatch):
    expected=[{'center_label':'Example','scores':{'final_score_0_1':0.5}}]
    def engine(payload):
        assert payload['seeds'][0]['importance'] == 2
        assert payload['seeds'][0]['value_uri'] == web.EN_NS+'Technology'
        return expected
    monkeypatch.setattr(web,'build_flexible_ui_payload',engine)
    result=client.post('/api/recommend',json={'target_type':'TrainingCentre','seeds':[{'type':'Technology','mode':'class','importance':2}]})
    assert result.get_json() == {'results':expected}


def test_feedback_does_not_record_remote_address(client):
    response=client.post('/api/feedback',json={'center_label':'Example','rating':'useful'},environ_base={'REMOTE_ADDR':'192.0.2.1'})
    assert response.status_code == 200
    row=json.loads(web.FEEDBACK_FILE.read_text())
    assert set(row) == {'timestamp','tech','scenario','query_title','center_label','rating','scores'}
    assert '192.0.2.1' not in web.FEEDBACK_FILE.read_text()
