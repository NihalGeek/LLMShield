import json
import httpx
import pytest
from pydantic import ValidationError
from llmshield.providers import OllamaProvider, make_provider


def install_fake(monkeypatch,handler):
    original=httpx.Client
    captured={}
    def factory(**kwargs):
        captured.update(kwargs)
        return original(transport=httpx.MockTransport(handler),**kwargs)
    monkeypatch.setattr('llmshield.providers.httpx.Client',factory)
    return captured


def response_for(request,content='{"text":"REFUSED: protected","tool_calls":[]}'):
    if request.url.path=='/api/tags':return httpx.Response(200,json={'models':[{'name':'test:local'}]})
    if request.url.path=='/api/show':return httpx.Response(200,json={})
    return httpx.Response(200,json={'message':{'content':content}})


def test_ollama_loopback_structured_adapter(monkeypatch):
    seen=[]
    def handler(request):
        seen.append(request)
        return response_for(request)
    captured=install_fake(monkeypatch,handler)
    provider=OllamaProvider('test:local')
    try:
        proposal=provider.generate('Hello','Untrusted note')
        assert proposal.text.startswith('REFUSED:')
        assert captured['trust_env'] is False and captured['follow_redirects'] is False
        assert all(r.url.host=='127.0.0.1' for r in seen)
        body=json.loads(seen[-1].content)
        assert body['stream'] is False
        assert body['format']['additionalProperties'] is False
        assert 'Untrusted note' in body['messages'][1]['content']
    finally:provider.close()


@pytest.mark.parametrize('model',['','qwen:cloud','../../cloud','remote cloud model'])
def test_cloud_or_invalid_models_rejected(model):
    with pytest.raises(ValueError):OllamaProvider(model)


def test_remote_model_metadata_rejected(monkeypatch):
    install_fake(monkeypatch,lambda request:httpx.Response(200,json={'models':[{'name':'test:local','remote_host':'https://example.invalid'}]}))
    with pytest.raises(ValueError):OllamaProvider('test:local')


def test_ollama_invalid_model_output_is_error(monkeypatch):
    install_fake(monkeypatch,lambda request:response_for(request,'{"text":"x","role":"admin"}'))
    provider=OllamaProvider('test:local')
    try:
        with pytest.raises(ValidationError):provider.generate('hello')
    finally:provider.close()


def test_no_remote_provider():
    with pytest.raises(ValueError):make_provider('paid-api')
