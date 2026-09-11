"""Small data-only counterpart to Rust quality::Model; never activates a candidate."""
import time
import unicodedata
import numpy as np
from scipy.special import expit, softmax
from train_quality import PROTOCOL_HASH, PROTOCOL, KINDS
from train_fusion import require, numeric, is_hex, decode


def load_model(path):
    with path.open('rb') as f:
        raw=f.read(2*1024*1024+1)
    require(len(raw)<=2*1024*1024,'Oversized candidate')
    model=decode(raw)
    required={'schema','version','protocol_sha256','artifacts_sha256','trained_at','dataset_sha256','profiles','risk','calibration','thresholds','kinds','kind_models','kind_temperature','kind_profiles','training_manifest_sha256'}
    require(isinstance(model,dict) and set(model)==required and model['schema']=='noisefence-quality-model-2' and model['protocol_sha256']==PROTOCOL_HASH,'Invalid model contract')
    require(all(is_hex(model[k]) for k in ('artifacts_sha256','dataset_sha256','training_manifest_sha256')),'Invalid model binding')
    require(isinstance(model['version'],str) and 0<len(model['version'].encode('utf-8'))<=100 and not any(unicodedata.category(c)=='Cc' for c in model['version']),'Invalid model version')
    require(type(model['trained_at']) is int and 0<model['trained_at']<=time.time()+60,'Invalid model time')
    valid_profiles=lambda p:isinstance(p,list) and 0<len(p)<=256 and all(isinstance(s,str) and 0<len(s)<=1024 and all(c in 'abcdefghijklmnopqrstuvwxyz/_' for c in s) for s in p)
    require(valid_profiles(model['profiles']),'Invalid risk profiles')
    full=(model['kinds']==KINDS and isinstance(model['kind_models'],list) and len(model['kind_models'])==6 and valid_profiles(model['kind_profiles']))
    empty=(model['kinds']==[] and model['kind_models']==[] and model['kind_profiles']==[] and model['kind_temperature']==1.)
    require(full or empty,'Invalid kind model')
    for m in [model['risk'],*model['kind_models']]:
        require(isinstance(m,dict) and set(m)=={'bias','weights'} and numeric(m['bias']) and abs(m['bias'])<=10000 and isinstance(m['weights'],list) and len(m['weights'])==len(PROTOCOL['features']) and all(numeric(v) and abs(v)<=10000 for v in m['weights']),'Invalid weights')
    require(isinstance(model['calibration'],list) and len(model['calibration'])==2 and all(numeric(v) for v in model['calibration']) and 0<model['calibration'][0]<=100 and abs(model['calibration'][1])<=100,'Invalid calibration')
    require(isinstance(model['thresholds'],list) and len(model['thresholds'])==2 and all(numeric(v) for v in model['thresholds']) and 0<=model['thresholds'][0]<model['thresholds'][1]<=1,'Invalid thresholds')
    require(numeric(model['kind_temperature']) and .05<=model['kind_temperature']<=20.,'Invalid temperature')
    return model,raw


def predict(model, observation):
    require(isinstance(observation,dict) and observation.get('protocol_sha256')==model['protocol_sha256'] and observation.get('artifacts_sha256')==model['artifacts_sha256'] and observation.get('source')=='smtp_session' and observation.get('complete_features') is True and observation.get('availability_profile') in model['profiles'],'Unsupported observation')
    values=observation.get('values')
    require(isinstance(values,list) and len(values)==len(PROTOCOL['features']) and all(numeric(v) and f['minimum']<=v<=f['maximum'] for v,f in zip(values,PROTOCOL['features'])),'Invalid observations')
    logit=model['risk']['bias']+float(np.dot(values,model['risk']['weights']))
    p=float(expit(np.clip(model['calibration'][0]*logit+model['calibration'][1],-40,40)))
    lower,upper=model['thresholds']
    result={'risk_probability':p,'risk':'spam' if p>=upper else 'legitimate' if p<=lower else 'review','kind':'unavailable','kind_probabilities':[]}
    if model['kind_models'] and observation['availability_profile'] in model['kind_profiles']:
        probabilities=softmax(np.array([m['bias']+np.dot(values,m['weights']) for m in model['kind_models']])/model['kind_temperature'])
        result.update(kind=KINDS[int(np.argmax(probabilities))],kind_probabilities=probabilities.tolist())
    return result
