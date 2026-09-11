"""Auditable three-way metrics. Review is never a captured spam or a true negative."""
import numpy as np
from scipy.stats import beta

TARGETS = {'recall': .95, 'fpr': .001, 'review_rate': .05}


def kind_argmax(probabilities):
    """Match Rust Iterator::max_by: equal probabilities select the last kind."""
    values=np.asarray(probabilities)
    return values.shape[-1]-1-np.argmax(np.flip(values,axis=-1),axis=-1)


def interval(success, total, alpha=.05):
    if not total:
        return None
    return [0. if not success else float(beta.ppf(alpha/2, success, total-success+1)),
            1. if success == total else float(beta.ppf(1-alpha/2, success+1, total-success))]


def outcomes(y, predicted):
    y, predicted = np.asarray(y, dtype=int), np.asarray(predicted)
    if len(y) != len(predicted) or not set(y.tolist()) <= {0, 1} or not set(predicted.tolist()) <= {'spam', 'legitimate', 'review'}:
        raise ValueError('Invalid outcome arrays')
    positive, negative = y == 1, y == 0
    spam, legit, review = predicted == 'spam', predicted == 'legitimate', predicted == 'review'
    tp, fp, tn, fn = (int(np.sum(m)) for m in (spam & positive, spam & negative, legit & negative, legit & positive))
    p, n, r = int(positive.sum()), int(negative.sum()), int(review.sum())
    return {'messages':len(y),'tp':tp,'fp':fp,'tn':tn,'fn':fn,'spam_total':p,'legitimate_total':n,
            'spam_missed_or_review':p-tp,'review':r,'spam_to_review':int(np.sum(review & positive)),
            'legitimate_to_review':int(np.sum(review & negative)),
            'recall':tp/p if p else None,'recall_ci95':interval(tp,p),
            'fpr':fp/n if n else None,'fpr_ci95':interval(fp,n),
            'precision':tp/(tp+fp) if tp+fp else None,'precision_ci95':interval(tp,tp+fp),
            'review_rate':r/len(y) if len(y) else None,'review_ci95':interval(r,len(y))}


def metrics(y, probability, lower, upper, available=None):
    y, probability = np.asarray(y, dtype=int), np.asarray(probability, dtype=float)
    available = np.ones(len(y), dtype=bool) if available is None else np.asarray(available, dtype=bool)
    if len(probability)!=len(y) or len(available)!=len(y) or not 0<=lower<upper<=1 or not np.all(np.isfinite(probability)) or not np.all((probability>=0)&(probability<=1)):
        raise ValueError('Invalid risk metrics input')
    predicted=np.where(available & (probability>=upper),'spam',np.where(available & (probability<=lower),'legitimate','review'))
    report=outcomes(y,predicted)
    report['unsupported_profile']=int(np.sum(~available))
    report['brier']=float(np.mean((probability[available]-y[available])**2)) if np.any(available) else None
    report['reliability']=[]
    for index in range(10):
        selected=available & (np.minimum((probability*10).astype(int),9)==index)
        if np.any(selected):
            report['reliability'].append({'bin':index,'count':int(selected.sum()),'mean_prediction':float(np.mean(probability[selected])),
                                          'spam_fraction':float(np.mean(y[selected]))})
    return report


def acceptance(candidate, baseline, independent, coverage_complete):
    """Diagnostic gates only. Passing never writes config or issues an activation certificate."""
    comparable=(candidate['messages']==baseline['messages'] and candidate['spam_total']==baseline['spam_total']
                and candidate['legitimate_total']==baseline['legitimate_total'])
    enough=candidate['spam_total']>=20 and candidate['legitimate_total']>=100
    pilot=(comparable and enough and independent and coverage_complete and candidate['fp']<baseline['fp']
           and candidate['tp']>=baseline['tp'] and candidate['review']<=baseline['review'])
    p,n,size=candidate['spam_total'],candidate['legitimate_total'],candidate['messages']
    lower=0. if not candidate['tp'] else float(beta.ppf(.05,candidate['tp'],p-candidate['tp']+1))
    upper=1. if not n or candidate['fp']==n else float(beta.ppf(.95,candidate['fp']+1,n-candidate['fp']))
    review_upper=1. if not size or candidate['review']==size else float(beta.ppf(.95,candidate['review']+1,size-candidate['review']))
    target_met=(independent and coverage_complete and lower>=TARGETS['recall'] and upper<=TARGETS['fpr'] and review_upper<=TARGETS['review_rate'])
    return {'targets':TARGETS,'independent':bool(independent),'coverage_complete':bool(coverage_complete),
            'sufficient_pilot_counts':enough,'passes_pilot':bool(pilot),'meets_final_confidence_bounds':bool(target_met),
            'one_sided_95_bounds':{'recall_lower':lower,'fpr_upper':upper,'review_upper':review_upper},
            'may_activate':False,'status':'needs_independent_review' if pilot or target_met else 'not_validated'}
