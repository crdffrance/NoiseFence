"""Export-use provenance; recorded freshness alone is not independent validation."""
SCHEMA = 'noisefence-quality-exposure-1'


def validate(header):
    if 'exposure_tracking' not in header:
        return None
    value = header['exposure_tracking']
    if (not isinstance(value, dict) or set(value) != {
        'schema', 'tracking_since', 'previously_exported', 'related_campaign_seen', 'candidate_sha256'
    } or value.get('schema') != SCHEMA
        or type(value.get('tracking_since')) is not int
        or not 0 < value['tracking_since'] <= header['captured_at']
        or value.get('candidate_sha256') is not None and (not isinstance(value['candidate_sha256'],str) or len(value['candidate_sha256'])!=64 or any(c not in '0123456789abcdef' for c in value['candidate_sha256']))
        or type(value.get('previously_exported')) is not bool
        or type(value.get('related_campaign_seen')) is not bool):
        raise ValueError('Invalid export exposure provenance')
    return value


def report(header, candidate_sha256=None):
    value = validate(header)
    covered = value is not None and header['since'] > value['tracking_since']
    unused = (value is not None and not value['previously_exported']
              and not value['related_campaign_seen'] and header.get('previously_examined') is False)
    bound = value is not None and candidate_sha256 is not None and value['candidate_sha256'] == candidate_sha256
    return {'schema': SCHEMA, 'tracked': value is not None,
            'observation_window_covered': covered,
            'not_previously_exposed': unused,
            'candidate_bound': bound,
            'eligible_for_independence_checks': covered and unused and bound,
            'independent_validation': False}
