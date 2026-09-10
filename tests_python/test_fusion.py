"""Fusion isolation, calibration and fail-open decision tests. Synthetic only."""
import hashlib
import copy
import importlib.util
import json
import math
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
try:
    import numpy as np
    import sklearn
except ImportError:
    np = None


@unittest.skipIf(np is None, 'Install research/requirements.txt')
class FusionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('train_fusion', ROOT/'research/train_fusion.py')
        cls.f = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.f)

    def binding(self):
        # Valid bounded settings; no detector is executed by Python fixtures.
        limits = {key: 1 for key, _ in self.f.STRUCTURE_LIMITS}
        version = 'noisefence-content-inspection-1'
        digest = hashlib.sha256(json.dumps([version, limits], separators=(',', ':')).encode()).hexdigest()
        return {'version': 'noisefence-local-evidence-1',
                'heuristics': {'version': 'heuristics-1', 'pattern_version': 'heuristics-fr-en-1',
                               'settings_digest': 'a'*64, 'enabled': True, 'rule_ids': ['custom_a', 'custom_b']},
                'structure': {'version': version, 'settings_digest': digest, 'limits': limits}}

    def fixture(self, root, version=1):
        f = self.f
        protocol = f.protocol_for_hash(f.KNOWN_PROTOCOLS[version-1][0])
        digest = lambda text: hashlib.sha256(text.encode()).hexdigest()
        artifacts = {'application': 'fixture', 'dependency_lock_sha256': digest('lock'), 'policy_sha256': digest('policy'),
                     'lexical_model_sha256': digest('lexical'), 'semantic_model_sha256': None, 'semantic_protocol': None,
                     'llm_prompt_sha256': None, 'antivirus_database_sha256': None, 'signatures_database_sha256': None,
                     'llm_model_revision': None}
        data = [{'type': 'header', 'schema': 'noisefence-fusion-vectors-1', 'protocol_sha256': protocol.sha256, 'artifacts': artifacts}]
        if version == 2:
            data[0]['local_binding'] = self.binding()
        annotations = []
        for i in range(200):
            values = [0.] * len(protocol.features)
            values[next(j for j, v in enumerate(protocol.features) if v.name == 'lexical.logit_clipped_32')] = .7 if i % 2 else -.7
            if version == 2:
                local = {'heuristics.state.complete': 1., 'structure.state.complete': 1.,
                         'heuristics.rule_00.hit': float(i % 2), 'structure.pdf_active_name': float(i % 2),
                         'structure.html_parts_div256': 1/256}
                for j, feature in enumerate(protocol.features):
                    if feature.name in local:
                        values[j] = local[feature.name]
            key = digest('row-'+str(i))
            data.append({'type': 'row', 'id': key, 'fingerprint': key, 'simhash': key[:16], 'observed_at': 100+i,
                         'labelled_at': 1000+i, 'source': 'local_human_feedback', 'spam': bool(i % 2), 'values': values,
                         'availability_profile': 'complete' if version == 1 else '/'.join(['complete']*14),
                         'tag_eligible': i % 19 != 0, 'legacy_score': 50.})
            annotations.append({'id': key, 'campaign': key, 'split': f.SPLITS[i//40], 'label': 'unwanted_binary' if i % 2 else 'legit',
                                'language': 'fr', 'kind': 'unit-fixture'})
        data.append({'type': 'footer', 'counts': {'considered': 200, 'exported': 200, 'missing_evidence': 0,
                                                  'non_smtp_evidence': 0, 'ineligible_to_tag': len(range(0,200,19))}})
        history = {'schema': 'noisefence-base-history-1', 'lexical_model_sha256': artifacts['lexical_model_sha256'],
                   'semantic_model_sha256': None, 'complete_for': f.BASE_USES,
                   'rows': [{'fingerprint': digest('base'), 'campaign': digest('base'), 'simhash': digest('base')[:16]}]}
        (root/'vectors.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in data))
        (root/'annotations.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in annotations))
        (root/'history.json').write_text(json.dumps(history))
        manifest = {'schema': 'noisefence-fusion-experiment-1', 'version': 'unit', 'purpose': 'research', 'protocol_sha256': protocol.sha256,
                    **{k: {'path': path, 'sha256': hashlib.sha256((root/path).read_bytes()).hexdigest()}
                       for k, path in [('vectors','vectors.jsonl'), ('annotations','annotations.jsonl'), ('base_history','history.json')]},
                    'sampling': {'kind': 'synthetic', 'description': 'Unit fixtures', 'authorization': 'No private data', 'start_at':100,'end_at':299}}
        path = root/'manifest.json'
        path.write_text(json.dumps(manifest))
        return path, data

    def rewrite_vectors(self, manifest, data):
        m = json.loads(manifest.read_text())
        path = manifest.parent / m['vectors']['path']
        path.write_text(''.join(json.dumps(r)+'\n' for r in data))
        m['vectors']['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest.write_text(json.dumps(m))

    def test_threshold_ties_and_incomplete_checks_do_not_escape_fpr_constraint(self):
        f = self.f
        y, score, eligible = np.array([False, True, True]), np.array([2.,2.,100.]), np.array([True,True,False])
        threshold = f.choose_cutoff(y, score, eligible)
        result = f.metrics(y, eligible & (score >= threshold))
        self.assertEqual((result['tp'], result['fp']), (0,0))
        self.assertGreater(f.wilson(0,97)[1], .03)
        y = np.array([False]*1000 + [True]*20)
        score = np.arange(len(y), dtype=float)
        point = f.choose_cutoff(y, score, np.ones(len(y),bool))
        result = f.metrics(y, score >= point)
        self.assertEqual(result['tp'], 20)
        self.assertLessEqual(result['fp'], 1)

    def test_monotone_calibration_handles_reversed_predictions_and_reports_mixture(self):
        cal = self.f.calibrate(np.array([-2.,-1.,1.,2.]), np.array([True,True,False,False]))
        self.assertGreaterEqual(cal['slope'], 0.)
        self.assertLess(cal['slope'], 1e-6)
        self.assertEqual(cal['positive_fraction'], .5)
        self.assertEqual(cal['messages'], 4)

    def test_transitive_campaigns_cannot_cross_splits_or_base_training(self):
        rows = [{'id': str(i), 'fingerprint': str(i)*64, 'campaign': str(i)*64,
                 'simhash': f'{s:016x}', 'split': split, 'label': 'legit', 'spam': False}
                for i,s,split in [(1,0,'train'),(2,7,'train'),(3,63,'test')]]
        self.assertEqual(len(self.f.components(rows)), 1)
        with self.assertRaisesRegex(ValueError, 'crosses'):
            self.f.audit_groups(rows, [])
        with self.assertRaisesRegex(ValueError, 'base-model'):
            self.f.audit_groups(rows[:2], [rows[2]])
        rows[1]['spam'] = True
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            self.f.audit_groups(rows[:2], [])

    def test_test_predictions_cannot_change_fit_and_frozen_models_cannot_be_replaced(self):
        f = self.f
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, data = self.fixture(root)
            f.fit(manifest, root/'first')
            original = json.loads((root/'first/full.json').read_text())
            for row in data[161:201]:
                row['values'] = [-x for x in row['values']]
            (root/'vectors.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in data))
            m = json.loads(manifest.read_text())
            m['vectors']['sha256'] = hashlib.sha256((root/'vectors.jsonl').read_bytes()).hexdigest()
            manifest.write_text(json.dumps(m))
            f.fit(manifest, root/'second')
            changed = json.loads((root/'second/full.json').read_text())
            for field in ('weights','bias','cutoff','calibration','supported_profiles'):
                self.assertEqual(original[field], changed[field])
            report = f.evaluate(manifest, root/'second')
            self.assertFalse(report['production_eligible'])
            self.assertFalse(report['target_supported_on_this_test'])
            self.assertEqual(report['variants']['full']['metrics']['tp'], 0)
            with self.assertRaisesRegex(ValueError, 'consumed'):
                f.evaluate(manifest, root/'second')
            with self.assertRaisesRegex(ValueError, 'mismatch'):
                f.evaluate(manifest, root/'first')

    def test_hashes_protocol_and_export_footer_prevent_silent_dataset_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, _ = self.fixture(root)
            (root/'vectors.jsonl').write_text('{}\n')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                self.f.load_experiment(manifest)
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON'):
            self.f.decode('{"x":1,"x":2}')
        with self.assertRaisesRegex(ValueError, 'Non-finite'):
            self.f.decode('{"x":NaN}')

    def test_v2_context_masks_and_interleaving_preserve_v1_model_bytes(self):
        f = self.f
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'v1').mkdir()
            (root/'v2').mkdir()
            v1, _ = self.fixture(root/'v1')
            v2, _ = self.fixture(root/'v2', 2)
            self.assertEqual(len(f.load_experiment(v1)), 5)
            self.assertEqual(len(f.load_experiment(v2)), 5)
            f.fit(v1, root/'before')
            receipt = f.fit(v2, root/'v2-models')
            f.fit(v1, root/'after')
            context = f.load_experiment_context(v2)[-1]
            self.assertEqual(context.protocol.variant_names, ('baseline', 'heuristics', 'structure', 'full'))
            self.assertEqual(set(receipt['models_sha256']), set(context.protocol.variant_names))
            for variant in f.VARIANTS:
                self.assertEqual((root/'before'/f'{variant}.json').read_bytes(),
                                 (root/'after'/f'{variant}.json').read_bytes())
                model = json.loads((root/'before'/f'{variant}.json').read_text())
                self.assertNotIn('local_binding', model)
                self.assertEqual((model['schema'], len(model['weights'])), ('noisefence-fusion-model-1', 218))
            for variant, families in context.protocol.variants:
                model = json.loads((root/'v2-models'/f'{variant}.json').read_text())
                self.assertEqual((model['schema'], len(model['weights'])),
                                 ('noisefence-fusion-model-2', len(context.protocol.features)))
                self.assertEqual(model['local_binding'], self.binding())
                self.assertTrue(all(weight == 0 for weight, feature in zip(model['weights'], context.protocol.features)
                                    if feature.family not in families))
                for family in ('heuristics', 'structure'):
                    if family in families:
                        self.assertTrue(any(weight != 0 for weight, feature in zip(model['weights'], context.protocol.features)
                                            if feature.family == family))
            report = f.evaluate(v2, root/'v2-models')
            self.assertEqual(tuple(report['variants']), context.protocol.variant_names)
            self.assertFalse(report['production_eligible'])
            self.assertFalse(report['target_supported_on_this_test'])

    def test_protocol_selection_rejects_paths_unknown_hashes_and_cross_version_headers(self):
        f = self.f
        for digest in ('f'*64, '/tmp/protocol.json', {'path': 'fusion-protocol-2.json'}, None):
            with self.subTest(digest=digest), self.assertRaisesRegex(ValueError, 'Unknown fusion protocol'):
                f.protocol_for_hash(digest)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, data = self.fixture(root, 2)
            data[0]['protocol_sha256'] = f.PROTOCOL_HASH
            self.rewrite_vectors(manifest, data)
            with self.assertRaisesRegex(ValueError, 'vector protocol'):
                f.load_experiment(manifest)
            m = json.loads(manifest.read_text())
            m['protocol_path'] = '/tmp/protocol.json'
            manifest.write_text(json.dumps(m))
            with self.assertRaisesRegex(ValueError, 'manifest fields'):
                f.load_experiment(manifest)

    def test_local_binding_is_typed_ordered_and_matches_rust_structure_digest(self):
        f = self.f
        valid = self.binding()
        f.validate_local_binding(valid)
        reordered = copy.deepcopy(valid)
        reordered['structure']['limits'] = dict(reversed(list(reordered['structure']['limits'].items())))
        f.validate_local_binding(reordered)
        f.validate_local_binding({'version': valid['version'], 'heuristics': None, 'structure': None})
        mutations = [
            lambda b: b.update(version='other'),
            lambda b: b.update(address='private@example.test'),
            lambda b: b['heuristics'].update(enabled=1),
            lambda b: b['heuristics'].update(settings_digest='A'*64),
            lambda b: b['heuristics'].update(pattern_version='other'),
            lambda b: b['heuristics'].update(rule_ids=['custom_b', 'custom_a']),
            lambda b: b['heuristics'].update(rule_ids=['duplicate', 'duplicate']),
            lambda b: b['heuristics'].update(rule_ids=[f'rule_{i:02}' for i in range(65)]),
            lambda b: b['heuristics'].update(rule_ids=['private@example.test']),
            lambda b: b['heuristics'].update(rule_ids=['x'*65]),
            lambda b: b['structure'].update(settings_digest='0'*64),
            lambda b: b['structure']['limits'].update(max_parts=True),
            lambda b: b['structure']['limits'].update(max_parts=1.0),
            lambda b: b['structure']['limits'].update(max_parts=257),
            lambda b: b['structure']['limits'].update(max_unpacked_bytes=2),
            lambda b: b['structure']['limits'].pop('max_images'),
            lambda b: b['structure']['limits'].update(unknown=1),
        ]
        for index, mutate in enumerate(mutations):
            binding = copy.deepcopy(valid)
            mutate(binding)
            with self.subTest(index=index), self.assertRaises(ValueError):
                f.validate_local_binding(binding)

    def test_v2_missing_binding_dimensions_and_incomplete_local_evidence_fail_closed(self):
        f = self.f
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, original = self.fixture(root, 2)
            protocol = f.load_experiment_context(manifest)[-1].protocol
            index = {feature.name: i for i, feature in enumerate(protocol.features)}
            mutations = [
                lambda d: d[0].pop('local_binding'),
                lambda d: d[0].update(local_binding=None),
                lambda d: d[1]['values'].pop(),
                lambda d: d[1]['values'].__setitem__(index['heuristics.rule_00.hit'], .5),
                lambda d: d[1]['values'].__setitem__(index['heuristics.rule_63.hit'], 1.),
                lambda d: d[1]['values'].__setitem__(index['structure.html_parts_div256'], .1),
                lambda d: d[1]['values'].__setitem__(index['structure.image_dimensions'], .5),
                lambda d: d[1]['values'].__setitem__(index['structure.image_bytes_log16777216'], 1.01),
                lambda d: d[1]['values'].__setitem__(index['structure.pdf_bytes_log16777216'], -1.),
                lambda d: d[1]['values'].__setitem__(index['structure.image_max_pixels_log100000000'],
                                                  math.log1p(.5)/math.log1p(100_000_000)),
                lambda d: d[1].update(availability_profile='complete/complete/complete'),
                lambda d: d[1].update(availability_profile='/'.join(['complete']*12 + ['missing', 'complete'])),
                lambda d: d[1]['values'].__setitem__(index['structure.state.missing'], 1.),
                lambda d: d[0]['local_binding'].update(heuristics=None),
            ]
            for n, mutate in enumerate(mutations):
                data = copy.deepcopy(original)
                mutate(data)
                self.rewrite_vectors(manifest, data)
                with self.subTest(index=n), self.assertRaises(ValueError):
                    f.load_experiment(manifest)
            data = copy.deepcopy(original)
            # A missing detector is an observation, but it cannot authorize a tag.
            row = data[2]
            row['values'][index['heuristics.state.complete']] = 0.
            row['values'][index['heuristics.state.missing']] = 1.
            row['values'][index['heuristics.rule_00.hit']] = 0.
            row['availability_profile'] = '/'.join(['complete']*12 + ['missing', 'complete'])
            self.rewrite_vectors(manifest, data)
            with self.assertRaisesRegex(ValueError, 'cannot authorize tagging'):
                f.load_experiment(manifest)
            row['tag_eligible'] = False
            data[-1]['counts']['ineligible_to_tag'] += 1
            self.rewrite_vectors(manifest, data)
            self.assertEqual(len(f.load_experiment(manifest)[3]), 200)

    def test_v2_native_log_rounding_and_caps_are_accepted_but_fractional_counts_are_not(self):
        f = self.f
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, data = self.fixture(root, 2)
            context = f.load_experiment_context(manifest)[-1]
            slots = {feature.name: i for i, feature in enumerate(context.protocol.features)}
            self.assertEqual(tuple(feature.name for feature in context.protocol.features if '_log' in feature.name
                                   and feature.family == 'structure'), tuple(name for name, _ in f.MEDIA_LOG_FEATURES))
            for name, cap in f.MEDIA_LOG_FEATURES:
                for raw in (0, 1, 7, cap//2, cap-1, cap):
                    encoded = math.log1p(raw)/math.log1p(cap)
                    with self.subTest(name=name, raw=raw):
                        self.assertTrue(f.log_scaled_integer(encoded, cap))
                        data[1]['values'][slots[name]] = encoded
                        f.validate_local_vector(data[1], context)
                        fractional = math.log1p(raw+.25)/math.log1p(cap)
                        data[1]['values'][slots[name]] = fractional
                        with self.assertRaisesRegex(ValueError, 'structure vector'):
                            f.validate_local_vector(data[1], context)
                        data[1]['values'][slots[name]] = encoded
                for invalid in (-1., 1.01, float('nan'), float('inf'), True):
                    with self.subTest(name=name, invalid=invalid):
                        self.assertFalse(f.log_scaled_integer(invalid, cap))
            # Caps also survive JSON serialization and the complete loader.
            self.rewrite_vectors(manifest, data)
            f.load_experiment(manifest)
            # Count columns keep their original /256 integer encoding.
            data[1]['values'][slots['structure.png_parts_div256']] = 7.25/256
            self.rewrite_vectors(manifest, data)
            with self.assertRaisesRegex(ValueError, 'structure vector'):
                f.load_experiment(manifest)

    def test_v2_test_values_do_not_affect_fitting_and_binding_cannot_be_replaced(self):
        f = self.f
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, data = self.fixture(root, 2)
            f.fit(manifest, root/'first')
            context = f.load_experiment_context(manifest)[-1]
            for row in data[161:201]:
                for i, feature in enumerate(context.protocol.features):
                    if feature.name == 'lexical.logit_clipped_32':
                        row['values'][i] *= -1
                    elif feature.name in ('heuristics.rule_00.hit', 'structure.pdf_active_name'):
                        row['values'][i] = 1 - row['values'][i]
            self.rewrite_vectors(manifest, data)
            f.fit(manifest, root/'second')
            for variant in context.protocol.variant_names:
                first = json.loads((root/'first'/f'{variant}.json').read_text())
                second = json.loads((root/'second'/f'{variant}.json').read_text())
                for field in ('weights', 'bias', 'calibration', 'cutoff', 'supported_profiles', 'local_binding'):
                    self.assertEqual(first[field], second[field])
            model_path = root/'second/full.json'
            model = json.loads(model_path.read_text())
            model['local_binding']['heuristics']['settings_digest'] = 'b'*64
            model_path.write_text(json.dumps(model))
            receipt_path = root/'second/fit.json'
            receipt = json.loads(receipt_path.read_text())
            receipt['models_sha256']['full'] = hashlib.sha256(model_path.read_bytes()).hexdigest()
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, 'local detector binding changed'):
                f.evaluate(manifest, root/'second')
            model['schema'] = 'noisefence-fusion-model-1'
            with self.assertRaisesRegex(ValueError, 'model contract'):
                f.validate_model(model)

    def test_v2_campaign_leakage_is_rejected_before_any_fit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, data = self.fixture(root, 2)
            data[161]['fingerprint'] = data[1]['fingerprint']
            self.rewrite_vectors(manifest, data)
            with self.assertRaisesRegex(ValueError, 'crosses frozen fusion splits'):
                self.f.fit(manifest, root/'models')
            self.assertFalse((root/'models').exists())

    def test_v2_image_pdf_metadata_has_a_real_learned_effect_only_in_structure_variants(self):
        f = self.f
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, data = self.fixture(root, 2)
            context = f.load_experiment_context(manifest)[-1]
            self.assertEqual(len(context.protocol.features), 327)
            log_caps = dict(f.MEDIA_LOG_FEATURES)
            for row in data[1:-1]:
                for index, feature in enumerate(context.protocol.features):
                    if feature.name in ('lexical.logit_clipped_32', 'heuristics.rule_00.hit', 'structure.pdf_active_name'):
                        row['values'][index] = 0.
                    elif feature.name in log_caps:
                        row['values'][index] = math.log1p(4 if row['spam'] else 0)/math.log1p(log_caps[feature.name])
                    elif index >= 309:
                        row['values'][index] = float(row['spam']) * (1. if index < 315 else .5)
            self.rewrite_vectors(manifest, data)
            f.fit(manifest, root/'models')
            report = f.evaluate(manifest, root/'models')
            for variant in ('baseline', 'heuristics'):
                self.assertEqual(report['variants'][variant]['metrics']['tp'], 0)
                model = json.loads((root/'models'/f'{variant}.json').read_text())
                self.assertTrue(all(weight == 0 for weight in model['weights'][309:]))
            for variant in ('structure', 'full'):
                self.assertGreater(report['variants'][variant]['metrics']['tp'], 0)
                self.assertEqual(report['variants'][variant]['metrics']['fp'], 0)
                model = json.loads((root/'models'/f'{variant}.json').read_text())
                self.assertTrue(all(weight != 0 for weight in model['weights'][309:]))
            self.assertFalse(report['target_supported_on_this_test'])
            self.assertFalse(report['production_eligible'])

    def test_v2_tiny_media_log_features_fit_within_unchanged_native_coefficient_bound(self):
        f = self.f
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, data = self.fixture(root, 2)
            context = f.load_experiment_context(manifest)[-1]
            log_caps = dict(f.MEDIA_LOG_FEATURES)
            for row in data[1:-1]:
                for index, feature in enumerate(context.protocol.features):
                    if feature.name in ('lexical.logit_clipped_32', 'heuristics.rule_00.hit', 'structure.pdf_active_name'):
                        row['values'][index] = 0.
                    elif feature.name in log_caps:
                        row['values'][index] = math.log1p(2 if row['spam'] else 1)/math.log1p(log_caps[feature.name])
            self.rewrite_vectors(manifest, data)
            f.fit(manifest, root/'models')
            for variant in ('structure', 'full'):
                model = json.loads((root/'models'/f'{variant}.json').read_text())
                weights = [weight for weight, feature in zip(model['weights'], context.protocol.features)
                           if feature.name in log_caps]
                self.assertEqual(len(weights), 5)
                self.assertTrue(all(0 < abs(weight) <= 1e6 for weight in weights))
                f.validate_model(model, context)
                model['weights'][0] = 1_000_001.
                with self.assertRaisesRegex(ValueError, 'coefficients'):
                    f.validate_model(model, context)

    def population(self):
        sys.path.insert(0, str(ROOT/'research'))
        try:
            spec = importlib.util.spec_from_file_location('evaluate_population', ROOT/'research/evaluate_population.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        finally:
            sys.path.pop(0)

    def prediction_envelope(self, protocol):
        prediction = {'version': 'fixture', 'logit': 1., 'probability': .7, 'above_threshold': True,
                      'profile_supported': True, 'tag_eligible': True, 'would_tag': True, 'contributions': []}
        rows = []
        for i, assessment in enumerate(('missing_or_invalid_evidence', 'artifact_mismatch',
                                         'missing_local_evidence', 'invalid_local_evidence', 'assessed', 'assessed')):
            row = {'type': 'row', 'id': hashlib.sha256(f'population {i}'.encode()).hexdigest(),
                   'observed_at': 100, 'raw_sha256': None, 'fingerprint': None, 'simhash': None,
                   'complete': i == 5, 'features_complete': True, 'decision': None, 'tagged': False,
                   'label': {'status': 'consensus', 'unwanted': bool(i % 2), 'labelled_at': 101,
                             'authorized_votes': 1, 'ignored_votes': 0},
                   'evidence_status': 'smtp', 'availability_profile': None if i == 2 else 'complete',
                   'assessment': assessment, 'prediction': copy.deepcopy(prediction) if assessment == 'assessed' else None}
            if i == 4:
                row['prediction'].update(tag_eligible=False, would_tag=False)
            rows.append(row)
        header = {'type': 'header', 'schema': 'noisefence-population-predictions-1', 'source': {},
                  'protocol_sha256': protocol.sha256, 'model_sha256': 'b'*64,
                  'manifest_sha256': 'c'*64, 'hypothetical': True, 'production_eligible': False}
        footer = {'type': 'footer', 'schema': 'noisefence-population-predictions-1',
                  'population_sha256': 'a'*64, 'source_counts': {'exported': 6},
                  'counts': {'rows': 6, 'assessed': 2, 'unassessable': 4, 'artifact_mismatch': 1,
                             'ineligible_to_tag': 1, 'unsupported_profiles': 0, 'would_tag': 1}}
        return [header, *rows, footer]

    def test_population_v2_local_failures_stay_in_denominators_and_are_version_scoped(self):
        p = self.population()
        protocol = self.f.protocol_for_hash(self.f.KNOWN_PROTOCOLS[1][0])
        data = self.prediction_envelope(protocol)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'predictions.jsonl'
            path.write_text(''.join(json.dumps(r)+'\n' for r in data))
            _, rows, footer = p.checked_predictions(path, 'a'*64, 'b'*64, 'c'*64, protocol)
            self.assertEqual(footer['counts']['artifact_mismatch'], 1)
            truth = [{'spam': bool(i % 2)} for i in range(6)]
            values = [row['prediction']['would_tag'] if row['prediction'] is not None else None for row in rows]
            metrics = p.outcome_metrics(truth, values, [[i] for i in range(6)])
            self.assertEqual((metrics['population'], metrics['unassessable']), (6, 4))
            self.assertEqual((metrics['conservative_on_known_truth']['fp'],
                              metrics['conservative_on_known_truth']['fn']), (2, 2))
            data[0]['protocol_sha256'] = self.f.PROTOCOL_HASH
            path.write_text(''.join(json.dumps(r)+'\n' for r in data))
            with self.assertRaisesRegex(ValueError, 'Unknown assessment status'):
                p.checked_predictions(path, 'a'*64, 'b'*64, 'c'*64)

    def test_population_v2_rejects_wrong_protocol_profile_status_and_counter_bindings(self):
        p = self.population()
        protocol = self.f.protocol_for_hash(self.f.KNOWN_PROTOCOLS[1][0])
        original = self.prediction_envelope(protocol)
        mutations = [
            lambda d: d[0].update(protocol_sha256=self.f.PROTOCOL_HASH),
            lambda d: d[0].update(local_binding=self.binding()),
            lambda d: d[0].update(model_sha256='f'*64),
            lambda d: d[3].update(availability_profile='complete'),
            lambda d: d[4].update(assessment='unknown_local_state'),
            lambda d: d[-1]['counts'].update(artifact_mismatch=3),
            lambda d: d[-1]['counts'].update(unassessable=3),
            lambda d: d[-1]['counts'].update(would_tag=True),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'predictions.jsonl'
            for i, mutate in enumerate(mutations):
                data = copy.deepcopy(original)
                mutate(data)
                path.write_text(''.join(json.dumps(r)+'\n' for r in data))
                with self.subTest(index=i), self.assertRaises(ValueError):
                    p.checked_predictions(path, 'a'*64, 'b'*64, 'c'*64, protocol)


if __name__ == '__main__':
    unittest.main()
