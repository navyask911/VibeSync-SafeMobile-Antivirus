import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import generate_translations as generation


class TranslationGenerationTests(unittest.TestCase):
    def test_placeholders_survive_and_modified_tokens_fail(self):
        source = 'Scanned %1$d apps from %2$s\\nDone'
        protected, tokens = generation.protect(source)
        result = generation.restore(protected.replace('Scanned', 'Analysé'), tokens)
        generation.validate(source, result)
        with self.assertRaises(ValueError):
            generation.restore(protected.replace('ZXQKEEP0QXZ', 'wrong'), tokens)

    def test_english_is_rejected_and_product_identifiers_allowed(self):
        with self.assertRaises(ValueError):
            generation.validate('Scan now', 'Scan now')
        generation.validate('YARA', 'YARA')
        with self.assertRaises(ValueError):
            generation.validate('Scan', '')

    def test_failed_provider_does_not_overwrite_locale(self):
        class FailedTranslator:
            def translate(self, text):
                raise RuntimeError('provider rate limit')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'values').mkdir()
            (root / 'values-fr').mkdir()
            (root / 'values/strings.xml').write_text('<resources><string name="scan">Scan now</string></resources>')
            original = '<resources><string name="scan">Analyser</string></resources>'
            target = root / 'values-fr/strings.xml'
            target.write_text(original)
            with self.assertRaises(RuntimeError):
                generation.generate_locale(root, 'fr', 'fr', FailedTranslator(), {}, root / 'cache.json', 0, 0)
            self.assertEqual(original, target.read_text())

    def test_locale_generation_includes_secondary_resources_and_removes_duplicate_fallback(self):
        class Translator:
            def translate(self, text):
                return {'Scan ZXQKEEP0QXZ apps': 'Analyser ZXQKEEP0QXZ applications',
                        'Alert': 'Alerte'}[text]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'values').mkdir()
            (root / 'values-fr').mkdir()
            (root / 'values/strings.xml').write_text('<resources><string name="scan">Scan %1$d apps</string></resources>')
            (root / 'values/incident.xml').write_text('<resources><string name="alert">Alert</string></resources>')
            (root / 'values-fr/fallback.xml').write_text('<resources><string name="alert">Alert</string></resources>')
            count = generation.generate_locale(root, 'fr', 'fr', Translator(), {}, root / 'cache.json', 0, 0)
            self.assertEqual(2, count)
            self.assertEqual(2, generation.validate_locale(root, 'fr'))
            self.assertFalse((root / 'values-fr/fallback.xml').exists())


if __name__ == '__main__':
    unittest.main()
