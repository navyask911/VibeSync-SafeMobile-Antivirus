#!/usr/bin/env python3
"""Generate Android resources with GoogleTranslator; no English-copy fallback.

Install build-time dependencies: python3 -m pip install -r scripts/translation-requirements.txt
Run: python3 scripts/generate_translations.py
Validate previously generated resources without network: --validate-only

Only public UI resource text is sent to Google, never app data or source code.
Outputs are machine translations, not a guarantee of linguistic accuracy. Each
locale is staged and installed only after every resource validates. Cached
successful translations survive retries; failed calls never become English XML.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import tempfile
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / 'app/src/main/res'
# Android qualifier -> Google language. Preserve current Android Hebrew/Chinese paths.
LOCALES = dict(pair.split(':') for pair in (
    'af:af az:az bg:bg ca:ca cs:cs da:da de:de el:el es:es et:et fa:fa fi:fi '
    'fil:tl fr:fr gu:gu hi:hi hr:hr hu:hu id:id it:it ja:ja ka:ka kk:kk '
    'kn:kn ko:ko lt:lt lv:lv ml:ml mr:mr ms:ms nb:no ne:ne nl:nl pa:pa '
    'pl:pl pt:pt ro:ro ru:ru sk:sk sv:sv ta:ta te:te th:th tr:tr uk:uk '
    'ur:ur vi:vi ar:ar bn:bn b+he:iw zh-rCN:zh-CN'
).split())
TOKEN = re.compile(r'%(?:\d+\$)?[-#+ 0,(]*\d*(?:\.\d+)?[a-zA-Z%]|\\[nrt\\]|https?://[^\s]+')
# Tokens/product names legitimately retain their spelling; never exempt whole sentences.
INVARIANT = re.compile(r'^(?:[\W\d_]+|SafeMobile|VibeSync|YARA|SHA-256|MD5|APK|EXE|Android|OK|DM Sans)$')


def source_files(res: Path):
    return [p for p in sorted((res / 'values').glob('*.xml'))
            if any(x.tag == 'string' for x in ET.parse(p).getroot())]


def text_of(element):
    if list(element):
        raise ValueError('Nested markup needs explicit handling: ' + element.attrib['name'])
    # Android escaping is not prose and must not be translated as literal backslashes.
    return (element.text or '').replace("\\'", "'").replace('\\"', '"')


def protect(text):
    tokens = []
    def substitute(match):
        tokens.append(match.group())
        return f'ZXQKEEP{len(tokens)-1}QXZ'
    return TOKEN.sub(substitute, text), tokens


def restore(text, tokens):
    for i, token in enumerate(tokens):
        marker = f'ZXQKEEP{i}QXZ'
        if text.count(marker) != 1:
            raise ValueError('Translation altered a protected placeholder: ' + marker)
        text = text.replace(marker, token)
    if 'ZXQKEEP' in text:
        raise ValueError('Unexpected placeholder token in translation')
    return text


def validate(source, translated, resource_name=""):
    if resource_name.startswith("locale_") and source == translated:
        return  # Native language names in the language picker are intentional invariants.
    if not translated.strip():
        raise ValueError('Empty translation')
    if sorted(TOKEN.findall(source)) != sorted(TOKEN.findall(translated)):
        raise ValueError('Format arguments or escapes changed')
    if source.strip().casefold() == translated.strip().casefold() and not INVARIANT.fullmatch(source.strip()):
        raise ValueError('Unchanged English text requires review: ' + source[:90])


def android_escape(text):
    # Android requires apostrophes/quotes escaped even though XML itself does not.
    text = text.replace("'", "\\'").replace('"', '\\"')
    if text.startswith(('@', '?')):
        text = '\\' + text
    return text


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def translate_text(source, language, translator, cache, cache_path, retries, delay, resource_name=""):
    key = hashlib.sha256((language + '\0' + source).encode()).hexdigest()
    if resource_name.startswith('locale_') or INVARIANT.fullmatch(source.strip()):
        return source
    if key in cache:
        validate(source, cache[key], resource_name)
        return cache[key]
    protected, tokens = protect(source)
    for attempt in range(retries + 1):
        try:
            translated = restore(translator.translate(protected), tokens)
            validate(source, translated, resource_name)
            cache[key] = translated
            write_json(cache_path, cache)
            time.sleep(delay)
            return translated
        except Exception as error:
            if attempt == retries:
                raise RuntimeError(f'{language}: translation failed after {attempt+1} attempts: {error}') from error
            # Honor provider throttling; no proxy/IP rotation or English substitute.
            pause = min(45, max(delay, 5 * (2 ** attempt)))
            print(f'{language}: retry in {pause:g}s ({type(error).__name__})', flush=True)
            time.sleep(pause)
    raise AssertionError('unreachable')


def validate_locale(res, locale):
    errors = []
    actual = {}
    for path in (res / ('values-' + locale)).glob('*.xml'):
        for entry in ET.parse(path).getroot().findall('string'):
            key = entry.attrib['name']
            if key in actual:
                errors.append('Duplicate key: ' + key)
            actual[key] = entry
    count = 0
    for path in source_files(res):
        for entry in ET.parse(path).getroot().findall('string'):
            if entry.get('translatable') == 'false':
                continue
            key = entry.attrib['name']
            try:
                validate(text_of(entry), text_of(actual[key]), key)
                count += 1
            except (KeyError, ValueError) as error:
                errors.append(key + ': ' + str(error))
    if errors:
        raise ValueError(f'{locale}: ' + '; '.join(errors[:12]) + f' ({len(errors)} failures)')
    return count


def generate_locale(res, locale, language, translator, cache, cache_path, retries, delay):
    with tempfile.TemporaryDirectory(prefix='safemobile-i18n-') as temp:
        staging = Path(temp)
        folder = staging / ('values-' + locale)
        folder.mkdir()
        generated_keys = set()
        for path in source_files(res):
            output = ET.Element('resources')
            for original in ET.parse(path).getroot().findall('string'):
                if original.get('translatable') == 'false':
                    continue
                entry = copy.deepcopy(original)
                source = text_of(original)
                entry.text = android_escape(translate_text(source, language, translator, cache, cache_path, retries, delay, entry.attrib["name"]))
                entry.tail = None
                output.append(entry)
                generated_keys.add(entry.attrib['name'])
            ET.indent(output)
            ET.ElementTree(output).write(folder / path.name, encoding='utf-8', xml_declaration=True)
        # Validate before modifying existing resources. Includes every default string XML,
        # so posture, incident/siren and sentinel strings cannot silently fall back.
        (staging / 'values').mkdir()
        for path in source_files(res):
            (staging / 'values' / path.name).write_bytes(path.read_bytes())
        count = validate_locale(staging, locale)
        target = res / ('values-' + locale)
        target.mkdir(exist_ok=True)
        # Old fallback files may duplicate translated keys; preserve unrelated resources.
        for path in target.glob('*.xml'):
            tree = ET.parse(path)
            changed = False
            for entry in list(tree.getroot()):
                if entry.tag == 'string' and entry.get('name') in generated_keys:
                    tree.getroot().remove(entry)
                    changed = True
            if changed:
                if not list(tree.getroot()):
                    path.unlink()
                else:
                    tree.write(path, encoding='utf-8', xml_declaration=True)
        for path in folder.glob('*.xml'):
            (target / path.name).write_bytes(path.read_bytes())
        return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--locales', nargs='+', default=list(LOCALES))
    parser.add_argument('--res', type=Path, default=RES)
    parser.add_argument('--cache', type=Path, default=ROOT / 'build/translation-cache.json')
    parser.add_argument('--report', type=Path, default=ROOT / 'build/translation-report.json')
    parser.add_argument('--retries', type=int, default=3)
    parser.add_argument('--delay', type=float, default=0.5)
    parser.add_argument('--validate-only', action='store_true')
    args = parser.parse_args()
    if args.retries < 0 or args.delay < 0:
        parser.error('retries/delay must be nonnegative')
    unknown = set(args.locales) - LOCALES.keys()
    if unknown:
        parser.error('Unknown Android locales: ' + ', '.join(sorted(unknown)))
    cache = json.loads(args.cache.read_text()) if args.cache.exists() else {}
    report = {'provider': 'deep-translator/GoogleTranslator', 'human_reviewed': False, 'locales': {locale: {'status': 'pending'} for locale in args.locales}}
    if not args.validate_only:
        from deep_translator import GoogleTranslator
        # deep-translator has no request timeout option; bound every provider request.
        import deep_translator.google as provider
        original_get = provider.requests.get
        def bounded_get(*a, **kw):
            kw.setdefault('timeout', 20)
            return original_get(*a, **kw)
        provider.requests.get = bounded_get
    for locale in args.locales:
        try:
            if args.validate_only:
                count = validate_locale(args.res, locale)
            else:
                translator = GoogleTranslator(source='en', target=LOCALES[locale])
                count = generate_locale(args.res, locale, LOCALES[locale], translator, cache, args.cache, args.retries, args.delay)
            report['locales'][locale] = {'status': 'validated', 'keys': count}
            print(f'{locale}: validated {count} translated keys', flush=True)
        except Exception as error:
            report['locales'][locale] = {'status': 'failed', 'error': str(error)}
            write_json(args.report, report)
            # Provider failure usually affects every locale. Stop, retain cache and
            # existing translations; rerun resumes instead of generating English XML.
            if not args.validate_only:
                raise SystemExit(str(error))
            print(str(error), flush=True)
        write_json(args.report, report)
    if any(item['status'] != 'validated' for item in report['locales'].values()):
        raise SystemExit('Incomplete localization; see ' + str(args.report))
    print('Resource validation passed. Native-speaker linguistic review is still required.')


if __name__ == '__main__':
    main()
