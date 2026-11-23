"""Offline, fail-closed reconnaissance evidence inventory (Python standard library)."""
import argparse
import hashlib
import html
import ipaddress
import json
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit, urlunsplit


class EvidenceError(ValueError):
    pass


def host(value):
    if not isinstance(value, str) or not value or value != value.strip():
        raise EvidenceError('invalid host')
    try:
        return 'ip', str(ipaddress.ip_address(value))
    except ValueError:
        pass
    value = value.removesuffix('.').lower()
    if len(value) > 253 or not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+', value):
        raise EvidenceError('invalid ASCII DNS name')
    if all(part.isdigit() for part in value.split('.')):
        raise EvidenceError('ambiguous numeric host')
    if any(len(p) > 63 or p.startswith('-') or p.endswith('-') for p in value.split('.')):
        raise EvidenceError('invalid DNS label')
    return 'domain', value


def endpoint(value):
    if not isinstance(value, str) or any(ord(c) <= 32 or ord(c) == 127 for c in value) or '\\' in value:
        raise EvidenceError('invalid URL')
    try:
        u = urlsplit(value)
        if u.scheme not in ('http', 'https') or not u.hostname or u.username is not None or u.password is not None or '#' in value:
            raise EvidenceError('URL must be HTTP(S), without credentials or fragment')
        kind, name = host(u.hostname)
        port = u.port
        if port is not None and not 1 <= port <= 65535:
            raise EvidenceError('invalid port')
        authority = '[' + name + ']' if ':' in name else name
        if port is not None and port != {'http': 80, 'https': 443}[u.scheme]:
            authority += ':' + str(port)
        normalized = urlunsplit((u.scheme, authority, u.path or '/', u.query, ''))
        if '?' in value and not u.query:
            normalized += '?'
        return normalized, (kind, name)
    except ValueError as exc:
        raise EvidenceError(str(exc)) from exc


class Scope:
    def __init__(self, data):
        if not isinstance(data, dict) or set(data) != {'domains', 'networks', 'endpoints'}:
            raise EvidenceError('allowlist requires only domains, networks, endpoints arrays')
        if any(not isinstance(v, list) or any(not isinstance(x, str) for x in v) for v in data.values()):
            raise EvidenceError('allowlist entries must be strings')
        self.domains = set()
        for rule in data['domains']:
            wildcard = rule.startswith('*.')
            kind, name = host(rule[2:] if wildcard else rule)
            if kind != 'domain':
                raise EvidenceError('domain rule cannot be an IP')
            self.domains.add(('*.' if wildcard else '') + name)
        try:
            self.networks = [ipaddress.ip_network(x, strict=True) for x in data['networks']]
        except ValueError as exc:
            raise EvidenceError('invalid CIDR') from exc
        self.endpoints = {endpoint(x)[0] for x in data['endpoints']}

    def permits(self, kind, value):
        if kind == 'ip':
            return any(ipaddress.ip_address(value) in n for n in self.networks)
        if kind == 'endpoint':
            return value in self.endpoints and self.permits(*endpoint(value)[1])
        return value in self.domains or any(r.startswith('*.') and value.endswith('.' + r[2:]) for r in self.domains)


def parse_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise EvidenceError('duplicate JSON key')
            result[key] = value
        return result
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError('nonfinite number')))
    except (ValueError, TypeError) as exc:
        raise EvidenceError(str(exc)) from exc


def records(raw):
    text = raw.decode('utf-8')
    if text.lstrip().startswith('['):
        items = parse_json(text)
    else:
        items = [parse_json(line) for line in text.splitlines() if line.strip()]
    if not items or any(not isinstance(x, dict) for x in items):
        raise EvidenceError('expected nonempty JSON object records or array')
    return items


def candidates(tool, row):
    found = []
    def add_host(value):
        found.append(host(value))
    def add_url(value):
        url, target = endpoint(value)
        found.extend([('endpoint', url), target])
    def many(key, fn):
        if key in row:
            if not isinstance(row[key], list):
                raise EvidenceError(key + ' must be an array')
            for value in row[key]:
                fn(value)
    if tool in ('subfinder', 'dnsx'):
        add_host(row.get('host'))
    elif tool == 'httpx':
        add_url(row.get('url'))
        for key in ('host', 'host_ip'):
            if key in row:
                add_host(row[key])
        for key in ('final_url', 'location'):
            if key in row:
                add_url(row[key])
    else:
        raise EvidenceError('unsupported tool')
    for key in ('a', 'aaaa'):
        def add_ip(value):
            kind, name = host(value)
            if kind != 'ip':
                raise EvidenceError(key + ' must contain IP addresses')
            found.append((kind, name))
        many(key, add_ip)
    for key in ('cname', 'ns', 'ptr', 'mx'):
        many(key, add_host)
    return sorted(set(found))


def build(scope, inputs):
    assets, rejected, sources = {}, [], {}
    for tool, path in inputs:
        raw = Path(path).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        source = tool + ':' + digest
        sources[source] = {'tool': tool, 'sha256': digest}
        for index, row in enumerate(records(raw), 1):
            ref = {'source': source, 'record': index}
            try:
                values = candidates(tool, row)
            except EvidenceError as exc:
                rejected.append({**ref, 'reason': 'invalid_record', 'detail': str(exc)})
                continue
            # Record-level quarantine prevents partial trusted relationships.
            denied = [{'kind': k, 'value': v} for k, v in values if not scope.permits(k, v)]
            if denied:
                rejected.append({**ref, 'reason': 'out_of_scope', 'assets': denied})
                continue
            for key in values:
                assets.setdefault(key, set()).add((source, index))
    unique_rejections = {json.dumps(r, sort_keys=True): r for r in rejected}
    return {'version': '0.2', 'sources': dict(sorted(sources.items())),
            'assets': [{'kind': k, 'value': v, 'references': [{'source': s, 'record': i} for s, i in sorted(refs)]}
                       for (k, v), refs in sorted(assets.items())],
            'rejected': [unique_rejections[k] for k in sorted(unique_rejections)]}


def markdown(report):
    def safe(value):
        return html.escape(str(value)).replace('|', '&#124;').replace('\n', '&#10;').replace('`', '&#96;')
    lines = ['# Authorized asset inventory', '', f"Accepted assets: {len(report['assets'])}; rejected records: {len(report['rejected'])}", '', '| Kind | Asset | Evidence references |', '| --- | --- | --- |']
    for item in report['assets']:
        refs = ', '.join(f"{r['source']}#{r['record']}" for r in item['references'])
        lines.append(f"| {item['kind']} | {safe(item['value'])} | {refs} |")
    lines += ['', '## Rejected records', '']
    lines.extend('- ' + safe(json.dumps(r, sort_keys=True)) for r in report['rejected'])
    return '\n'.join(lines) + '\n'


def publish(report, output):
    """Reserve a new destination; a persistent marker guards partial publication."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    marker = output / '.inventory-incomplete'
    marker.mkdir()
    # Stage both serialized reports before exposing either final report file.
    # The marker survives write, rename, cleanup, and interruption failures.
    with tempfile.TemporaryDirectory(prefix='.staging-', dir=output) as staging:
        staging = Path(staging)
        (staging / 'inventory.json').write_text(
            json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        (staging / 'inventory.md').write_text(markdown(report), encoding='utf-8')
        for name in ('inventory.json', 'inventory.md'):
            (staging / name).replace(output / name)
    marker.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allowlist', required=True)
    for tool in ('subfinder', 'dnsx', 'httpx'):
        parser.add_argument('--' + tool, action='append', default=[])
    parser.add_argument('--output', required=True, help='new output directory')
    args = parser.parse_args()
    try:
        inputs = [(t, p) for t in ('subfinder', 'dnsx', 'httpx') for p in getattr(args, t)]
        if not inputs:
            raise EvidenceError('at least one evidence file is required')
        report = build(Scope(parse_json(Path(args.allowlist).read_text())), inputs)
        publish(report, args.output)
    except (ValueError, OSError, UnicodeError) as exc:
        parser.exit(2, f'error: {exc}\n')
    return 1 if report['rejected'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
