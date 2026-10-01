#!/usr/bin/env python3
"""Refuse retired server Passkeys sources in the running-door producer graph."""
import sys
import tomllib
from pathlib import Path
from urllib.parse import urlsplit


def check(packages):
    keyhole = False
    for package in packages:
        source = urlsplit(package.get('source', '').removeprefix('git+'))
        if source.hostname != 'github.com':
            continue
        path = source.path.rstrip('/').removesuffix('.git').lower()
        if path == '/corbet-foss/cpky':
            raise ValueError('Retired server source in door graph')
        if path == '/corbet-foss/ckyh' and package['name'] == 'ckyh':
            keyhole = True
    if not keyhole:
        raise ValueError('Missing current Keyhole server in door graph')


if __name__ == '__main__':
    current = {'name': 'ckyh', 'source': 'git+https://github.com/corbet-foss/ckyh?branch=main#' + 'a' * 40}
    retired = {'name': 'cpky', 'source': 'git+https://github.com/corbet-foss/cpky?branch=main#' + 'b' * 40}
    check([current])
    for invalid in ([], [retired], [current, retired]):
        try:
            check(invalid)
        except ValueError:
            continue
        raise AssertionError('Invalid server dependency graph accepted')
    if '--self-test' not in sys.argv:
        check(tomllib.loads(Path(sys.argv[1]).read_text())['package'])
    print('Door dependency source checks passed')
