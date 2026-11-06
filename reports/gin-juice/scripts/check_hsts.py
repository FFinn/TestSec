#!/usr/bin/env python3
"""Check only allowlisted HTTPS paths; save redacted headers, never bodies/cookies."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    opener = urllib.request.build_opener(NoRedirect())
    results = []
    for repeat in (1, 2):
        for name, path in [('catalog', '/catalog'), ('login', '/login'), ('account', '/my-account')]:
            time.sleep(1)
            url = 'https://ginandjuice.shop' + path
            request = urllib.request.Request(url, headers={'User-Agent': 'Course-HSTS-Check/1.0'})
            try:
                response = opener.open(request, timeout=25)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                headers = []
                for key, value in response.headers.items():
                    if key.lower() == 'set-cookie':
                        value = re.sub(r'^([^=]+)=[^;]*', r'\1=REDACTED', value)
                    headers.append(f'{key}: {value}')
                hsts = response.headers.get_all('Strict-Transport-Security') or []
                status = response.status
                expected = 302 if name == 'account' else 200
                if status != expected:
                    raise RuntimeError(f'Unexpected status for {path}: {status}; no finding recorded')
                if name == 'account' and response.headers.get('Location') != '/login':
                    raise RuntimeError('Unexpected account redirect; no finding recorded')
                stamp = datetime.now(timezone.utc).isoformat()
                result = f'{path} repeat={repeat} status={status} HSTS={hsts!r}'
                args.output.joinpath(f'hsts-{name}-{repeat}.txt').write_text(
                    f'Captured UTC: {stamp}\nRequest: GET {url}\n'
                    'No Cookie, Authorization or injected headers sent. Redirects not followed.\n'
                    f'Status: {status}\n' + '\n'.join(headers) + '\n\n' + result + '\n', encoding='utf-8')
                results.append(result)
                if hsts:
                    raise RuntimeError(f'HSTS present at {path}; absence finding not reproduced')
    summary = '\n'.join(results) + '\nCONFIRMED: HSTS absent in all six observed responses.\n'
    args.output.joinpath('hsts-summary.txt').write_text(summary, encoding='utf-8')
    print(summary)

if __name__ == '__main__':
    main()
