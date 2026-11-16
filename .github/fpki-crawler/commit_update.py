"""Commit the updated files to a branch through the GitHub API.

A commit made this way is signed by GitHub, so it shows as verified. That matters because
staging only accepts signed commits. The branch is created from the given parent commit, or
replaced if an earlier run this week left it.

Usage: commit_update.py BRANCH PARENT_SHA MESSAGE PATH [PATH ...]
Needs GH_TOKEN and GITHUB_REPOSITORY. Prints the new commit SHA and whether it is verified.
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.request

API = os.environ.get('GITHUB_API_URL', 'https://api.github.com')
REPO = os.environ['GITHUB_REPOSITORY']
TOKEN = os.environ['GH_TOKEN']


def call(method, path, body=None):
    request = urllib.request.Request(
        f'{API}/repos/{REPO}/{path}', method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={'Authorization': f'Bearer {TOKEN}', 'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': '2022-11-28'})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if method == 'GET' and error.code == 404:
            return None
        sys.exit(f'{method} {path} failed: {error.code} {error.read().decode()[:500]}')


def main():
    branch, parent, message, *paths = sys.argv[1:]
    tree = []
    for path in paths:
        with open(path, 'rb') as handle:
            content = base64.b64encode(handle.read()).decode()
        blob = call('POST', 'git/blobs', {'content': content, 'encoding': 'base64'})
        tree.append({'path': path, 'mode': '100644', 'type': 'blob', 'sha': blob['sha']})

    base_tree = call('GET', f'git/commits/{parent}')['tree']['sha']
    new_tree = call('POST', 'git/trees', {'base_tree': base_tree, 'tree': tree})
    commit = call('POST', 'git/commits', {'message': message, 'tree': new_tree['sha'], 'parents': [parent]})

    if call('GET', f'git/ref/heads/{branch}'):
        call('PATCH', f'git/refs/heads/{branch}', {'sha': commit['sha'], 'force': True})
    else:
        call('POST', 'git/refs', {'ref': f'refs/heads/{branch}', 'sha': commit['sha']})

    verified = commit.get('verification', {}).get('verified', False)
    print(commit['sha'], 'verified' if verified else 'unverified')


if __name__ == '__main__':
    main()
