"""GitHub interactions."""
import json
import time

import github3


CommonError = github3.models.GitHubError


def set_ref(repo, ref, sha, *, force=False, auto_create=True, retry=1):
    url = repo._build_url('git', 'refs', ref, base_url=repo._api)
    data = {'sha': sha, 'force': force}

    try:
        js = repo._json(repo._patch(url, data=json.dumps(data)), 200)
    except github3.models.GitHubError as e:
        if e.code == 422 and auto_create:
            try:
                return repo.create_ref('refs/' + ref, sha)
            except github3.models.GitHubError:
                raise e
        elif e.code == 422 and retry > 0:
            time.sleep(5)
            return set_ref(
                repo,
                ref,
                sha,
                force=force,
                auto_create=auto_create,
                retry=retry - 1,
            )
        else:
            raise

    return github3.git.Reference(js, repo) if js else None


class Status(github3.repos.status.Status):
    def __init__(self, info):
        super(Status, self).__init__(info)

        self.context = info.get('context')


def iter_statuses(repo, sha):
    url = repo._build_url('statuses', sha, base_url=repo._api)
    return repo._iter(-1, url, Status)


def create_status(
        repo, sha, state, target_url='', description='', *,
        context='',
):
    data = {
        'state': state, 'target_url': target_url,
        'description': description, 'context': context,
    }
    url = repo._build_url('statuses', sha, base_url=repo._api)
    js = repo._json(repo._post(url, data=data), 201)
    return Status(js) if js else None


def merge(repo, branch, head_sha, merge_msg):
    try:
        merge_commit = repo.merge(
            branch,
            head_sha,
            merge_msg,
        )
    except github3.models.GitHubError as e:
        if e.code != 409:
            raise
    else:
        return merge_commit.sha if merge_commit else ''


def login(access_token):
    return github3.login(token=access_token)


def iter_issue_comments(repo, num):
    return repo.issue(num).iter_comments()


def get_ref_sha(repo, ref):
    return repo.ref(ref).object.sha


def get_pull_request_sha(repo, num):
    return repo.pull_request(num).head.sha


def get_pull_request_user(repo, num):
    return repo.pull_request(num).user.login


def is_pull_request_mergeable(repo, num):
    pull_request = repo.pull_request(num)
    if pull_request is None or pull_request.mergeable is None:
        time.sleep(5)
        pull_request = repo.pull_request(num)
    return pull_request is not None and pull_request.mergeable


def get_parent_shas(repo, sha):
    _parents = repo.commit(sha).parents
    return [x['sha'] for x in _parents]


def get_commit(repo, sha):
    return repo.commit(sha)


def is_collaborator(repo, username):
    return repo.is_collaborator(username)
