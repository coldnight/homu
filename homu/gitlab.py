"""GitHub interactions."""
import json
import time

import gitlab


CommonError = gitlab.exceptions.GitlabError


def set_ref(repo, ref, sha, *, force=False, auto_create=True, retry=1):
    branch_name = ref[len("heads/"):] if ref.startswith('heads') else ref

    # Delete branch first
    try:
        repo.branches.delete(branch_name)
    except CommonError:
        pass

    repo.branches.create({"branch": branch_name, "ref": sha})


class Status:
    def __init__(self, info):
        self.state = info.status
        self.context = info.name


def iter_statuses(repo, sha):
    for item in repo.commits.get(sha).statuses.list():
        yield Status(item)


def create_status(
        repo, sha, state, target_url='', description='', *,
        context='',
):
    data = {
        'state': state, 'target_url': target_url,
        'description': description, 'context': context,
    }
    repo.commits.get(sha).statuses.create(data)


def login(host, access_token):
    return gitlab.Gitlab(host, private_token=access_token)


def iter_issue_comments(repo, num):
    return repo.mergerequests.get(num).notes.list()


def get_ref_sha(repo, ref):
    branch_name = ref[len("heads/"):] if ref.startswith('heads/') else ref
    return repo.branches.get(branch_name).commit["id"]


def get_pull_request_sha(repo, num):
    return repo.mergerequests.get(num).sha


def get_pull_request_user(repo, num):
    return repo.mergerequests.get(num).author.username


def is_pull_request_mergeable(repo, num):
    return repo.mergerequests.get(num).merge_status == "can_be_merged"


def get_parent_shas(repo, sha):
    return repo.commit(sha).parent_ids


def get_commit(repo, sha):
    return repo.commits.get(sha)


def is_collaborator(repo, username):
    return True


def get_repository(gitlab, owner, name):
    return gitlab.projects.get("{owner}/{name}".format(owner=owner, name=name))
