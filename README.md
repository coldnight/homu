# GitLab Homu

[![Hommando]][Akemi Homura]

homu-gitlab is a bot that based on [homu], add support for GitLab via integrates with [GitLab Pipelines].

[homu]: https://github.com/servo/homu
[Hommando]: https://i.imgur.com/j0jNvHF.png
[Akemi Homura]: https://wiki.puella-magi.net/Homura_Akemi
[GitLab Pipelines]: https://docs.gitlab.com/ee/ci/pipelines.html

See more detail in [homu].

## Usage

### How to install

```sh
$ sudo apt-get install python3-venv
$ pyvenv .venv
$ . .venv/bin/activate
$ git clone https://github.com/coldnight/homu-gitlab.git
$ pip install -e homu-gitlab
```

### How to configure

In the following instructions, `HOST` refers to the hostname (or IP address)
where you are running your custom homu instance. `PORT` is the port the service
is listening to and is configured in `web.port` in `cfg.toml`. `NAME` refers to
the name of the repository you are configuring homu for.

1. Copy `cfg.sample.toml` to `cfg.toml`. You'll need to edit this file to set up
   your configuration. The following steps explain where you can find important
   config values.

2. Go to the user settings of the GitHub account you created/used in the
   previous step. Go to "Personal access tokens". Click "Create person access\_token" and
   choose the "api" and "read\_user" scopes. Put the token value in your `cfg.toml`.

3. Add your new GitLab account as a Collaborator to the GitLub project you are
   setting up homu for. This can be done in repo (NOT user) "Settings", then
   "Members".

4. Add a Webhook to your repository. This is done under project(NOT user)
   "Settings", then "Integrations". the set:
   - URL: `http://HOST:PORT/gitlab`
   - Secret Token: The same as `repo.NAME.github.secret` in `cfg.toml`
   - Events: `Push events`, `Comments`, `Merge Request events`, `Job events`

5. Add a job in your `.gitlab-ci.yml`

   ```yaml
   auto-test:
       only:
           - auto
       script:
           - some test commands

6. Go through the rest of your `cfg.toml` and uncomment (and change, if needed)
   parts of the config you'll need.


### How to run

```sh
$ . .venv/bin/activate
$ homu
```
