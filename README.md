# Release Service Collectors

Collection of scripts run by the Collector Framework on the Release Service of Konflux.

## Usage

### Jira Issues

The Jira collector works by running a JQL (Jira Query Language) query against a Jira instance. It
requires a k8s secret defined on the cluster. This secret should reside in the same namespace as the Release.
It should contain a key called `api_token` that holds the API token to authenticate
against the Jira instance. The script returns a hardcoded amount of 50 results maximum.

Example of k8s secret:
```
{
  "kind": "Secret",
  "apiVersion": "v1",
  "metadata": {
    "name": "jira-collectors-secret",
    "namespace": "dev-release-team-tenant",
  },
  "data": {
    "apitoken": "c2NvdHRvCg=="
  },
  "type": "Opaque"
}
```

Example execution:
```
$ python lib/jira.py <tenant/managed> \
  --url https://issues.redhat.com \
  --query 'project = KONFLUX AND status = "NEW" AND fixVersion = CY25Q1' \
  --secretName jira-collectors-secret \
  --release release.json \
  --previousRelease previous_release.json 
{
  "releaseNotes": {
    "issues": {
      "fixed": [
        { "id": "CPAAS-1234", "source": "issues.redhat.com", "summary": "summary 1..", "cveid": "CVE-2345" },
        { "id": "CPAAS-5678", "source": "issues.redhat.com", "summary": "summary 2..", "cveid": "CVE-2349" }
      ]
    }
  }
}
```

### CVE

The CVE collector works by running the command against a git repository.
It requires 2 files currentRelease json file and previousRelease json file.
The script retreive all the components from the currentRelease.
It checks what CVEs where added to the git log between the current to previous release.
and retrun all the relevant CVEs per component

Example execution:
```
$python lib/cve.py <tenant/managed> \
  --release release.json \
  --previousRelease previous_release.json

{
    "releaseNotes": {
        "cves":  [
             { "key": "CVE-3444", "component": "my-component" },
             { "key": "CVE-3445", "component": "my-component" }
        ]
    }
}
```

The CVE collector supports private repositories. First you need to specify a
`--secretName` referencing a Kubernetes secret. The secret should
be in the following form:

```
{
  "kind": "Secret",
  "apiVersion": "v1",
  "metadata": {
    "name": "cve-collectors-secret",
    "namespace": "dev-release-team-tenant",
  },
  "data": {
    "my-group.my-repo": "c2NvdHRvCg==",
    ...
  },
  "type": "Opaque"
}
```

Each key on the secret should have a private key as value. If a key matches
a repository listed in the snapshot related with the release, the private key
is used for cloning the repository. The comparison strips the scheme from the
repositories listed on the snapshots. So to match the repository `https://gitlab.com/my-group/my-repo`
you need to specify `my-group.my-repo` on the Secret. Note the dot (`.`) to separate
the group from the repository.

The URL used for
cloning with SSH is derived from the HTTPS URL of the repository, so
`https://gitlab.com/my-group/my-repo` becomes `git@gitlab.com:my-group/my-repo`.
The private key is passed using the environment variable `GIT_SSH_COMMAND`.

### Convert YAML to JASON

This script gets a yaml file with jinja2 code and convert to json data.
This script doesn't run the jinja2 to render values.

Example execution:
```
python lib/convertyaml.py \
    tenant \
    --git https://gitlab.cee.redhat.com/gnecasov/container-errata-templates.git \
    --branch main \
    --path RHEL/XXXXX.yaml \
    --release release.json \
    --previousRelease previous_release.json 


{ "releaseNotes":
    {
        "synopsis": "{% if advisory.spec.type == \"RHSA\" %} RHSA {% endif %}\n", 
        "solution": "{% if advisory.spec.type == \"RHSA\" %} RHSA {% endif %}\n",
        "description": "{{Problem_description}}\n"
    }
}

```


## Tests

To install `pytest` you can do:

```
python -m venv venv
source venv/bin/activate
python -m pip install pytest
```

To run the tests, have `pytest` available and run:

```
python -m pytest
```
