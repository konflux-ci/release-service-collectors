# Release Service Collectors

Collection of scripts run by the Collector Framework on the Release Service of Konflux.

## Usage

### Jira Issues

The Jira collector works by running a JQL (Jira Query Language) query against Jira Cloud. It
requires a k8s secret defined on the cluster. This secret should reside in the same namespace as the Release.

The secret must contain:
- `email`: Service account email for Jira Cloud authentication
- `apitoken`: API token generated at [id.atlassian.com](https://id.atlassian.com/manage-profile/security/api-tokens)

Example of k8s secret:
```
{
  "kind": "Secret",
  "apiVersion": "v1",
  "metadata": {
    "name": "jira-collectors-secret",
    "namespace": "dev-release-team-tenant"
  },
  "data": {
    "email": "Y252LWNpLXJlbGVhc2UtZ3JvdXArY252LWRvd25zdHJlYW0tYm90QHJlZGhhdC5jb20=",
    "apitoken": "QVRBVFQzeEZmR0YwVmpPUC4uLg=="
  },
  "type": "Opaque"
}
```

Example execution:
```
$ python lib/jira.py <tenant/managed> \
  --url https://redhat.atlassian.net \
  --query 'project = KONFLUX AND status = "NEW" AND fixVersion = CY25Q1' \
  --secretName jira-collectors-secret \
  --limit 50 \
  --release release.json \
  --previousRelease previous_release.json 
{
  "releaseNotes": {
    "issues": {
      "fixed": [
        { "id": "CPAAS-1234", "source": "redhat.atlassian.net", "summary": "summary 1..", "cveid": "CVE-2345" },
        { "id": "CPAAS-5678", "source": "redhat.atlassian.net", "summary": "summary 2..", "cveid": "CVE-2349" }
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
