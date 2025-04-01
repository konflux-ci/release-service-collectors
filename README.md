# Release Service Collectors

Collection of scripts run by the Collector Framework on the Release Service of Konflux.

## Usage

### Template

The template collector works by cloning a repository and rendering the contents of a certain
file using Python's template system with the values of the environment. The variables to be rendered
should be in the form of `{VARIABLE_NAME}` for example `{VERSION}`, `{HOME}` or `{PATH}`.

Example file to be templated:
```
{
  "text": "This text contains the value of the variable ENV_VAR: {ENV_VAR}"
}
```

Example execution:
```
$ export ENV_VAR="5"
$ python lib/template.py <tenant/managed> \
  --git https://example.com/repository/template.git \
  --branch main \
  --path path/to/the/file
{
  "text": "This text contains the value of the variable ENV_VAR: 5"
}
```

### Jira Issues

The Jira collector works by running a JQL (Jira Query Language) query against a Jira instance. It
requires a JSON file with a key called `api_token` that contains an API token to authenticate
against the Jira instance. The script returns a hardcoded amount of 50 results maximum.

Example of credentials file:
```
{
    "api_token": "some_token"
}
```

Example execution:
```
$ python lib/jira.py <tenant/managed> \
  --url https://issues.redhat.com \
  --query 'project = KONFLUX AND status = "NEW" AND fixVersion = CY25Q1' \
  --credentials-file /path/to/credentials.json \
  --release release.json \
  --previousRelease previous_release.json 
{
  "releaseNotes": {
    "issues": {
      "fixed": [
        { "id": "CPAAS-1234", "source": "issues.redhat.com" },
        { "id": "CPAAS-5678", "source": "issues.redhat.com" }
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
