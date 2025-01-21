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
$ python lib/get_issues.py <tenant/managed> \
  --url https://issues.redhat.com
  --query 'project = KONFLUX AND status = "NEW" AND fixVersion = CY25Q1'
  --credentials-file /path/to/credentials.json
["KONFLUX-1", "KONFLUX-2", "KONFLUX-3", ...]
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
