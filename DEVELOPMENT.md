# DEVELOPMENT

To test the collectors you need to have control over the `ReleasePlanAdmission` of your application.
The main idea is to use your fork of the [`release-service-catalog`](https://github.com/konflux-ci/release-service-catalog)
so your version of the `run-collectors` Pipeline pulls the branch you want to test from `release-service-collectors`.

This can be achieved even in a staging or production environment, however we do recommend
you deploy a local Konflux instance and use a test repository as an application.

## Local Testing

We recommend using KinD to deploy Konflux. For that go over the docs at [konflux-ci/konflux-ci](https://github.com/konflux-ci/konflux-ci?tab=readme-ov-file#local-development-kind).
After the cluster is deployed, we provide resources you can provide for manual testing. However
you need to customize them to point to your organization resources:


```bash
$ grep -r CHANGEME resources/
resources/ns2/integration-test-hello.yaml:        value: https://github.com/<CHANGEME-ORG>/testrepo.git
resources/ns2/application-and-component.yaml:      url: https://github.com/<CHANGEME-ORG>/testrepo.git
resources/ns2/application-and-component.yaml:  url: https://github.com/<CHANGEME-ORG>/testrepo.git
resources/ns2/release-plan.yaml:          value: https://github.com/<CHANGEME-ORG>/testrepo.git
resources/ns2/jira-collectors-secret.yaml:  email: <CHANGEME-JIRA-ACCOUNT>
resources/ns2/jira-collectors-secret.yaml:  apitoken: <CHANGEME-JIRA-TOKEN>
resources/managed-ns2/rpa.yaml:          value: https://github.com/<CHANGEME-USER>/release-service-catalog.git
resources/managed-ns2/rpa.yaml:          value: <CHANGEME-BRANCH>
```

In your [`release-service-catalog`](https://github.com/konflux-ci/release-service-catalog) fork
you need to change the `run-collectors.yaml` which defines the `run-collectors` Pipeline. You
specifically need to change the `collectorsRepository` and `collectorsRepositoryRevision`.
This change makes the Pipeline pull the collectors branch under test:

```yaml
    - name: collectorsRepository
      type: string
      description: Git repository where the collectors will be defined
      default: https://github.com/<CHANGEME-USER>/release-service-collectors.git
    - name: collectorsRepositoryRevision
      type: string
      description: Git repository revision
      default: <CHANGEME-BRANCH>
```

After pushing this to a branch in your fork of `release-service-catalog` make sure that the
ReleasePlanAdmission on `resources/` points to that same branch, otherwise your collector
changes won't be tested.

Then you can apply the resources:

```bash
kubectl apply -k resources/
```

Now log in with the `user2@konflux.dev` user, navigate to the `test-component` and start a build.
When the build finishes a Release should automatically happen. This release should have a collectors
pipeline related to it. That should pull your branch for testing.

Now each time you introduce a change in the collectors you need to push them and re-trigger the release.
Do not trigger another build unless really needed, as it is time-consuming.

## Local Standalone Testing

After the first release has been triggered if you want a faster development cycle you can write the release
into a file and call the collectors manually passing the release to them. Some collectors will pull stuff
from the cluster using `kubectl`. If you don't want to keep the cluster around you can get all of these
resources and patch the collectors to read from files instead of pulling from the cluster.
