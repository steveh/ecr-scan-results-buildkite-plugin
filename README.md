# ECR Scan Results Buildkite Plugin

Buildkite plugin to retrieve ECR scan results from AWS's ECR image scanning
service. By default the plugin will cause the step to fail if there are critical
or high vulnerabilities reported, but there are configurable thresholds on this
behaviour.

> ℹ️ **TIP**: if you want the build to continue when vulnerabilities are found, be
> sure to supply values for `max-criticals` and `max-highs` parameters. If these
> are set to high values your build will never fail, but details will be
> supplied in the annotation.
>
> If a finding is irrelevant, or you're waiting on an upstream fix, use an
> "ignore" configuration file instead: see the [ignore
> findings](./docs/ignore-findings.md) documentation.

## Rendering

The plugin shows a detailed summary of the vulnerability findings in the scanned image using data pulled from AWS ECR. The summary is rendered as a Buildkite [build annotation](https://buildkite.com/docs/agent/v3/cli-annotate).

<figure>
<figcaption>
The default view summarizes the number of findings in the scan, hiding details behind an expanding element.
</figcaption>
<img src="docs/img/eg-success-collapsed.png" alt="example of successful check annotation with collapsed results table">
</figure>

<figure>
<figcaption>
When a threshold is exceeded, the annotation is rendered as an error.
</figcaption>
<img src="docs/img/eg-failed-collapsed.png" alt="example of failed check annotation with collapsed results table" width="80%" align="center">
</figure>

<figure>
<figcaption>
The details view can be expanded, showing a table of the vulnerability findings from the scan. Findings link to the CVE database in most cases. The CVSS vector links to the <a href="https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV%3AN%2FAC%3AL%2FPR%3AN%2FUI%3AN%2FS%3AU%2FC%3AN%2FI%3AN%2FA%3AH&version=3.1">CVSS calculator</a>, allowing for exploration of the potential impact and enabling environmental scoring.
</figcaption>
<img src="docs/img/eg-success-expanded.png" alt="example of successful check annotation with collapsed results table" width="80%" align="center">
</figure>

## Example

Add the following lines to your `pipeline.yml`:

```yml
steps:
  - command: "command which creates an image"
    # the docker-compose plugin may be used here instead of a command
    plugins:
      - cultureamp/ecr-scan-results#v1.2.0:
          image-name: "$BUILD_REPO:deploy-$BUILD_TAG"
```

In a pipeline this will look something like:

```yml
steps:
  - label: ":docker: Build and push CDK deployment image"
    command: "bin/ci_cdk_build_and_push.sh"
    agents:
      queue: ${BUILD_AGENT}
    plugins:
      - cultureamp/aws-assume-role:
          role: ${BUILD_ROLE}
      - cultureamp/ecr-scan-results#v1.2.0:
          image-name: "$BUILD_REPO:deploy-$BUILD_TAG"
```

If you want the pipeline to pass with some vulnerabilities then set
`max-criticals` and `max-highs` like below. This pipeline will pass if there is
one critical vulenerability but fail if there are two. Similarly it will fail if
there are eleven high vulnerabilities.

```yml
steps:
  - label: ":docker: Build and push CDK deployment image"
    command: "bin/ci_cdk_build_and_push.sh"
    agents:
      queue: ${BUILD_AGENT}
    plugins:
      - cultureamp/aws-assume-role:
          role: ${BUILD_ROLE}
      - cultureamp/ecr-scan-results#v1.2.0:
          image-name: "$BUILD_REPO:deploy-$BUILD_TAG"
          max-criticals: "1"
          max-highs: "10"
```

## Configuration

### `image-name` (Required, string)

The name of the container image in ECR. This should be the same string that is
supplied as an arguement to the `docker push` command used to push the image to
AWS ECR. It should have the form:
`AWS_ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/REPOSITORY_NAME:IMAGE_TAG` with the
text in capitals replaced with the appropriate values for your environment.

### `max-criticals` (Optional, string)

If the number of critical vulnerabilities in the image exceeds this threshold
the build is failed. Defaults to 0. Use a sufficiently large number (e.g. 999)
to allow the build to always pass.

> [!IMPORTANT]
> Prefer an [ignore file](./docs/ignore-findings.md) over setting thresholds if
> a finding is irrelevant or time to respond is required.

### `max-highs` (Optional, string)

If the number of high vulnerabilities in the image exceeds this threshold the
build is failed. Defaults to 0. Use a sufficiently large number (e.g. 999) to
allow the build to always pass.

> [!IMPORTANT]
> Prefer an [ignore file](./docs/ignore-findings.md) over setting thresholds if
> a finding is irrelevant or time to respond is required.

### `image-label` (Optional, string)

When supplied, this is used to title the report annotation in place of the
repository name and tag. Useful sometimes when the repo name and tag make the
reports harder to scan visually.

## Requirements

### ECR Scan on Push

This plugin assumes that the ECR repository has the `ScanOnPush` setting set (see
the [AWS
docs](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html)
for more information). By default this is not set on AWS ECR repositories.
However `Base Infrastructure for Services` configures this for all repostories
that it creates so for `cultureamp` pipelines no change should be required.

### Agent role requires the ecr:DescribeImages permission

The Buildkite agent needs the AWS IAM `ecr:DescribeImages` permission to
retrieve the vulnerability scan counts. Culture Amp build-roles created by `Base
Infrastructure for Services` have all been modified to include this permission.

### Scratch images are not supported

ECR cannot scan scratch based images, and this should be OK as the underlying
container doesn't contain packages to scan.

If this plugin is installed and pointed at a scratch image you may receive an
error and it may block the pipeline as a result. The error
`UnsupportedImageError` is expected in this scenario; see [the ECR
docs](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-troubleshooting.html)
for more information.

## FAQ

### The build is failing for an unresolved vulnerability. How do I do configure this plugin so I can unblock my builds?

There are two options here:

1. configure an [ignore file](docs/ignore-findings.md) to tell the plugin to
  skip this vulnerability. Set an `until` date to ensure that it is dealt with
  in the future.
2. refer to how to set your [max-criticals](#max-criticals-optional-string), and
  [max-highs](#max-highs-optional-string) thresholds.

Out of the two options, the first is far more preferable as it targets the
finding that is causing the problem. Altering a threshold is unlikely to be
rolled back and is indiscriminate about the findings that it will ignore.

### How do I set my thresholds? _OR_ My build often breaks because of this plugin. Should I change the thresholds?

Setting the `max-criticals` and `max-high` thresholds requires some thought, and
needs to take into account the risk profile of the company and the service
itself.

Allowing a container with a critical or high vulnerability to be deployed is not
necessarily wrong, it really depends on the environment of the deployed
application and the nature of the vulnerabilities themselves.

Consult with your company's internal security teams about the acceptable risk
level for a service if a non-zero threshold is desired, and consider making use
of the [ignore file](docs/ignore-findings.md) configuration to avoid temporary
blockages. Using an ignore entry with an expiry is strongly recommended over
increasing the threshold.

### What should I think about when ignoring a finding for a period of time?

Consider the following:

- Follow the link to read the details of the CVE. Does it impact a component
  that is directly (or indirectly) used by your application?
- Reference the CVSS score associated with the vulnerability and look carefully
  at the vector via the link. The vector will help inform about how this
  vulnerability can affect your system.
- Consider using the CVSS calculator (reached via the vector link) to fill out
  the "Environmental" part of the score. The environmental score helps judge the
  risks posed in the context of your application deployment environment. This is
  likely adjust the base score and assist in your decision making.
- Is a patch or update already available?
- Is this update likely to be made available in an update to the current base
  image, or does it exist in a later version of the base image?

Possible actions:

1. Update the base image that incorporates the fix. This may be the simplest
   option.
2. Remove the dependency from the image, or choose a different base image
   without the issue.
3. Add an ignore with an expiry to allow for an update to be published within a
   period of time. This is only valid if your corporate standards allow it, and
   there is a plan to follow up on this issue in the given time frame.
4. Update the image definition to update the package with the vulnerability.
   This can negatively impact image size, and create a future maintenance issue
   if not done carefully. Take care to keep the number of packages updated
   small, and avoid adding hard-coded versions unless a process exists to keep
   them up-to-date.
5. Ignore the finding indefinitely. This will generally only be valid if
   dependency both cannot be removed and is not used in a vulnerable fashion.
   Your working environment may require special exceptions for this.
