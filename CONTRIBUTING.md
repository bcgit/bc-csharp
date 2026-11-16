# Bouncy Castle Contributing Guidelines <!-- omit in toc -->

Thank you for contributing to Bouncy Castle!

In this guide, you get an overview of the contribution workflow from starting a discussion or opening an issue to creating, reviewing, and merging a pull request.

For an overview of the project, see [README](README.md).

## Start a discussion

If you have a question or problem, you can [search in discussions](../../discussions) to see if someone has already found a solution to your problem.

Or you can [start a new discussion](../../discussions/new/choose) and ask your question.

## Create an issue

If you find a problem with Bouncy Castle, [search if an issue already exists](../../issues).

> **_NOTE:_** If the issue is a **potential security problem**, please contact us
> before posting anything public. See [Security Policy](SECURITY.md).

If a related discussion or issue doesn't exist, and the issue is not security related, you can [open a new issue](../../issues/new/choose). An issue can be converted into a discussion if we think it fits better there.

## Contribute to the code

For substantial, non-trivial contributions, you may be asked to sign a contributor assignment agreement. Optionally, you can also have your name and contact information listed in [Contributors](https://www.bouncycastle.org/contributors.html).

Please note we are unable to accept contributions which cannot be released under the [Bouncy Castle License](https://www.bouncycastle.org/licence.html). Issuing a pull request on our public GitHub mirror is taken as agreement to issuing under the Bouncy Castle License.

### Create a pull request

> **_NOTE:_** If the issue is a **potential security problem**, please contact us. See [Security Policy](SECURITY.md).

You are welcome to send patches, under the Bouncy Castle License, as pull requests. For more information, see [Creating a pull request](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request). For minor updates, you can instead choose to create an issue with short snippets of code. See above.

* Keep the patch focused; only change the parts related to your patch.
* Do not change other lines, such as whitespace, adding line breaks to documentation comments, etc. It will make it very hard for us to review the patch.
* For contributions touching multiple files, try to split up the pull request; smaller changes are easier to review and test, as well as being less likely to run into merge conflicts.
* Add test cases for your change; these may be simple additions to existing tests. See [Writing tests](#writing-tests). If you do not know how to do this, ask us and we will help you.
* Edits to the public API require more care, to avoid breaking existing code that uses the library. Prefer adding new members over changing or removing existing ones.
* If you have problems merging, see this [git tutorial](https://github.com/skills/resolve-merge-conflicts), which explains how to resolve merge conflicts and other problems.

For more information, refer to the Bouncy Castle documentation on [Getting Started with Bouncy Castle](https://doc.primekey.com/bouncycastle/introduction#Introduction-GettingStartedwithBouncyCastle).

#### Writing tests

Tests are in the [crypto/test](crypto/test) project, in folders that match the layout of the library source.

* Write new tests as plain NUnit tests (`[TestFixture]` and `[Test]`). Many existing tests extend `SimpleTest`; please do not use it for new tests.
* Many tests need extra data from the [bc-test-data](https://github.com/bcgit/bc-test-data) repository. Clone it next to this repository (as `../bc-test-data`), otherwise those tests will fail with `DirectoryNotFoundException`.
* If your change needs new test vectors or sample files, ask us where to put them. Small files can go inline or in [crypto/test/data](crypto/test/data); larger ones may belong in bc-test-data.

### Self-review

When you think your pull request is finished, read through the whole diff once more, as a reviewer would, and check it against the points in [Create a pull request](#create-a-pull-request). Does every change belong to your patch? Are there any unrelated whitespace or formatting changes? Did you add tests, and do they pass? Does the change affect the public API?

Fixing problems yourself is much quicker than waiting for us to find them in review.

### Your pull request is merged

For acceptance, pull requests need to meet specific quality criteria, including tests for anything substantial. Someone on the Bouncy Castle core team will review the pull request when there is time and let you know if something is missing or suggest improvements. If it is a useful and generic feature, it will be integrated in Bouncy Castle to be available in a later release.
