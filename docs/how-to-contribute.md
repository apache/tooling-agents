# How to contribute

**Sections**:

* [Introduction](#introduction)
* [Finding something to work on](#finding-something-to-work-on)
* [Pull request workflow](#pull-request-workflow)
* [Commit message style](#commit-message-style)
* [ASF contribution policies](#asf-contribution-policies)
* [Getting help](#getting-help)

## Introduction

This page explains how to contribute code and documentation to Tooling Agents.

**IMPORTANT: New contributors must introduce themselves on [the development mailing list first](mailto:dev@tooling.apache.org), to deter spam.** Contributions are very welcome, but please do not submit a PR until you have introduced yourself first.

## Finding something to work on

The easiest way to find something to work on is to look at our [issue tracker](https://github.com/apache/tooling-agents/issues) on GitHub.

If you have an idea or suggestion that is not already reported in the issue tracker, please [create a new issue](https://github.com/apache/tooling-agents/issues/new) to discuss it with other developers before you start working on it. This helps to ensure that your contribution will be accepted, and that you do not duplicate work that is already in progress. For small changes such as fixing typographical errors or improving documentation clarity, you do not need to create an issue first.

## Pull request workflow

Once you have identified something to work on, the process of contributing is as follows:

1. **Fork the repository.** Create a personal fork of the [Tooling Agents repository](https://github.com/apache/tooling-agents) on GitHub.

2. **Clone your fork.** Clone your fork to your local machine.

3. **Create a branch.** [Create a new branch](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-and-deleting-branches-within-your-repository) for your work. Use a descriptive name that indicates what you are working on, such as `fix-typo-in-docs` or `improve-error-messages`.

4. **Make your changes.** Implement your contribution.

5. **Commit your changes.** Write clear, concise commit messages following [our commit message style](#commit-message-style). Each commit should represent a logical unit of work, but we are not particularly strict about this.

6. **Push your branch.** Push your branch to your fork on GitHub.

7. **Create a pull request (PR).** The PR should be from your branch to the `main` branch of the Tooling Agents repository. In the PR description, explain what your changes do and why they are needed. If your PR addresses an existing issue, reference that issue by number. Use the rebase strategy, not merge, to keep your PR up to date as you work on it.

8. **Participate in code review.** A member of the Tooling team will review your PR and may request changes. _We strongly recommend enabling the option to allow maintainers to edit your PR when you create it._ Even if you allow us to make changes, we may still ask you to make the changes yourself.

You can also [email patches](https://lists.apache.org/list.html?dev@tooling.apache.org) if you prefer not to use GitHub. Please use standard Git patch formatting, as if you were e.g. contributing to the Linux Kernel.

## Commit message style

We follow a consistent style for commit messages. The first line of the commit message is called the subject line, and should follow these guidelines:

* **Use the imperative mood.** The subject line should complete the sentence "If applied, this commit will...".
* **Use sentence case.** Start with a capital letter, but do not use a full stop at the end.
* **Use articles as appropriate before nouns**. Write about "a feature" not just "feature". Say, for example, "fix a bug", and not "fix bug".
* **Be specific and descriptive.** Prefer "Fix a bug in vote resolution for tied votes" to "Fix a bug" or "Update the vote code".
* **Keep it concise.** Aim for 50 to 72 characters. If you need more space to explain your changes, use the commit body.

**Examples of good subject lines:**

```cmd
Add distribution platform validation to the compose phase
Fix a bug with sorting version numbers containing release candidates
Move code to delete releases to the storage interface
Update dependencies
```

**Examples of poor subject lines:**

```cmd
fixed stuff
Updated the code.
refactoring vote resolution logic
```

Most commits do not need a body. The subject line alone is sufficient for small, focused changes. If, however, your commit is complex or requires additional explanation, add a body separated from the subject line by a blank line. In the body, explain what the change does and why it was necessary. We typically use itemized lists for this, using asterisks. You do not need to explain how the change works.

## ASF contribution policies

As an Apache Software Foundation effort, Tooling Agents follows the standard ASF contribution and licensing policies. These policies ensure that the ASF has the necessary rights to distribute your contributions, and that contributors retain their rights to use their contributions for other purposes.

### Contributor License Agreement

Before we can accept your first contribution as an individual contributor, you must sign the [Apache Individual Contributor License Agreement](https://www.apache.org/licenses/contributor-agreements.html#clas) (ICLA). This is a one-time requirement, and you do not need to sign a new ICLA for each contribution. The ICLA grants the ASF the right to distribute and build upon your work within Apache, while you retain full rights to use your original contributions for any other purpose. The ICLA is not a copyright assignment. You can find detailed instructions for submitting the ICLA in the [ASF new committers guide](https://infra.apache.org/new-committers-guide.html#submitting-your-individual-contributor-license-agreement-icla).

If your employer holds rights to your work, then you may also need to submit a [Corporate Contributor License Agreement](https://www.apache.org/licenses/contributor-agreements.html#clas) (CCLA). Please consult with your employer to determine whether this is necessary.

### Licensing

All contributions to Tooling Agents are licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). By submitting a pull request, you agree that your contributions will be licensed under this license. If you include any third party code or dependencies in your contribution, you must ensure that they are compatible with the Apache License 2.0. The ASF maintains a list of [Category A licenses](https://www.apache.org/legal/resolved.html#category-a) that are compatible, and [Category X licenses](https://www.apache.org/legal/resolved.html#category-x) that are not compatible.

### Code of conduct

All contributors to Tooling Agents are expected to follow the [ASF Code of Conduct](https://www.apache.org/foundation/policies/conduct.html), and any other applicable policies of the ASF.

### Access controls

We strongly encourage all contributors to enable two-factor authentication on their GitHub accounts, preferably with a [passkey](https://en.wikipedia.org/wiki/WebAuthn#Passkey_branding).

## Getting help

If you have questions about contributing, or if you need help with any step of the contribution process, please reach out to the team. You can:

* Ask questions on the [dev mailing list](https://lists.apache.org/list.html?dev@tooling.apache.org), which is the primary forum for Tooling development discussions.
* Comment on the relevant issue or pull request in the [issue tracker](https://github.com/apache/tooling-agents/issues).
* Chat with us in [#tooling-discuss](https://the-asf.slack.com/archives/C086X8CKEMB) on ASF Slack.

We welcome all types of contribution, and are happy to help you get started. Thank you for your interest in contributing to Tooling Agents.
