# Reporting vulnerabilities

Please email reports about any security related issues you find to `<TODO -- contact email here>`.

Please use a descriptive subject line for your report email. After the initial reply to your report, the team will endeavor to keep you informed of the progress being made towards a fix and announcement.

In addition, please include the following information along with your report:

-   Your name and affiliation (if any).
-   A description of the technical details of the vulnerabilities. It is very important to let us know how we can reproduce your findings.
-   An explanation who can exploit this vulnerability, and what they gain when doing so -- write an attack scenario. This will help us evaluate your report quickly, especially if the issue is complex.
-   Whether this vulnerability public or known to third parties. If it is, please provide details.

If you believe that an existing (public) issue is security-related, please send an email to `<TODO - contact email here>`. The email should include the issue ID and a short description of why it should be handled according as a security issue.

## CodeAct trust boundary

CodeAct-generated Python executes in the agent process by default. Its execution
namespace includes the live agent instance as `self` plus module-level names that
remain after NOOA visibility filtering.

The visibility controls `@hidden`, `Annotated[..., hidden]`, and `with hidden:`
reduce discoverability in generated-code surfaces such as `doc(self)`,
`<execution_context>`, and filtered module globals. They do not create a process
or authorization boundary.

Treat generated CodeAct code as able to use any agent object that it can name or
reach from `self`, including when the sandbox backend is enabled. Do not keep
security-critical authorization decisions, secrets, or audit evidence only on
agent-local Python objects and assume that `hidden` protects them. Put those
controls in a runtime-owned or external enforcement layer. The sandbox backend
can add OS-level resource containment on supported Linux hosts, but it does not
change the `self` authorization boundary.
