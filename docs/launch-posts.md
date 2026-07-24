# Agent hosting launch drafts

These are paste-ready drafts for the verified-agent app-hosting launch. They
deliberately lead with the problem and the design choices rather than a feature
list. Adjust only the first line if the public launch URL changes from
`https://agents.example.com/launch`.

## Bookface

### Title

Launched: every verified AgentTransfer agent can now host its own app

### Post

I built AgentTransfer because my agents kept needing the same few things: an
address, somewhere to put files, and a way to send work to one another without
shoving the bytes through a context window. Over time it became the little
piece of internet infrastructure that I use for my own agents.

There was still an awkward gap. An agent could build a website or a small
service, but publishing it meant handing the result back to me so I could wire
up hosting. That is now gone.

Every agent with a human-verified owner can deploy one app at a stable
subdomain. A simple address lines up with the site:

```text
field-notes@agents.example.com  ->  https://field-notes.agents.example.com
```

Static sites are one command:

```sh
agenttransfer app-deploy ./site
```

Containerized services can be built from a directory with a `Dockerfile`, or
started from an OCI image:

```sh
agenttransfer app-deploy ./service --kind container --port 8080 --health-path /healthz
agenttransfer app-deploy --image ghcr.io/example/service@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef --port 8080
agenttransfer app-logs --tail 200
```

The agent can deploy, inspect, tail logs, and stop through the CLI, REST API,
or MCP. Reset and destructive data purge are intentionally explicit CLI/REST
operations. Deploys are immutable. Because releases share writable `/data`,
the runner drains the old container before starting its replacement. The new
runtime must return healthy 2xx before routing; on failure the runner removes
uncertain state, restarts and health-checks the previous release, and restores
its route. Static releases use the same content-addressed blob store as the
agent's files. Container hosts forward every HTTP method. They get a persistent
`/data` directory and run nonroot with a read-only root filesystem, dropped
capabilities, rotating logs, and CPU, memory, PID, and temporary-storage
limits. Source builds and runtime egress are separate operator trust choices
and are both off by default; registry and base images must be digest-pinned.

The part I spent the most time on was the boundary around Docker. The public
AgentTransfer process never gets the Docker socket. It talks over an
authenticated Unix socket to a separate, narrow runner process. That does not
magically turn Docker into a VM—and the docs say so—but it keeps mail relay
credentials, the control-plane database, and app code out of one another's
reach.

I kept one intentional human step: hosting unlocks only after the owner clicks
the verification email. The agent can sign up, receive mail, transfer files,
and work locally before that. The click is just the point where a human says,
“yes, this agent can publish on this domain.” An admin flag does not silently
bypass it, and migrated legacy approvals have to complete the challenge too.

This is open source and self-hostable. Static hosting only needs the existing
Go binary; dynamic apps add Docker plus a second invocation of that same
binary as the runner. You point a wildcard DNS record at the instance and the
server obtains certificates only for active app names.

Launch note, illustrations, and commands:
https://agents.example.com/launch

Code and the honest security notes:
https://github.com/shehryarsaroya/agenttransfer

I would especially appreciate feedback on the isolation boundary and on what
an agent actually needs from a small personal app platform. This is primarily
infrastructure for me and my own agents, so I have intentionally optimized for
a simple, generous single-operator setup instead of pretending it is a
multi-tenant cloud.

## Hacker News / YC

### Suggested title

Show HN: AgentTransfer – verified AI agents can deploy apps to their own subdomains

### Post

Hi HN — I made AgentTransfer so my agents could have durable identities,
inboxes, and storage, and send large artifacts without routing the bytes
through a model context. It has gradually become infrastructure for my own
agents.

One manual step kept bothering me: an agent could build a site, but still
needed me to publish it. I added app hosting so a human-verified agent can now
deploy directly to its own stable HTTPS subdomain.

For a DNS-safe name, the mapping is literal:

```text
field-notes@agents.example.com
https://field-notes.agents.example.com
```

The smallest deploy is:

```sh
agenttransfer app-deploy ./site
```

The directory needs a root `index.html`. For services, the agent can deploy a
directory containing a `Dockerfile`, or an existing OCI image:

```sh
agenttransfer app-deploy ./api --kind container --port 8080 --health-path /healthz
agenttransfer app-deploy --image ghcr.io/example/api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef --port 8080
```

There are REST and MCP equivalents, so the agent does not need a human to run
the command. Releases are immutable and activation is health-gated. Static
files live in AgentTransfer's content-addressed store. Dynamic apps run behind
a separate local runner: only that runner can access Docker; the public server
cannot. Runtime containers are nonroot, read-only except for `/data` and
`/tmp`, capability-dropped, and resource-limited. Egress-off Linux hosts proxy
the exact runner-attested RFC1918 endpoint on a per-app internal bridge;
egress-enabled or Docker Desktop hosts use a random loopback-published port.

The proxy forwards every HTTP method, while static hosts accept only GET/HEAD.
Container logs rotate, and `/data` survives redeploy, stop, and ordinary app
reset. Only an explicit purge removes that data and the stable app identity.

I am not claiming this is hostile multi-tenant isolation. Docker and the
runner are still privileged infrastructure. Runtime egress is off by default,
but an enabled network and the shared host kernel remain security boundaries;
a VM boundary is the right answer for mutually hostile tenants. My actual use
case is one operator and their agents, so I chose a small, legible design and
documented where it stops.

The only human gate is email verification. Agents can self-register and use
their inbox/storage immediately, but publishing a site requires the owner to
click an emailed confirmation. Operator verification alone does not unlock
hosting, and migrated legacy approvals need a new email challenge. This is less
about anti-abuse for me than making the authority to publish explicit.

The project is MIT-licensed Go. Static hosting uses the existing single
binary; container hosting runs the same binary a second time as the Docker
runner. Self-hosters add a wildcard DNS record and can choose their own
storage/resource limits.

Launch note: https://agents.example.com/launch

Source: https://github.com/shehryarsaroya/agenttransfer

I would value criticism of the deployment model, especially the public
process/runner split and the storage accounting around persistent `/data`.

## Posting notes

- Publish only after the launch page, both images, wildcard DNS, and a real
  agent subdomain all resolve over HTTPS from a clean browser session.
- Push the release commit first; verify every GitHub documentation link from
  the live launch page resolves rather than relying on uncommitted files.
- Confirm the supervised production concierge is active and complete one
  real file round-trip through it before suggesting readers try that address.
- For Bookface, attach the hero image and leave the full URL visible near the
  end. The direct, personal opening is more useful there than a long technical
  preamble.
- For HN, submit the launch page as the Show HN URL and paste the HN draft as
  the first comment. Keep the title descriptive; do not add “launching,” emoji,
  or claims such as “secure sandbox” that the architecture does not make.
- Suggested image alt text for social uploads: “An agent email address flowing
  into a live HTTPS subdomain, shown as a restrained technical illustration.”
- Be present for the first hour. Likely questions are: why email verification,
  why Docker rather than microVMs, whether arbitrary images work under uid
  65532/read-only root, whether `/data` survives redeploys, and how wildcard
  TLS avoids certificate abuse. The launch page and `docs/apps.md` answer each
  one; answer candidly and link to the exact section.
- Do not call the platform multi-tenant or serverless. The accurate phrase is
  “a small personal app platform for an operator and their verified agents.”
- If someone asks about unusual names, say the simple case maps exactly;
  characters that are not valid in DNS labels are normalized with a stable
  collision-resistant suffix, and `app-status` is authoritative.
