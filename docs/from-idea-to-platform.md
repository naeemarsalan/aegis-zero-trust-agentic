# From an Idea to a Zero-Trust Agentic Platform — a build journal

> How I went from a one-line idea to a working zero-trust platform for autonomous
> agents, building it alongside an AI coding agent. The decisions I had to make,
> the things I had to understand before I could make them, what the docs didn't
> tell me, and the dead-ends I hit on the way. Written so the next person can see
> *why* the system looks the way it does — not just *what* it is.

---

## 0. The idea

It started as one sentence: **let an AI agent do real operational work on my
behalf — touch the firewall, the cluster, DNS — without ever handing it a
standing credential, and so that everything it does is traceable back to *me*,
the human, not to "the agent."**

That sentence already contains the whole design tension. Agents are useful
exactly because they act autonomously; security teams hate them for exactly the
same reason. The usual "solution" is to give the agent a service account with
broad rights and hope the prompt stays on the rails. That's a non-starter the
moment the agent can reach anything that matters.

So the real problem wasn't "build an agent." It was: **what does the trust
architecture have to look like so that giving an agent real power is actually
safe?** Everything below is the answer to that, discovered by building it.

### The one rule everything hangs off

Before writing a line, I committed to a single invariant and refused to break it:

> **No credential is ever passed to or held by the agent. The agent presents its
> own identity; the platform turns that identity into the right, narrowly-scoped,
> time-boxed access at the moment of use, and the downstream system sees the
> *user*, never the agent.**

Every later decision was really just "which option keeps this invariant true?"
When I was tempted to cut a corner (mount a token, cache a secret, let the agent
hold the exchanged JWT), this rule is what said no. If you only remember one
thing about why the system is shaped this way, remember this rule.

---

## 1. The shape of the thing (and the choices that set it)

The platform is a chain. A request from an agent flows: **agent → gateway →
policy/delegation → downstream tool**, and identity is transformed at each hop so
that what arrives at the tool is a short-lived, user-scoped credential the agent
never saw. Four big choices set that shape. For each one I'll give the fork I was
actually standing at, what I had to understand to choose, and why I chose what I
did.

### Choice 1 — Where does delegation live?

**The fork:** bake auth into every MCP tool server, or centralize it in one place
the traffic already flows through.

Baking it into each tool means every server re-implements identity, exchange, and
audit — and the off-the-shelf ones (like the 327-tool pfSense server I wanted to
reuse) simply don't support it; they validate a static API key and nothing else.

I chose a **gateway + one custom delegation service**. The gateway
([agentgateway](https://agentgateway.dev), a Linux Foundation project, MCP-native)
fronts every tool. A single Go service (`ext-proc-delegation`) sits in the request
path and does the identity work. That service is the *only* bespoke code in the
whole platform — everything else is configuration of best-of-breed pieces.

**What I had to understand first:** Envoy's external-processing (`ext_proc`) and
external-authorization (`ext_authz`) extension points, and how an MCP request is
framed (JSON-RPC `tools/call` over a streamable HTTP session). I couldn't choose
the integration point without knowing what the gateway would actually hand my
service.

**The surprise that cost me a day:** agentgateway is alpha, and its behavior is
*not* what the diagrams imply. Its `jwtAuthentication` filter **validates and then
strips** the bearer token, forwarding neither the token nor the claims downstream.
Its `transformation` phase can't read JWT claims (it runs before auth populates
them — I proved this with an HTTP 472 probe). It forwards **no** claims to
`ext_authz` at all. I only learned this by instrumenting and testing, not from
docs. The consequence reshaped the design: **my service has to independently
re-verify the user's JWT** rather than trust anything the gateway tells it. That
turned out to be the *correct* security posture anyway — never trust the proxy as
your identity source — but I arrived at it by being forced to, not by foresight.

### Choice 2 — How does the downstream see the *user*?

**The fork:** pass the user's token through (credential passing — breaks the
invariant), or exchange it.

I chose **RFC 8693 token exchange** in Keycloak. My service takes the verified
user token and exchanges it (acting as a confidential client) for a *new*,
downstream-audience-scoped token. The downstream validates that token and sees
`preferred_username: arsalan`, `aud: mcp-downstream` — provably an exchanged
token, not a pass-through. The agent never holds it.

**What I had to research:** Keycloak's token-exchange is fiddly and the error
messages lie. Getting it to work required understanding that the client needs the
`basic` scope (or the access token has no `sub` and verification fails with "empty
sub"), `standard-token-exchange` enabled with `fullScopeAllowed`, a dedicated
audience client-scope mapper (or you get "Requested audience not available"), and
— the one that really cost me — **the exchange has to hit the public route, not
the in-cluster service**, because Keycloak validates the subject-token's issuer
against the request URL. None of this is in one place; I assembled it from the
upstream source, a handful of issues, and a lot of trial.

### Choice 3 — How does the agent prove who it is without a secret?

**The fork:** give the agent a Kubernetes service-account token (a secret on
disk), or give it a cryptographic identity it can't leak.

I chose **SPIFFE/SPIRE** (Red Hat's Zero Trust Workload Identity Manager). The
agent gets an **SVID** — a short-lived, automatically-rotated cryptographic
identity — and uses *that* to authenticate to Vault and pull only its own secret.
There is no token on disk. I verified this literally: `find / -name '*token*'`
inside the running agent returns nothing.

**What I had to understand:** the SPIFFE Workload API, JWT-SVIDs vs X.509-SVIDs,
how Vault's JWT auth validates an SVID against the SPIRE OIDC issuer, and how the
SPIFFE CSI driver delivers the identity socket into a pod. This choice is also the
one that later created the single hardest problem in the project (§4).

### Choice 4 — How does a human approve a *temporary* escalation?

**The fork:** a custom approval UI, a ChatOps button, or "approval as a pull
request."

I chose **approval-as-a-PR**. When an agent hits a wall and needs elevated rights,
the platform opens a pull request in Git containing the *grant as reviewable YAML*
— who, what scope, which namespace, how long, the justification. A human approves
by **merging the PR**. That merge fires the rest: a per-session, ephemeral Vault
credential is minted, scoped to exactly the reviewed verbs/resources, with a lease
TTL that auto-revokes.

**Why a PR and not a shiny UI:** review-by-PR gives you, for free, a versioned and
signed grant, required-reviewers/branch-protection as your access policy, full
who-approved-what history, and — crucially — the PR becomes the *system of record*
the entire audit trail hangs off. I'd be a fool to rebuild that. (The UX question
of whether a raw PR is the right *human surface* is a separate, later conversation
— the PR stays the substrate regardless.)

---

## 2. Build order, and why

I built it in five phases, deliberately lowest-risk-first so each phase unblocked
a demo and a piece of reproducibility before the next:

1. **Prove delegation works** against a trivial echo server that just reflects the
   identity it sees. (If the downstream doesn't see the user here, nothing else
   matters.)
2. **Point it at a real tool** — the 327-tool pfSense server — and discover what
   "real" breaks. (It validates a static key, so delegation had to learn a
   per-user static-token injection mode. The off-the-shelf world doesn't speak
   your protocol; meet it where it is.)
3. **Move tool-level RBAC into the delegation service** — read-only tools open,
   dangerous tools gated. (I'd intended to do this in policy/Kyverno, but the
   gateway forwards no claims and the policy plugin lacks the MCP CEL library, so
   the enforcement point *had* to be my service. Two upstream gaps, one pragmatic
   move.)
4. **Just-in-time escalation, end to end** — the PR-approval flow, ephemeral Vault
   credentials, auto-revocation.
5. **The capstone** — an agent in a hardware-isolated sandbox, pulling its secret
   by identity, logging in as the user, and driving a tool call through the whole
   chain.

The lesson in the ordering: **each phase's job was to surface the next phase's
surprises cheaply.** Phase 1 against a fake server is where I learned the gateway's
behavior without the noise of a real tool. Phase 2 is where I learned that real
tools don't cooperate. Front-loading the surprises is the whole point of the
sequence.

---

## 3. What the docs didn't tell me (the empirical layer)

A theme kept recurring: **the authoritative answer was always in the running
system, not the documentation.** A sampling of things I could only learn by
testing:

- **NetworkPolicies match the *pod* port after the Service DNAT, not the Service
  port.** A service on `:443` that targets container port `8081` needs the policy
  to allow `8081`. Every time I trusted the Service port, I got a silent timeout.
  I hit this at least three times across the project before it became muscle
  memory.
- **Anything that does file-locking wedges on NFS storage** on this cluster —
  SPIRE's SQLite, the database init, Vault's raft. The rule became "anything with
  a lock goes on local-path, never NFS," learned via three separate outages.
- **Vault re-seals on every node reboot** (Shamir). Obvious in hindsight; not
  obvious at 2am the first time the whole platform went dark.
- **A bad `git add` pathspec silently aborts the *entire* staging.** I committed
  what I thought were five files; one bad path meant only one landed. Because the
  cluster's GitOps reconciles from git, the un-committed fixes kept getting
  reverted on me — I was debugging a "flapping" network policy that was really a
  git mistake. The lesson: verify what actually got committed, not what you
  intended to commit.
- **The platform resolves an external hostname to a *public* IP via split-horizon
  DNS** even though my workstation sees the private one. A service couldn't reach
  Git until I pinned the hostname to its in-network address. The view from inside
  the cluster is not the view from your laptop.

None of these are exotic. They're the ordinary friction of real infrastructure —
and the reason "it should just work" is a sentence to distrust. **Empirical
verification wasn't a nicety; it was the only reliable source of truth.**

---

## 4. The hardest problem, in detail: identity *inside* a hardware VM

The capstone wanted the agent to run inside a **Kata** micro-VM (a real
hardware-virtualized sandbox, not just a container) *and* still get its SPIFFE
identity to pull its secret. Those two requirements fight each other, and
untangling that fight was the most interesting work in the project.

**Why they fight:** SPIRE delivers identity over a **Unix-domain socket** that the
host agent exposes and the CSI driver bind-mounts into the pod. A Kata pod is a
genuine guest VM. A process inside a VM **cannot `connect()` to a socket living on
the host** — the filesystem passthrough can move file *contents*, but not a live
socket endpoint. So the moment the agent went into Kata, the identity fetch hung
forever. I proved it cleanly: ~1.6 seconds to get an SVID outside Kata, infinite
hang inside.

I considered three honest paths:

1. **A bleeding-edge Kata feature** ([PR #13162](https://github.com/kata-containers/kata-containers/pull/13162),
   which forwards a host Unix socket into the guest over vsock). I researched it
   in detail — and concluded it was the *wrong* tool. It's for forwarding a host
   socket into the guest, but it would also break SPIRE's attestation, because the
   agent identifies a workload by the *peer credentials* of the socket connection;
   a forwarded connection looks like it came from the host forwarder, not the
   guest workload. You'd get an SVID for the wrong identity. (Knowing *why* a
   tempting solution is wrong is as valuable as finding the right one.)
2. **Drop Kata** and keep the identity story (works today, loses the hardware
   boundary).
3. **Run a SPIRE agent *inside* the VM** — the "correct" answer.

I chose (3). The insight that made it tractable: **a nested agent doesn't need any
of the socket forwarding at all.** It reaches the SPIRE *server* over ordinary pod
networking (TCP), and serves the Workload API on a socket *inside* the VM that the
workload connects to locally. Everything is either TCP (to the server) or a
same-VM Unix socket (to the workload). No boundary is crossed. PR #13162 turned
out to be irrelevant to the design I actually needed.

Getting it running surfaced a string of precise, only-learnable-by-doing details:

- **Node attestation:** two SPIRE agents on one node using the same attestor would
  collide on a node-derived identity, so the nested agent uses a **join-token**
  (its own unique identity) instead.
- **Workload attestation:** the nested agent identifies the workload by reading its
  `/proc`, which requires **`shareProcessNamespace: true`** — without it you get
  the cryptic "could not resolve caller information."
- **The same post-DNAT NetworkPolicy lesson** bit again: the agent's egress to the
  SPIRE server had to allow the *pod* port `8081`, not the service port `443`.
- And a governance wall: the managed SPIRE operator **hardcodes** which service
  accounts may attest and reverts any edit within ~25 seconds. To demonstrate the
  nested agent at all, I had to temporarily step around the operator — which is
  itself the honest finding: *the mechanism works; making it durable needs the
  operator to expose a knob it doesn't yet have.*

The payoff: an agent in a hardware micro-VM (guest kernel `5.14` vs host `6.19` —
provably a different kernel, i.e. real isolation) got **its own** SVID from an
agent running *inside* the VM, used it to pull its secret from Vault, with **no
service-account token and no Vault token anywhere on disk.** The "impossible"
combination, done the right way.

**The meta-lesson:** the deepest problem wasn't solved by the bleeding-edge
feature everyone would reach for. It was solved by *reframing* until the boundary
didn't need to be crossed at all. Most hard infra problems are like this — the win
is in the framing, not the tool.

---

## 5. What I had to know to direct an AI well

I built this *with* an AI agent doing most of the typing, searching, and testing.
That changes what the human's job is, and it's worth being honest about what that
job actually was:

- **Hold the invariant.** The AI is brilliant at "make it work" and will happily
  mount a token to unblock itself. *My* job was to keep saying "no — pull it via
  identity, not a token," over and over, because the invariant is the product. The
  human owns the principles; the AI owns the execution.
- **Make the irreversible calls.** Scope ("all of it"), the SVID-not-token rule,
  device-flow login, "use the nested SPIRE path," "use the PR for approval,"
  "bleeding edge is fine." These are judgment calls with trade-offs the AI can lay
  out but shouldn't *decide*. The AI's gift here was framing each fork crisply
  enough that I could choose fast and well.
- **Insist on empirical proof.** The most valuable instruction I gave, repeatedly,
  was effectively "stop theorizing, go test it." Every claim of "done" had to come
  with the log line or the HTTP status that proved it. The AI is fully capable of
  this — it just has to be pointed at *verification* rather than *plausibility.*
- **Know enough to smell a wrong turn.** I didn't write the Go, but I had to
  understand RFC 8693, SPIFFE, Envoy ext_proc, and Kata well enough to tell when an
  explanation was hand-waving. You can delegate the *building*; you cannot delegate
  the *understanding* of what's being built.

The collaboration that worked best was a loop: I set a principle and a target, the
AI explored and surfaced the forks with real trade-offs, I chose, the AI built and
**proved it empirically**, and we both treated a failing test as information rather
than a setback. The dead-ends — the gateway's claim-stripping, the Kata socket
boundary, the operator's hardcoded allow-list — were not detours. They *were* the
design process; each one eliminated a wrong answer and taught the constraint that
shaped the right one.

---

## 6. Where it landed, and the next frontier

What works today, proven end-to-end on a live cluster:

- **Delegated tool calls** — the downstream always sees the user, via an exchanged
  token, against both a test oracle and the real 327-tool pfSense server.
- **A tool-RBAC gate** — read-only open, dangerous tools denied without a valid,
  in-scope, time-boxed capability and allowed with one.
- **Just-in-time escalation, full lifecycle** — request → human approval by PR
  merge → ephemeral scoped credentials → used within the window (every action
  attributed to a per-session identity in the audit log, in-scope allowed /
  out-of-scope denied) → auto-revoked on expiry.
- **The capstone** — an agent in a Kata micro-VM, holding its identity from a
  nested SPIRE agent, pulling its secret by SVID, logging in as the user via
  device flow, and driving a delegated tool call through the gateway — running
  inside NVIDIA OpenShell's sandbox runtime.

What's *not* solved, and stated honestly: durable Kata-identity needs an operator
knob that doesn't exist yet; OpenShell's own orchestration of a packaged agent
*as* a Kata VM is alpha frontier. The zero-trust mechanics are proven; some of the
packaging around them is ahead of where the upstream projects are.

And the real next frontier isn't a security mechanism at all — it's **the
consumption experience.** All of the above is plumbing the end user should never
see. The open question is how a person goes from *"I have a task"* to *"the agent
did it for me, safely, and here's the receipt"* — without the security ever
feeling like it's fighting them. That's the next journal entry.

---

*This document is the "why." For the "what," see the ADRs under `docs/decisions/`
and the showroom under `docs/showroom/`. For the "how it actually behaves," see the
use-case runbooks under `usecases/` — and, as this whole journey argues, the
running system itself.*
