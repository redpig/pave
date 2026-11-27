# Pave on the web (design)

What pave would look like as a web platform feature: the kernel and wallet in the user agent, profiles as descriptions it understands, providers' own pages using them through a JavaScript API or a declarative HTML overlay, and a host app with embedded web views until browsers ship it. Nothing here is built; [profiles.md](profiles.md) is the part that exists.

## Goals

- **Seamless discovery and adoption.** A person finds a co-op, a restaurant or a town board the way they find anything on the web: a link, a QR code on a package, a search, an app store. The first use needs no new account.
- **Open like the web and app stores.** Anyone can publish a profile or be a provider by putting up a page. Anyone can build a host app and distribute it through a store. Nobody owns the directory.
- **The convenience of a super app.** One wallet, one set of identity tiers and one place to see what you hold and what's pending, across every provider.
- **No supplanting providers.** A restaurant keeps its own site, ordering system and customers; a co-op keeps its brand. Pave adds the parts they'd otherwise rent from a platform (trust, custody, payment, reputation), and nothing else.

## Layers

| Layer | Where it runs | Trusted for |
|---|---|---|
| **The kernel and wallet** | The user agent: a browser, or a host app's native core | Keys, holdings, views, signing, the acceptance check, request specs |
| **Profile descriptions** | Loaded and checked by the user agent | Layouts, receipts, actions, walks, and the general predicates ([profiles.md](profiles.md)) |
| **Provider pages** | The provider's own origin, in a tab or an embedded web view | Nothing: they compose actions, and the user agent decides |
| **The HTML overlay** | Markup in provider pages, rendered by the user agent | The confirmations a person sees |

**This is the sandbox.** The user agent is the only trusted code. It runs the kernel and evaluates descriptions, which are data. Provider pages are untrusted, sandboxed the way the web already sandboxes them: origin isolation, CSP, iframes and Permissions Policy. Pave doesn't need a sandbox of its own, and rules don't need WASM inside the wallet:

- A rule that each party must enforce is a predicate in the description, which every user agent evaluates for itself.
- A rule that only helps a person decide (a suggested route, an estimated pay) is page code, and can be any JavaScript or WASM the page likes, since nothing trusts it.
- A rule too rich for the predicates is a sign the predicate vocabulary needs a reviewed addition, as web APIs grow, not a reason to run arbitrary code with authority.

## The JavaScript API

A sketch, in the style of WebAuthn and Payment Request:

```js
const p = await navigator.pave.profile("https://pine.example/profiles/parcels.json",
                                       { integrity: "sha256-…" });
// The user agent shows its own confirmation, worded from the description's
// action doc and the parameters, and returns the record it signed.
const rec = await p.act("take", { manifest });
const steps = await p.walk("custody", { manifest });
const key = await p.receive({ ticketFrom: dispatch });   // a key, with its ticket to show
const tickets = await p.request("shift", { creds: 4 });    // a mint request from its spec
```

- **Keys never reach the page.** The page names an action and its parameters. The user agent finds the state, evaluates the predicates, runs the acceptance check, shows the confirmation and signs.
- **Holdings are private by default.** A page sees only what the person shares with that origin, for the schemas its descriptions name, like storage partitioning.
- **The origin is the service name.** A connection's network access check uses the page's origin as its basename, as WebAuthn binds a key to its relying party. A pseudonym at one provider is unrelated to the same person's at another.

## The HTML overlay

Declarative markup the user agent renders and confirms itself, so the common flows need no script at all:

```html
<link rel="pave-profile" href="/profiles/parcels.json" integrity="sha256-…">

<pave-action profile="parcels" action="take" manifest="…">Take this parcel</pave-action>

<form method="pave" profile="parcels" action="hand_off">
  <input name="to" type="pave-key" ticket-from="…">   <!-- the user agent scans a QR, or reads NFC -->
  <button>Hand off</button>
</form>

<pave-walk profile="parcels" walk="custody" manifest="…"></pave-walk>
```

- **The button is the user agent's.** Its label and confirmation come from the description, not the page, so a page can't dress up one action as another.
- **It works without script,** which helps accessibility and low-end phones, and is easy to add to an existing site: a restaurant's order page adds a `<link>` and a button.
- **Reading is rendered too.** `<pave-walk>` shows a parcel's custody without the page learning anything about the wallet.

## Before browsers ship it: a host app

A host app is the super app: a native wallet with the kernel in its core, and embedded web views for provider pages. It injects the same `navigator.pave` API through a message bridge and renders the overlay's elements, the way some wallets inject an API into pages and super apps host mini programs. The difference is that the host owns nothing else:

- **Provider pages are ordinary web pages** on the provider's own origin. The same page works in the host app, in a browser with an extension, and natively once the API is standard.
- **Discovery is open.** The host lists what a town's registry board publishes, plus anything the person opens from a link or a QR code (`web+pave:` deep links), plus `/.well-known/pave-profiles` on a provider's origin. There's no central directory.
- **Many hosts can exist.** A co-op, a town or a company can ship one through an app store. They all hold the same kind of wallet and speak the same records, so a person can switch hosts and keep everything.
- **The host carries what browsers can't yet.** Bluetooth and NFC for offline handoffs and meets, background gossip, secure-element keys.

## Discovery in practice

| Where a person starts | What happens |
|---|---|
| A QR code on a package | Opens the provider's page with the manifest; the overlay offers "Take" or "Confirm delivery" |
| A restaurant's site | Its order page has a pave payment and delivery option next to its usual ones |
| The town's directory | The host shows profiles and providers posted on the registry board, checked like any board post |
| A co-op's sign-up page | Joining the member roll is a join from the host's wallet; the co-op never sees the key |

## Path to a standard

- **Formats:** descriptions as JSON with CDDL for layouts; records and receipts as CBOR, signatures as COSE. These are already IETF formats.
- **Signatures:** the group signature scheme needs specification and review. FIDO once specified ECDAA for attestation, which is a precedent for the family, not for this use.
- **The API and the overlay:** a W3C Community Group incubation, alongside WebAuthn, the Digital Credentials API, Payment Request and the Web App Manifest, which solved neighboring problems.
- **What to prove first:** a host app with an embedded web view, the injected API and the overlay, over the Rust wallet as its core. Then a provider page that works unchanged in the host and in a browser extension.

## What it changes in pave

- **Descriptions gain an origin and consent text.** Each action needs a template for the confirmation the user agent shows, filled from its parameters.
- **The predicate vocabulary becomes an API surface.** Additions are reviewed like web API changes, since every user agent must implement them.
- **Mint requests are already data** ([request.rs](../board/src/request.rs)). A page can ask for one by name, and the user agent picks the credential and basename from the spec.
- **WASM moves out of the plan for the wallet.** Rules beyond the predicates stay in profile code at whoever runs the profile's servers, and in untrusted page code for advice.
