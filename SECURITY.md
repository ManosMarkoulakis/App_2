# Publication and runtime security

Real Fuseki addresses and credentials belong in environment settings, never
in source control. Example loopback addresses and ontology vocabulary URIs
are intentional. Do not commit feedback records, environment files, private
keys, Python caches or experimental model checkpoints.

The published ontology omits 15 unused contact-detail assertions (email,
point of contact, postal address and identification number). Schema,
object-property links, types and scoring inputs are retained. Frozen graph
summary metadata describes the original supplied snapshot; the published
snapshot has 15 fewer literal assertions. Generated diagnostic JSON is
recreated locally and excluded from Git.

The offline model-comparison tool loads locally trained PyTorch objects with
`weights_only=False`. Only use artifacts you generated and trust: loading
an untrusted pickle can execute code. These tools and dependencies are not
part of the standalone Render application.

App_2 restricts class URIs used in SPARQL to the known catalog, limits JSON
request sizes, rejects malformed inputs, escapes dynamic HTML values and
runs without Flask's interactive debugger. These controls are not a claim
of exhaustive security. Public prototypes still need infrastructure-level
traffic limits, appropriate Fuseki access restrictions and dependency
maintenance. Keep the Fuseki service read-only for the application's user.

Removing a value from the current tree does not remove it from old Git
commits, forks or caches. Previously published endpoint addresses remain a
separate historical-exposure issue; this update does not rewrite history.
