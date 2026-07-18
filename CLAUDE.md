# TwoMLSPQ — working notes

## Never put `;` in mermaid diagram text

Mermaid reads `;` as a **statement separator**, so a semicolon anywhere in a
sequence-diagram message or `Note` splits the line and the whole chart fails to parse.
This has bitten CI repeatedly (`07994da`, `ef23ba6`, `fe60ffa`). Use `—`, `.`, or `,`
instead — never `;` — inside any `` ```mermaid `` fence.

`mdbook build` does **not** catch it: `mdbook-mermaid` only rewraps the fence and lets
the browser parse it at runtime, so the local book builds green while the chart renders
as an error box on GitHub. The check that actually fails is the **`Diagrams parse`** job
(`.github/workflows/mermaid.yml`), which runs the real `mermaid-cli` renderer over every
fence. Before pushing a `.md` change that touches a diagram, scan the fences you edited
for a stray `;`.

## Run the Lint checks before pushing

`cargo test` and `cargo clippy` alone do **not** cover formatting, and the `Lint` job
fails the whole PR on it. Before pushing, run what CI gates on:

- `cargo fmt --all -- --check`
- `taplo fmt --check` — `Cargo.toml` formatting
- `cargo clippy --all-targets --features awslc,benchmark_util -- -D warnings`
- `cargo clippy -p apq --all-targets -- -D warnings`
