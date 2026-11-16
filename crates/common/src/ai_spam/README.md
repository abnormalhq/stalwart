# Community AI spam module contract

This directory contains an opt-in foundation only. It is exported from `common` for focused validation, but it is not installed in the server runtime or called by SMTP. The focused test command is `cargo test --locked -p common --no-default-features --features ai-spam-test-sqlite ai_spam::tests`; its file-backed tests exercise the actual SQLite Store and StoreLedger but do not validate other Store backends, SMTP, or an end-to-end provider/ACK path. The module remains inactive until the parent adds Community scoring/runtime wiring and authenticated configuration/acknowledgment.

## Runtime installation

The server integration must construct configuration only from authoritative operator state, resolve any sealed `ai-provider` credential on the server, and install the resulting immutable runtime for the exact server generation:

```rust
let runtime_config = RuntimeConfig::from_operator(operator_config, resolved_credential)?;
let ledger = Arc::new(StoreLedger::new(store));
let runtime = Arc::new(AiSpamRuntime::new(runtime_config, Some(ledger)));
```

The resolved credential must never come from a request or message. `ProviderCredential` redacts its `Debug` output. `AiSpamRuntime::new` uses a process-wide four-permit pool, shared across runtime replacements; the test-only provider constructor uses an isolated pool. Disabled, unready, unconsented, unpriced, or ledger-less runtimes return neutral before MIME extraction or provider/ledger calls.

Classification consumes the already parsed `mail_parser::Message`, reserves the full request/input/output/cost budget in `StoreLedger`, and only then calls the pinned OpenAI-compatible chat-completions adapter. It uses no proxy, redirect, or protocol retry; the workflow deadline is 1500 ms. Failed, malformed, timed-out, or overloaded work is neutral and reservations are retained.

## Required Community scoring hook

The module is exported from `crates/common/src/lib.rs` for focused validation only; this export does not install it in the server runtime or activate SMTP:

```rust
pub mod ai_spam;
```

In `crates/spam-filter/src/analysis/score.rs`, add an additive method to the existing `ScoreAccumulator` and call it after all native and user-defined rules, immediately before `finalize`:

```rust
impl ScoreAccumulator {
    pub(crate) fn add_ai_evidence(&mut self, evidence: common::ai_spam::AiEvidence) {
        self.tag_score = evidence.add_to_score(self.tag_score);
    }
}

if let ClassifyOutcome::Evidence(evidence) = runtime.classify(message).await {
    acc.add_ai_evidence(evidence);
}
finalize(ctx, acc, scores, thresholds, classifier)
```

The actual Community call site is the final-score path in `spam_filter_classify`, after the `AfterAi` user-defined rules and immediately before `finalize`. The method only adds the private, bounded 0–5 point contribution to `tag_score`; ham/uncertain contribute zero. It must not replace native entries, lower native scores, or clear an existing `Reject`/`Discard` decision. Focused module tests cover evidence addition and bounds, not the server's `ScoreAccumulator` integration; parent-owned integration tests must cover recipient results and terminal native decisions.

## Bounds and tokenizer contract

The input path accepts only a decoded subject and inline `text/plain` body. It skips attachments, non-text parts, and complete `message/rfc822` subtrees; raw input is capped at 256 KiB, traversal at 64 parts/depth 8, cumulative decoded text at 256 KiB, and extraction at 20 ms. The normalized user data and fixed system prompt fit within a 3584-byte total prompt budget; a further 512-token margin is reserved from the nominal 4096-token input budget for chat framing.

Only the exact model IDs mapped to `cl100k` or `o200k` in `config::tokenizer_for_model` are accepted. This is a documented byte-BPE assumption, not tokenizer execution or a universal byte-to-token guarantee. Custom/local model IDs are intentionally rejected; a parent adding tokenizer or context-window support must define and test a new explicit contract rather than assuming UTF-8 byte length proves a token bound.

The response stream is capped at 2048 bytes, requires one assistant choice with no tool call, and accepts only `{ "verdict": "spam|ham|uncertain", "confidence": 0..100 }` with no unknown fields. Provider usage, when present, is bounded by the reserved input/output limits; this is not a billing guarantee.

## Durable usage and remaining integration

The ledger keys totals by server and operator billing period, independent of configuration revision. A reservation writes ledger and active-period assertions in one Store batch; a CAS conflict is neutral and is not retried. Period rollover requires the expected current period and a strictly later next period. The gated SQLite tests use disposable file-backed stores to check concurrent limits, charges and uncertain reservations across reopen, forward-only rollover CAS, and atomic failure of a stale multi-assert batch. They do not establish behavior for other Store backends.

Parent-owned work still required: install and wire the exported module into the Community scoring path and test the actual `ScoreAccumulator` integration; connect the authoritative Mail config and authenticated service ACK transport; synchronize Console period rollover with `StoreLedger::rollover_period(server_id, expected_period, next_period)`; and connect server-side credential resolution/rotation. No current module path should be described as active or ready without those pieces.
