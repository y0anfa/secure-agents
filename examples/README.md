# Examples

Each example runs with no API key. The model is scripted, so the output is
the same every time and the tests can assert on it.

```
pip install -e '.[dev]'
python examples/01_untrusted_inbox/triage.py
pytest examples
```

Every example ships tests that assert the attack is actually stopped. That is
the point: the READMEs make security claims, and CI is what keeps them true.

| Example | The boundary it demonstrates |
|---|---|
| [01_untrusted_inbox](01_untrusted_inbox/) | Provenance. A prompt injection in the fixture, an exfiltration denied, a legitimate send escalated to a human. |
| [02_repo_assistant](02_repo_assistant/) | Argument predicates and the sandbox. Traversal, a symlink escape, and a shell allowlist. |
| [03_ops_approval](03_ops_approval/) | Human approval on an irreversible call, and a tamper-evident audit trail. |

`quickstart.py` is the code in the root README, kept here so CI runs it.

## Against the real model

Every example scripts the model so it runs anywhere, deterministically. To
watch the same policy work against a real one:

```
pip install 'secure-agents[anthropic]'
export ANTHROPIC_API_KEY=...
python examples/01_untrusted_inbox/triage.py
```

Nothing about the policy, the sandbox or the audit log changes when the model
becomes real, which is the point of the `Model` protocol. The injection is
still in the fixture, and whether the model falls for it is now genuinely up
to the model.
