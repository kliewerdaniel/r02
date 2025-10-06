# QASP Formal Verification Guide

This guide explains how to use QASP v0.2's formal verification hooks for protocol analysis and security proofs.

## Overview

QASP v0.2 includes formal verification support through:

- **Trace Logging**: Detailed event logs for TLA+ and ProVerif analysis
- **State Model**: Finite state machine definition for model checkers
- **Symbolic Constants**: Machine-readable protocol definitions

## Trace Logging

### Generating Traces

Run the test suite with tracing enabled:

```bash
# Run tests to generate trace_log.json
pytest tests/formal/test_trace_log.py -v

# Or run full suite
pytest tests/ --tb=short
```

The trace log is written to `logs/trace_log.json` with format:

```json
[
  {
    "timestamp": "2025-10-06T11:15:00.000Z",
    "event_type": "handshake_init",
    "qasp_version": "0.2",
    "payload": {
      "session_id": "session-123",
      "tenant_id": "tenant-A",
      "client_id": "client-X",
      "state": "handshake_initialization"
    }
  },
  {
    "timestamp": "2025-10-06T11:15:01.000Z",
    "event_type": "challenge_request",
    "qasp_version": "0.2",
    "payload": {
      "session_id": "session-123",
      "tenant_id": "tenant-A",
      "client_id": "client-X",
      "state": "challenge_verification"
    }
  }
]
```

### CI Artifacts

The `formal-trace-export` CI job runs tests and uploads `trace_log.json` as a build artifact for analysis.

## TLA+ Modeling

### Using the Trace

Import and analyze the trace in TLA+:

```tla
---- MODULE QASP ----
EXTENDS Naturals, FiniteSets, Sequences

VARIABLES state, trace

Init ==
    /\ state = "INIT"
    /\ trace = <<>>

HandshakeInit ==
    /\ state = "INIT"
    /\ state' = "CHALLENGE"
    /\ trace' = Append(trace, [type |-> "handshake_init"])

ChallengeRequest ==
    /\ state = "CHALLENGE"
    /\ state' = "ESTABLISHED"
    /\ trace' = Append(trace, [type |-> "challenge_request"])

Fairness == WF_vars(HandshakeInit) /\ WF_vars(ChallengeRequest)

Spec == Init /\ [][Next]_vars /\ Fairness
====
```

## ProVerif Analysis

### Protocol Definition

Define QASP in ProVerif syntax using the exported constants:

```proverif
(* QASP v0.2 ProVerif model *)
free c: channel.
const qasp_version: string.
const init, challenge, established: state.

(* Key generation *)
new kem_key: key.
new sig_key: key.

(* Handshake process *)
process handshake(client_id, tenant_id) =
    out(c, (qasp_version, init, client_id, tenant_id));
    in(c, server_nonce: nonce);
    out(c, challenge_request);
    in(c, challenge_response);
    out(c, resource_request).
```

### Security Properties

Verify secrecy and authentication:

```proverif
query attacker(session_key[]).  (* No session key compromise *)
query client_id, tenant_id: inj-event(Authenticated(client_id, tenant_id)) ==> inj-event(EndHandshake(client_id, tenant_id)).
```

## State Transition Validation

### Programmatic Checks

Use the state validation function in tests:

```python
from src.formal.qasp_model import validate_state_transition

assert validate_state_transition("INIT", "CHALLENGE", "handshake_start") == True
assert validate_state_transition("INIT", "ESTABLISHED", "direct") == False  # Invalid
```

### State Diagram

```
INIT ───────handshake_init────────► CHALLENGE
    ◄────────challenge_failure─────────┘
    │                                       │
    └──────────────────────────────────────► ESTABLISHED
                            challenge_success
```

## Debugging Traces

### Retrieving Logs

```python
from src.formal.qasp_model import get_trace_log
traces = get_trace_log()
for trace in traces:
    print(f"{trace['event_type']} at {trace['timestamp']}")
```

### Clearing Logs

```python
from src.formal.qasp_model import clear_trace_log
clear_trace_log()  # For clean test runs
```

## Integration with Testing

### Pytest Integration

Tests automatically generate traces. Run with tracing:

```bash
pytest tests/test_qasp_handshake.py --capture=no -s
```

### Adversary Testing

Use traces to validate protocol resilience:

```python
# Check for invalid state transitions in trace
traces = get_trace_log()
last_state = "INIT"
for trace in traces:
    payload = trace["payload"]
    current_state = payload["state"]
    if not validate_transition(last_state, current_state, trace["event_type"]):
        raise AssertionError(f"Invalid transition: {last_state} -> {current_state}")
    last_state = current_state
```

## Best Practices

1. **Always run formal tests** before protocol changes
2. **Use traces for debugging** authentication failures
3. **Model new features** in TLA+ before implementation
4. **Verify traces match specification** after changes
5. **Include tenant_id** in all security analyses (multi-tenant isolation)

## Limitations

- Trace logging is for testing/analysis only (production systems may disable)
- Model checkers are computationally intensive for large traces
- Real-time properties may require extended models

## References

- [TLA+ Documentation](https://lamport.azurewebsites.net/tla/tla.html)
- [ProVerif Manual](https://prosecco.gforge.inria.fr/personal/bblanche/proverif/manual.pdf)
- `specs/QASP_V0_2.md` for protocol specification
