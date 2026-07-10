# ADR 0002: KAG Query Interception Boundary

- Status: accepted
- Date: 2026-07-10
- Parent: GitHub issue #34
- Implements: GitHub issue #36
- Inspected package: OpenSPG/KAG `0.8.0`
- Inspected source: local `v0.8.0-9-gfdab15b3`

## Decision

The complete OpenSPG/KAG solver is a **No-Go** as knote's permissioned query boundary. KAG remains the builder and storage integration. Knote owns retrieval orchestration, authorization, per-frontier expansion decisions, evidence loading, and generation.

The production path will use three explicit adapter primitives:

1. `kag.retrieve` returns ID-only candidate handles.
2. `kag.expand` accepts an already-authorized frontier and returns ID-only expansion handles.
3. `kag.generate` accepts only an already-authorized evidence set.

The fake adapter implements these contracts for deterministic contract and leak tests. Real mode returns the typed error code `unsupported_primitive` until issue #39 supplies a proven low-level implementation. It must return that error before config loading, health checks, solver construction, graph access, trace creation, or LLM calls.

Legacy `kag.query` and `kag.explain` remain compatibility methods for existing non-permissioned smoke coverage. They are not a secure production query path and must not be selected by the future authorized gateway.

## Observed Execution Paths

The builder path is suitable for continued use:

```text
Client.Build
 -> adapter run_kag_build
 -> BuilderChainRunner.invoke
 -> DefaultUnstructuredBuilderChain.invoke
 -> reader / splitter / extractor / vectorizer / writer
```

Relevant sources:

- `internal/knowledge/kag/client.go`
- `adapters/kag/knote_kag_adapter.py`
- KAG `kag/builder/runner.py`
- KAG `kag/builder/default_chain.py`

The current query path is opaque before knote regains control:

```text
Client.Query
 -> adapter run_kag_query
 -> SolverPipelineABC.from_config
 -> KAGStaticPipeline.ainvoke
 -> KAGLFStaticPlanner.ainvoke
 -> task executors
 -> KAGHybridRetrievalExecutor
 -> LLMIndexGenerator
```

Relevant KAG sources:

- `kag/solver/pipeline/kag_static_pipeline.py`
- `kag/solver/planner/lf_kag_static_planner.py`
- `kag/solver/executor/retriever/kag_hybrid_retrieval_executor.py`
- `kag/solver/generator/llm_index_generator.py`

## Interception Findings

### Retrieval

KAG exposes replaceable `RetrieverABC`, `SearchApiABC`, `GraphApiABC`, and executor components through its registry/configuration system. Stock execution nevertheless calls retrievers directly and provides no supported before/after retrieval authorization callback. Replacing every component would be a solver fork in practice, not a stable hook.

### Graph expansion

There is no supported per-hop authorization callback. `FuzzyOneHopSelect` materializes a complete one-hop graph, converts it to candidate SPO text, and invokes an LLM selector before returning. PPR delegates traversal to one opaque server-side calculation and exposes only final scores. The retriever template also does not propagate arbitrary request authorization context into path selection.

Relevant KAG sources:

- `kag/common/tools/algorithm_tool/graph_retriever/path_select/fuzzy_one_hop_select.py`
- `kag/common/tools/algorithm_tool/chunk_retriever/ppr_chunk_retriever.py`
- `kag/common/tools/algorithm_tool/graph_retriever/lf_kg_retriever_template.py`
- `kag/common/tools/graph_api/impl/openspg_graph_api.py`

### Generation and observability

`GeneratorABC` can be replaced, but final-generation interception is too late:

- The generated knote KAG config enables retrieval summaries.
- The hybrid retrieval executor sends relations and chunks to context-selection and summary LLMs before final generation.
- Fuzzy graph selection can invoke an LLM before the final generator.
- The static pipeline prints task memory and results; the adapter redirects captured KAG stdout to stderr.
- The current real adapter discards structured evidence and exposes only the final answer.

Filtering the final answer, citation list, or generator input therefore cannot prevent protected content from reaching solver memory, traces, stderr, intermediate LLMs, or graph operations.

## Primitive Contracts

Candidate handles contain only:

```json
{
  "resource": {
    "resource_id": "res_11111111111111111111111111111111",
    "type": "chunk",
    "tenant_id": "tenant-1",
    "knowledge_base_id": "kb-1",
    "authz_object": "document:res_22222222222222222222222222222222",
    "authorization_resource_id": "res_22222222222222222222222222222222",
    "content_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "versions": {
      "source": "source-v1",
      "content": "content-v1",
      "acl": "acl-v1",
      "index": "index-v1",
      "graph": "graph-v1",
      "projection": "projection-v1"
    },
    "serving_state": "serving"
  },
  "score": 0.9
}
```

They do not contain titles, paths, snippets, relation labels, or bodies. Expansion output adds only opaque source and target resource IDs plus a hop number.

Generation input is the first primitive allowed to carry bodies. Its `evidence` array is explicitly defined as already authorized and contains the exact versioned resource handle, body, and citation handle. Both Go and the adapter verify the body against the handle's canonical SHA-256 digest before generation. Generation output carries only the answer, citation handles, evidence resource IDs, and a handle/count trace.

Authorization context is not part of these adapter JSON parameters. The trusted Go gateway owns authorization and invokes `kag.expand` and `kag.generate` only after the required checks.

## Failure, Cancellation, and Timeout Behavior

- Missing or malformed primitive inputs fail before the subprocess is started.
- Unknown methods remain ordinary adapter errors.
- Unimplemented real primitives return `unsupported_primitive` without touching KAG.
- Go context cancellation and deadlines terminate the adapter subprocess through `exec.CommandContext` and return the original context error.
- `kag.cancel` is only a protocol acknowledgement in the current one-request subprocess model; it is not the production cancellation mechanism.
- Partial, malformed, or oversized adapter output remains an error and cannot produce candidates or evidence.

## Option Assessment

| Option | Decision | Reason |
|---|---|---|
| Configure supported KAG hooks | No-Go | Component replacement exists, but the required retrieval, per-hop, and pre-LLM authorization hooks do not. |
| Wrap or fork the complete solver | Not selected | An outer wrapper is too late; a secure fork would need to replace retrieval executors, graph selectors, PPR, summaries, reporters, generators, and debug output. |
| KAG builder/storage with knote orchestration | Selected | It provides an explicit authorization point before bodies, graph hops, traces, and generation. |

## Consequences

- Issue #37 can implement authorization without importing KAG internals.
- Issue #38 must produce stable projection/index handles and a catalog that loads bodies only after authorization.
- Issue #39 owns the real retrieval primitive, the authorized gateway, and runtime wiring.
- Phase 1 graph expansion may remain disabled if an ID-only low-level primitive cannot be proven safe.
- Real KAG build smoke remains valid. Legacy real query/explain smoke is compatibility evidence only and is not a permissioned-query acceptance gate.
