# Protocol layer: device-sealed input requests (ADR 0004)

Status: DONE_WITH_CONCERNS (Worker typecheck breaks until the Worker change lands, as expected).

## Delivered
- `packages/protocol/src/input-seal.ts` (new): `INPUT_SEAL_ALG`, `InputSealContext`, `parseInputSealContext`,
  `InputSealPayload`, `parseInputSealPayload`, `InputSealWire`, `parseInputSeal`, `sealInput`,
  `sealInputWithVectorValues` (not re-exported), `openInput`, `generateInputKeyPair`. Exported from `index.ts`.
- Relay (TS + Go): tools `request_input`, `input_deliver` (`vault-mcp:write`); error codes `expired`,
  `decrypt_failed`; `MCP_RELAY_TOOLS`/`McpRelayTool` (the seven old tools) and `INPUT_RELAY_TOOLS`;
  Go `MCPRelayTools`, `InputRelayTools`, `ToolRequestInput`, `ToolInputDeliver`, `RelayErrExpired`, `RelayErrDecryptFailed`.
  Args/result validation per the brief; `input_deliver` args refuse any seal parse failure (incl. v2) as `bad_request`.
- Go `go/akv1/input_seal.go`: `AlgInputSeal`, `InputSealContext` (Purpose "" = null), `InputSealPayload`, `InputSeal`,
  `ParseInputSealContext`, `ParseInputSealPayload`, `ParseInputSeal`, `SealInput`, `OpenInput`, `GenerateInputKeyPair`.
- Vectors: new `protocol/v1/vectors/input-seal.json` (3 cases, 29 invalid, 7 seal_invalid); `relay-frames.json` extended
  (new frames, hello rule, tool args/results valid and invalid).
- Spec: new §3.11 with `#### Device contract (relay side)` (anchor `#device-contract-relay-side`); §9.7 hello tool count,
  scopes, error code set, tool set and table rows, vectors line.

## Additions beyond the literal brief (flag for review)
- `hello` listing exactly one of the two input tools is refused (`bad_request`), from ADR "Advertise".
- Device contract: an `input_deliver` that reaches a held key drops it whatever the outcome (stricter than the ADR,
  consistent with D5's single submission); `request_input` refuses an already-held `request_id` (`invalid_args`) and
  an `expires_at` at or before the device clock (`expired`).
- Sensitivity of the written record: higher of head and payload `sensitivity`, else the request's.

## Evidence
- `pnpm --filter @ak-vault/protocol typecheck`: pass. `pnpm -r typecheck` excluding worker: protocol, vault-app, e2e pass.
- `pnpm --filter @ak-vault/protocol test`: 17 files, 969 tests pass.
- `go -C go vet ./...` and `go -C go test ./... -count=1`: pass (input-seal.json 40 cases, relay-frames.json 111).
- `pnpm vectors` second run: "wrote 0 changed of 29", hashes identical.
- Worker typecheck fails only in `src/mcp/tools.ts` (DEFINITIONS lacks the two tools) and
  `src/mcp/tool-dispatch.ts` (error-message map lacks `expired`, `decrypt_failed`); owned by the orchestrator.

## Unresolved
- Threat model not touched (outside my ownership); §3.11 adds a guarantee (AAD binding) that it may want to cite.
