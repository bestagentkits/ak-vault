/** relay-frames.json */
import {
  cjson,
  parseRelayFrame,
  parseToolArgs,
  parseToolResult,
  signHello,
  signResult,
  verifyHello,
  verifyResult,
  type JsonObject,
  type RelayTool,
  utf8Encode,
} from '../../src/index.js';
import { alicePhone, aliceNewPhone, BASE_TS, flipByte, id, negative, VAULT_PERSONAL, VAULT_SHARED } from './fixtures.js';

const MAX_BYTES = 131_072;
const NOW = BASE_TS + 3_600_000;

export function relayFrameVectors(): Record<string, unknown> {
  const signPub = alicePhone.record.sign_pub;
  const hello = signHello({ device_id: alicePhone.record.device_id, vaults: [VAULT_SHARED, VAULT_PERSONAL], tools: ['search', 'list', 'describe', 'set', 'delete', 'request', 'run'], ts: NOW }, alicePhone.signSecret);
  const call = {
    v: 1, type: 'call', call_id: id('relay/call/1'), vault_id: VAULT_SHARED, tool: 'describe', args: { name: 'STRIPE_SECRET_KEY' },
    caller: { client_id: 'mcp-client-example', grant_id: 'grant_example_1', scopes: ['vault-mcp:read', 'vault-mcp:write'] }, deadline_ms: 25_000,
  };
  const okResult = signResult({ call_id: call.call_id, ok: true, result: { name: 'STRIPE_SECRET_KEY', profile: { provider: { value: 'stripe', origin: 'sync' } }, sensitivity: 'high' } }, alicePhone.signSecret);
  const errResult = signResult({ call_id: id('relay/call/2'), ok: false, error: { code: 'pending_approval' } }, alicePhone.signSecret);
  const vaultList = (n: number) => Array.from({ length: n }, (_, i) => id(`relay/vault/${i}`));
  const helloLimits = signHello({ device_id: alicePhone.record.device_id, vaults: vaultList(16), tools: ['search'], ts: NOW }, alicePhone.signSecret);
  const helloMin = signHello({ device_id: alicePhone.record.device_id, vaults: [VAULT_SHARED], tools: ['list'], ts: NOW }, alicePhone.signSecret);
  const frames = [
    { name: 'hello', frame: hello },
    { name: 'hello_16_vaults_1_tool', frame: helloLimits },
    { name: 'hello_1_vault_1_tool', frame: helloMin },
    { name: 'call_1_scope', frame: { ...call, caller: { ...call.caller, scopes: ['vault-mcp:use'] } } },
    { name: 'call_3_scopes', frame: { ...call, caller: { ...call.caller, scopes: ['vault-mcp:read', 'vault-mcp:write', 'vault-mcp:use'] } } },
    { name: 'ready', frame: { v: 1, type: 'ready', exp: NOW + 900_000 } },
    { name: 'reauth', frame: { v: 1, type: 'reauth', token: 'akv1.synthetic-token-not-real', proof: 'v1.synthetic-proof-not-real' } },
    { name: 'call', frame: call },
    { name: 'result_ok', frame: okResult },
    { name: 'result_error', frame: errResult },
  ].map(({ name, frame }) => {
    const text = cjson(frame as JsonObject);
    parseRelayFrame(text, { maxBytes: MAX_BYTES });
    return { name, text };
  });

  const badText = (name: string, code: string, text: string) => negative(name, code, { text }, () => parseRelayFrame(text, { maxBytes: MAX_BYTES }));
  const t = (o: object) => cjson(o as JsonObject);
  const oversize = t({ ...call, args: { name: 'x'.repeat(MAX_BYTES) } });
  const helloBad = (name: string, code: string, frame: unknown, now = NOW) =>
    negative(name, code, { frame, sign_pub: signPub, now }, () => verifyHello(frame, { signPub, now }));
  const resultBad = (name: string, code: string, frame: unknown) => negative(name, code, { frame, sign_pub: signPub }, () => verifyResult(frame, signPub));

  type ArgCase = { name: string; tool: RelayTool; args: unknown };
  const argOk = (c: ArgCase) => (parseToolArgs(c.tool, c.args), c);
  const argBad = (c: ArgCase) => negative(c.name, 'bad_request', { tool: c.tool, args: c.args }, () => parseToolArgs(c.tool, c.args));
  const resOk = (c: { name: string; tool: RelayTool; result: unknown }) => (parseToolResult(c.tool, c.result), c);
  const resBad = (c: { name: string; tool: RelayTool; result: unknown }) => negative(c.name, 'bad_request', { tool: c.tool, result: c.result }, () => parseToolResult(c.tool, c.result));
  const entry = { name: 'OPENAI_API_KEY', profile: { provider: { value: 'openai', origin: 'local' }, tags: { value: ['ml'], origin: 'sync' } }, updated_at: NOW };

  return {
    version: 1,
    description:
      'Device relay frames and tools (spec §9.7). Frames are canonical-JSON text WebSocket frames of at most max_bytes UTF-8 bytes (a binary frame is refused). parseRelayFrame(text, {max_bytes}): size; canonical cjson; v = 1 (unsupported_version); type in {hello, ready, reauth, call, result}; exact keys per type: ' +
      'hello {v,type,device_id,vaults (1..16 unique IDs),tools (1..7 unique tool names),ts,sig}; ready {v,type,exp}; reauth {v,type,token,proof} (non-empty strings); call {v,type,call_id,vault_id,tool,args (object),caller {client_id 1..256 and grant_id 1..64 printable ASCII, scopes 1..3 unique of vault-mcp:read|write|use},deadline_ms >= 1}; result {v,type,call_id,ok,sig} plus result (object) when ok is true or error {code} when ok is false, code in {denied, pending_approval, not_found, invalid_args, conflict, unsupported, internal}. Every refusal is bad_request. ' +
      'hello is signed with context "akv1/relay", result with "akv1/relay-result", over the frame without sig, by the device key. verifyHello(frame, {sign_pub, now}): device_id = kid(sign_pub) (forbidden); signature (invalid_signature); |now - ts| <= 60000 (unauthorized). verifyResult(frame, sign_pub): signature (invalid_signature). ' +
      'frames MUST parse; invalid_text MUST fail parseRelayFrame (binary: a binary frame carrying binary_utf8 bytes); invalid_hello and invalid_result MUST fail with expect_error. tool_args and tool_results: parseToolArgs(tool, args) and parseToolResult(tool, result) per the §9.7 table; *_invalid MUST fail with bad_request (a device answers invalid_args); an args object with value_fill uses value = value_fill repeated value_length times.',
    max_bytes: MAX_BYTES,
    device: { device_id: alicePhone.record.device_id, sign_pub: signPub },
    now: NOW,
    frames,
    invalid_text: [
      negative('binary_frame', 'bad_request', { binary_utf8: frames[1]!.text }, () => parseRelayFrame(utf8Encode(frames[1]!.text), { maxBytes: MAX_BYTES })),
      badText('oversize', 'bad_request', oversize),
      badText('unknown_type', 'bad_request', t({ v: 1, type: 'ping' })),
      badText('extra_key', 'bad_request', t({ v: 1, type: 'ready', exp: NOW, extra: 1 })),
      badText('missing_key', 'bad_request', t({ v: 1, type: 'ready' })),
      badText('non_canonical', 'bad_request', JSON.stringify({ v: 1, type: 'ready', exp: NOW }).replace('{', '{ ')),
      badText('result_ok_with_error', 'bad_request', t({ ...okResult, error: { code: 'internal' } })),
      badText('result_error_with_result', 'bad_request', t({ ...errResult, result: {} })),
      badText('unknown_error_code', 'bad_request', t({ ...errResult, error: { code: 'timeout' } })),
      badText('error_extra_key', 'bad_request', t({ ...errResult, error: { code: 'denied', message: 'no' } })),
      badText('hello_duplicate_vault', 'bad_request', t({ ...hello, vaults: [VAULT_SHARED, VAULT_SHARED] })),
      badText('hello_empty_vaults', 'bad_request', t({ ...hello, vaults: [] })),
      badText('hello_17_vaults', 'bad_request', t({ ...hello, vaults: vaultList(17) })),
      badText('hello_no_tools', 'bad_request', t({ ...hello, tools: [] })),
      badText('hello_8_tools', 'bad_request', t({ ...hello, tools: [...hello.tools, 'search'] })),
      badText('hello_duplicate_tool', 'bad_request', t({ ...hello, tools: ['search', 'search'] })),
      badText('hello_unknown_tool', 'bad_request', t({ ...hello, tools: ['exec'] })),
      badText('call_empty_scopes', 'bad_request', t({ ...call, caller: { ...call.caller, scopes: [] } })),
      badText('call_4_scopes', 'bad_request', t({ ...call, caller: { ...call.caller, scopes: ['vault-mcp:read', 'vault-mcp:write', 'vault-mcp:use', 'vault-mcp:read'] } })),
      badText('call_duplicate_scope', 'bad_request', t({ ...call, caller: { ...call.caller, scopes: ['vault-mcp:read', 'vault-mcp:read'] } })),
      badText('call_unknown_scope', 'bad_request', t({ ...call, caller: { ...call.caller, scopes: ['vault-mcp:admin'] } })),
      badText('call_zero_deadline', 'bad_request', t({ ...call, deadline_ms: 0 })),
      badText('reauth_empty_token', 'bad_request', t({ v: 1, type: 'reauth', token: '', proof: 'p' })),
      badText('version_2', 'unsupported_version', t({ v: 2, type: 'ready', exp: NOW })),
    ],
    invalid_hello: [
      helloBad('bad_signature', 'invalid_signature', { ...hello, sig: flipByte(hello.sig, 5) }),
      helloBad('tampered_vaults', 'invalid_signature', { ...hello, vaults: [VAULT_SHARED] }),
      helloBad('signed_by_other_device', 'forbidden', signHello({ device_id: aliceNewPhone.record.device_id, vaults: [VAULT_SHARED], tools: ['search'], ts: NOW }, aliceNewPhone.signSecret)),
      helloBad('stale_ts', 'unauthorized', hello, NOW + 60_001),
      helloBad('future_ts', 'unauthorized', hello, NOW - 60_001),
    ],
    invalid_result: [
      resultBad('bad_signature', 'invalid_signature', { ...okResult, sig: flipByte(okResult.sig, 7) }),
      resultBad('tampered_result', 'invalid_signature', { ...okResult, result: { name: 'OTHER', profile: {}, sensitivity: 'normal' } }),
      resultBad('signed_by_other_device', 'invalid_signature', signResult({ call_id: call.call_id, ok: true, result: okResult.ok ? okResult.result : {} }, aliceNewPhone.signSecret)),
      resultBad('hello_signature_context', 'invalid_signature', { ...okResult, sig: hello.sig }),
    ],
    tool_args: [
      argOk({ name: 'search', tool: 'search', args: { query: 'stripe live', fields: ['provider', 'tags'], limit: 10 } }),
      argOk({ name: 'list_empty', tool: 'list', args: {} }),
      argOk({ name: 'list_cursor', tool: 'list', args: { cursor: 'c1', limit: 100 } }),
      argOk({ name: 'describe', tool: 'describe', args: { name: 'STRIPE_SECRET_KEY' } }),
      argOk({ name: 'set', tool: 'set', args: { name: 'A', value: 'v', sensitivity: 'normal' } }),
      argOk({ name: 'delete', tool: 'delete', args: { name: 'A' } }),
      argOk({ name: 'request', tool: 'request', args: { name: 'A', purpose: 'Deploy the billing service', project: 'billing', ttl_s: 3600 } }),
      argOk({ name: 'run', tool: 'run', args: { argv: ['npm', 'run', 'deploy'], env: [{ var: 'STRIPE_KEY', name: 'STRIPE_SECRET_KEY' }], cwd_project: 'billing', timeout_s: 110 } }),
    ],
    tool_args_invalid: [
      argBad({ name: 'search_empty_query', tool: 'search', args: { query: '' } }),
      argBad({ name: 'search_query_too_long', tool: 'search', args: { query: 'q'.repeat(201) } }),
      argBad({ name: 'search_unknown_field', tool: 'search', args: { query: 'a', fields: ['value'] } }),
      argBad({ name: 'search_limit_51', tool: 'search', args: { query: 'a', limit: 51 } }),
      argBad({ name: 'list_extra_key', tool: 'list', args: { all: true } }),
      argBad({ name: 'describe_missing_name', tool: 'describe', args: {} }),
      negative('set_too_large_to_seal', 'bad_request', { tool: 'set', args: { name: 'A' }, value_fill: 'v', value_length: 65_536 }, () => parseToolArgs('set', { name: 'A', value: 'v'.repeat(65_536) })),
      argBad({ name: 'set_unknown_sensitivity', tool: 'set', args: { name: 'A', value: 'v', sensitivity: 'low' } }),
      argBad({ name: 'request_ttl_too_long', tool: 'request', args: { name: 'A', purpose: 'p', ttl_s: 86_401 } }),
      argBad({ name: 'run_empty_argv', tool: 'run', args: { argv: [], env: [{ var: 'A', name: 'A' }] } }),
      argBad({ name: 'run_bad_var', tool: 'run', args: { argv: ['x'], env: [{ var: 'lower', name: 'A' }] } }),
      argBad({ name: 'run_duplicate_var', tool: 'run', args: { argv: ['x'], env: [{ var: 'A', name: 'A' }, { var: 'A', name: 'B' }] } }),
      argBad({ name: 'run_timeout_111', tool: 'run', args: { argv: ['x'], env: [{ var: 'A', name: 'A' }], timeout_s: 111 } }),
    ],
    tool_results: [
      resOk({ name: 'search', tool: 'search', result: { items: [entry] } }),
      resOk({ name: 'list', tool: 'list', result: { items: [], next_cursor: 'c2' } }),
      resOk({ name: 'describe', tool: 'describe', result: { name: 'A', profile: {}, sensitivity: 'normal', created_at: NOW, last_device_label: 'Alice phone' } }),
      resOk({ name: 'set_written', tool: 'set', result: { status: 'written', revision: 3 } }),
      resOk({ name: 'set_conflict', tool: 'set', result: { status: 'conflict' } }),
      resOk({ name: 'delete_not_found', tool: 'delete', result: { status: 'not_found' } }),
      resOk({ name: 'request', tool: 'request', result: { status: 'pending', request_id: 'req_1' } }),
      resOk({ name: 'run', tool: 'run', result: { exit_code: 137, stdout: '', stderr: 'killed', truncated: false } }),
    ],
    tool_results_invalid: [
      resBad({ name: 'entry_unknown_origin', tool: 'search', result: { items: [{ ...entry, profile: { provider: { value: 'x', origin: 'remote' } } }] } }),
      resBad({ name: 'entry_extra_key', tool: 'list', result: { items: [{ ...entry, value: 'secret' }] } }),
      resBad({ name: 'describe_with_value', tool: 'describe', result: { name: 'A', profile: {}, sensitivity: 'normal', value: 'secret' } }),
      resBad({ name: 'set_written_without_revision', tool: 'set', result: { status: 'written' } }),
      resBad({ name: 'delete_unknown_status', tool: 'delete', result: { status: 'gone' } }),
      resBad({ name: 'run_missing_truncated', tool: 'run', result: { exit_code: 0, stdout: '', stderr: '' } }),
      resBad({ name: 'run_negative_exit_code', tool: 'run', result: { exit_code: -1, stdout: '', stderr: '', truncated: false } }),
    ],
  };
}
