// @vitest-environment happy-dom
/** The DOM builder inserts text only and refuses every attribute outside its allowlist. */
import { describe, expect, it } from 'vitest';
import { h } from '../src/ui/dom.js';

describe('dom builder', () => {
  it('inserts strings as text nodes', () => {
    const el = h('p', {}, ['<b onclick="x()">bold</b>']);
    expect(el.children.length).toBe(0);
    expect(el.textContent).toBe('<b onclick="x()">bold</b>');
  });

  it('refuses URL, style and handler attributes', () => {
    for (const attr of ['href', 'src', 'style', 'onclick', 'srcdoc', 'formaction', 'action']) {
      expect(() => h('a', { [attr]: 'javascript:alert(1)' }), attr).toThrow('attribute not allowed');
    }
  });
});
