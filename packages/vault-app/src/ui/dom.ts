/**
 * The only way the dashboard builds DOM. Text is always a Text node
 * (`createTextNode`), attributes come from a fixed allowlist and never include
 * `href`, `src`, `style`, `srcdoc` or an inline handler, and there is no
 * `innerHTML`, `insertAdjacentHTML` or `document.write` anywhere. With
 * `trusted-types 'none'` in the CSP, any HTML sink would throw anyway.
 */

const ALLOWED_ATTRS = new Set([
  'class', 'id', 'type', 'name', 'for', 'role', 'autocomplete', 'autocapitalize', 'spellcheck', 'inputmode', 'placeholder',
  'maxlength', 'rows', 'disabled', 'readonly', 'required', 'title', 'aria-label', 'aria-live', 'aria-describedby', 'aria-busy', 'aria-expanded', 'aria-controls', 'data-testid',
  // Password-manager opt-outs (1Password, LastPass, Bitwarden, Dashlane and others).
  'data-1p-ignore', 'data-lpignore', 'data-bwignore', 'data-form-type',
]);

export type Child = Node | string | null | undefined | false;
export type Attrs = Record<string, string | boolean | undefined>;
export type Handlers = Partial<Record<'click' | 'submit' | 'input' | 'keydown', (ev: Event) => void>>;

export function h(tag: keyof HTMLElementTagNameMap, attrs: Attrs = {}, children: Child[] = [], on: Handlers = {}): HTMLElement {
  const el = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (!ALLOWED_ATTRS.has(name)) throw new Error('attribute not allowed');
    if (value === undefined || value === false) continue;
    el.setAttribute(name, value === true ? '' : value);
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    el.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  for (const [event, handler] of Object.entries(on)) if (handler) el.addEventListener(event, handler);
  return el;
}

export function replaceChildren(parent: Element, ...children: Node[]): void {
  while (parent.firstChild) parent.removeChild(parent.firstChild);
  for (const c of children) parent.appendChild(c);
}
