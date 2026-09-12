import { PoolingConfigError } from './pooling-errors.mjs';

// Span editing intentionally keeps unrequested bytes, spelling and whitespace.
export class JsonSpans {
  constructor(bytes) {
    this.text = bytes.toString('utf8');
    this.offset = 0;
    try {
      if (!Buffer.from(this.text).equals(bytes)) throw new Error();
      this.servers = JSON.parse(this.text);
      if (!this.servers ||
          Array.isArray(this.servers) ||
          typeof this.servers !== 'object') throw new Error();
      this.root = this.value(0);
    } catch {
      throw new PoolingConfigError(400, 'INVALID_CONFIG',
        'Config must be a UTF-8 JSON object without duplicate keys or excessive nesting.');
    }
  }

  whitespace() {
    while (' \t\r\n'.includes(this.text[this.offset] ?? '\0')) this.offset++;
  }

  string() {
    const start = this.offset++;
    while (this.text[this.offset] !== '"') {
      this.offset += this.text[this.offset] === '\\' ? 2 : 1;
    }
    this.offset++;
    return JSON.parse(this.text.slice(start, this.offset));
  }

  value(depth) {
    if (depth > 128) throw new Error();
    this.whitespace();
    const start = this.offset;
    const token = this.text[this.offset];
    const properties = new Map();
    if (token === '{') {
      this.offset++;
      this.whitespace();
      while (this.text[this.offset] !== '}') {
        const keyStart = this.offset;
        const key = this.string();
        const keyEnd = this.offset;
        if (properties.has(key)) throw new Error();
        this.whitespace();
        this.offset++;
        const value = this.value(depth + 1);
        properties.set(key, { keyStart, keyEnd, value });
        this.whitespace();
        if (this.text[this.offset] !== ',') break;
        this.offset++;
        this.whitespace();
      }
      this.offset++;
    } else if (token === '[') {
      this.offset++;
      this.whitespace();
      while (this.text[this.offset] !== ']') {
        this.value(depth + 1);
        this.whitespace();
        if (this.text[this.offset] !== ',') break;
        this.offset++;
      }
      this.offset++;
    } else if (token === '"') {
      this.string();
    } else {
      while (this.offset < this.text.length &&
             !' \t\r\n,}]'.includes(this.text[this.offset])) this.offset++;
    }
    return { start, end: this.offset, properties };
  }

  update(name, changes) {
    const server = this.root.properties.get(name).value;
    const entries = [...server.properties.values()];
    const edits = [];
    const additions = [];
    for (const [key, value] of changes) {
      const property = server.properties.get(key);
      if (!property) {
        if (value !== undefined) additions.push([key, value]);
        continue;
      }
      if (value === undefined) {
        const index = entries.indexOf(property);
        const previous = entries[index - 1];
        const next = entries[index + 1];
        edits.push({
          start: previous ? previous.value.end : property.keyStart,
          end: previous ? property.value.end : next.keyStart,
          text: '',
        });
      } else if (this.servers[name][key] !== value) {
        edits.push({ start: property.value.start, end: property.value.end, text: JSON.stringify(value) });
      }
    }
    if (additions.length) {
      const first = entries[0];
      const last = entries.at(-1);
      const spacing = this.text.slice(server.start + 1, first.keyStart);
      const colon = this.text.slice(first.keyEnd, first.value.start);
      const text = additions.map(([key, value]) =>
        `,${spacing}${JSON.stringify(key)}${colon}${JSON.stringify(value)}`).join('');
      edits.push({ start: last.value.end, end: last.value.end, text });
    }
    let text = this.text;
    for (const edit of edits.sort((a, b) => b.start - a.start)) {
      text = text.slice(0, edit.start) + edit.text + text.slice(edit.end);
    }
    return Buffer.from(text);
  }

  validateComplete() {
    for (const server of Object.values(this.servers)) {
      if (!server ||
          Array.isArray(server) ||
          typeof server !== 'object' ||
          (!server.command && !server.url)) {
        throw new PoolingConfigError(400, 'INVALID_CONFIG',
          'Every server definition must be an object with a command or URL.');
      }
    }
  }
}
