'use strict';

const vscode = require('vscode');

/** @type {Promise<any> | null} */
let wasmInitPromise = null;
/** @type {any | null} */
let wasmApi = null;
/** @type {any | null} */
let protocolSchema = null;

/**
 * Escapes arbitrary strings for safe interpolation inside Webview HTML.
 * @param {unknown} text
 * @returns {string}
 */
function escapeHtml(text) {
  return String(text ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Generates a cryptographic or high-entropy nonce for Webview Content-Security-Policy scripts.
 * @returns {string}
 */
function createNonce() {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let out = '';
  for (let i = 0; i < 32; i += 1) {
    out += alphabet.charAt(Math.floor(Math.random() * alphabet.length));
  }
  return out;
}

/**
 * Lazily loads `protocol_schema.json` using `vscode.workspace.fs` so it works identically
 * in both Desktop Node Extension Hosts and Browser Web Extension Hosts.
 * @param {vscode.ExtensionContext} context
 * @returns {Promise<any>}
 */
async function ensureProtocolSchema(context) {
  if (protocolSchema) {
    return protocolSchema;
  }
  const schemaUri = vscode.Uri.joinPath(context.extensionUri, 'protocol_schema.json');
  const rawBytes = await vscode.workspace.fs.readFile(schemaUri);
  protocolSchema = JSON.parse(new TextDecoder('utf-8').decode(rawBytes));
  return protocolSchema;
}

/**
 * Lazily imports and initializes `./wasm/frameassembly_wasm.js` + `frameassembly_wasm_bg.wasm`
 * across both Desktop Node Extension Hosts (`file:` URI) and Browser Web Extension Hosts.
 * @param {vscode.ExtensionContext} context
 * @returns {Promise<any>}
 */
async function ensureWasm(context) {
  if (wasmApi) {
    return wasmApi;
  }
  if (wasmInitPromise) {
    return wasmInitPromise;
  }

  wasmInitPromise = (async () => {
    const jsUri = vscode.Uri.joinPath(context.extensionUri, 'wasm', 'frameassembly_wasm.js');
    const wasmUri = vscode.Uri.joinPath(context.extensionUri, 'wasm', 'frameassembly_wasm_bg.wasm');

    let mod;
    if (jsUri.scheme === 'file') {
      // Desktop / Remote Node Extension Host
      // eslint-disable-next-line global-require
      const { pathToFileURL } = require('url');
      mod = await import(pathToFileURL(jsUri.fsPath).href);
    } else {
      // Browser Web Extension Host (`vscode.dev`, `github.dev`, etc.)
      try {
        mod = await import(jsUri.toString(true));
      } catch (_err) {
        const jsBytes = await vscode.workspace.fs.readFile(jsUri);
        const jsSource = new TextDecoder('utf-8').decode(jsBytes);
        const blob = new Blob([jsSource], { type: 'text/javascript' });
        const blobUrl = URL.createObjectURL(blob);
        try {
          mod = await import(blobUrl);
        } finally {
          URL.revokeObjectURL(blobUrl);
        }
      }
    }

    const wasmBytes = await vscode.workspace.fs.readFile(wasmUri);
    if (typeof mod.default === 'function') {
      await mod.default({ module_or_path: wasmBytes });
    } else if (typeof mod.initSync === 'function') {
      mod.initSync({ module: wasmBytes });
    }

    wasmApi = mod;
    return mod;
  })();

  try {
    return await wasmInitPromise;
  } catch (err) {
    wasmInitPromise = null;
    throw err;
  }
}

/**
 * Resolves the WASM `validate` export, preferring the 3.0 `.frasm` names and falling back to 2.x names.
 * @param {any} wasm
 * @returns {(source: string) => Array<any>}
 */
function resolveValidateFn(wasm) {
  return wasm.validateFrasm || wasm.validate_frasm || wasm.validateFasm || wasm.validate_fasm;
}

/**
 * Resolves the WASM `inspect` export, preferring the 3.0 `.frasm` names and falling back to 2.x names.
 * @param {any} wasm
 * @returns {(source: string) => Array<any>}
 */
function resolveInspectFn(wasm) {
  return wasm.inspectFrasm || wasm.inspect_frasm || wasm.inspect_fasm;
}

/**
 * Resolves the WASM `compile` export, preferring the 3.0 `.frasm` names and falling back to 2.x names.
 * @param {any} wasm
 * @returns {(source: string) => Uint8Array}
 */
function resolveCompileFn(wasm) {
  return wasm.compileFrasm || wasm.compile_frasm_to_pcapng || wasm.compile_fasm_to_pcapng;
}

/**
 * Replaces the file extension on a `vscode.Uri` while preserving directory and query/authority.
 * @param {vscode.Uri} uri
 * @param {string} newExtWithDot
 * @returns {vscode.Uri}
 */
function replaceUriExtension(uri, newExtWithDot) {
  const pathStr = uri.path;
  const slashIdx = pathStr.lastIndexOf('/');
  const dotIdx = pathStr.lastIndexOf('.');
  const stem = dotIdx > slashIdx ? pathStr.slice(0, dotIdx) : pathStr;
  return uri.with({ path: `${stem}${newExtWithDot}` });
}

/**
 * Clamps a zero-based `(line, col)` coordinate pair into valid bounds for `document`.
 * @param {vscode.TextDocument} document
 * @param {number} line
 * @param {number} col
 * @returns {vscode.Position}
 */
function clampPosition(document, line, col) {
  const maxLine = Math.max(0, document.lineCount - 1);
  const safeLine = Math.min(Math.max(0, line | 0), maxLine);
  const lineLen = document.lineAt(safeLine).text.length;
  const safeCol = Math.min(Math.max(0, col | 0), lineLen);
  return new vscode.Position(safeLine, safeCol);
}

/**
 * Strips `//` trailing comments from a single line while respecting `"..."` string literals.
 * @param {string} line
 * @returns {{ code: string, inCommentAtEnd: boolean, inStringAtEnd: boolean }}
 */
function analyzeLineState(line) {
  let inString = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (inString) {
      if (ch === '\\') {
        i += 1;
      } else if (ch === '"') {
        inString = false;
      }
    } else if (ch === '"') {
      inString = true;
    } else if (ch === '/' && line[i + 1] === '/') {
      return { code: line.slice(0, i), inCommentAtEnd: true, inStringAtEnd: false };
    }
  }
  return { code: line, inCommentAtEnd: false, inStringAtEnd: inString };
}

/**
 * Parses declared `host` names, `flow` definitions, and cursor block context up to `cursorPosition`.
 * @param {vscode.TextDocument} document
 * @param {vscode.Position} cursorPosition
 * @returns {{
 *   blockKind: 'top' | 'host' | 'flow' | 'compile',
 *   hostNames: string[],
 *   flowDefs: Map<string, string[]>,
 *   activeFlowParams: string[]
 * }}
 */
function inspectDocumentSymbolsAndBlock(document, cursorPosition) {
  const fullText = document.getText();
  const cursorOffset = document.offsetAt(cursorPosition);

  /** @type {Set<string>} */
  const hostSet = new Set();
  /** @type {Map<string, string[]>} */
  const flowDefs = new Map();

  // Lightweight full-document scan for declared hosts and flows (ignoring comments and strings)
  const cleanFull = fullText
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/\/\/[^\r\n]*/g, '');

  const hostRe = /\bhost\s+([A-Za-z_][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)*)\s*\{/g;
  let m;
  while ((m = hostRe.exec(cleanFull)) !== null) {
    hostSet.add(m[1]);
  }

  const flowRe = /\bflow\s+([A-Za-z_][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)*)\s*\(([^)]*)\)\s*\{/g;
  while ((m = flowRe.exec(cleanFull)) !== null) {
    const params = m[2]
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    flowDefs.set(m[1], params);
  }

  // Scan prefix up to cursorOffset to determine enclosing block and active flow parameters
  const prefixClean = fullText
    .slice(0, cursorOffset)
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/\/\/[^\r\n]*/g, (match) => ' '.repeat(match.length));

  /** @type {Array<{ kind: 'host' | 'flow' | 'compile' | 'other', params: string[] }>} */
  const stack = [];
  const tokenRe = /\b(host|flow|compile)\b([^{};]*)\{|\{|\}/g;
  let tok;
  while ((tok = tokenRe.exec(prefixClean)) !== null) {
    const raw = tok[0];
    if (raw === '}') {
      stack.pop();
    } else if (raw === '{') {
      stack.push({ kind: 'other', params: [] });
    } else {
      const kw = /** @type {'host' | 'flow' | 'compile'} */ (tok[1]);
      const headerRest = tok[2] || '';
      /** @type {string[]} */
      let params = [];
      if (kw === 'flow') {
        const parenMatch = headerRest.match(/\(([^)]*)\)/);
        if (parenMatch) {
          params = parenMatch[1]
            .split(',')
            .map((s) => s.trim())
            .filter((s) => s.length > 0);
        }
      }
      stack.push({ kind: kw, params });
    }
  }

  const top = stack.length > 0 ? stack[stack.length - 1] : null;
  const blockKind = top && top.kind !== 'other' ? top.kind : 'top';
  const activeFlowParams = top && top.kind === 'flow' ? top.params : [];

  return {
    blockKind,
    hostNames: Array.from(hostSet),
    flowDefs,
    activeFlowParams,
  };
}

/**
 * Renders the theme-aware HTML for the Live Packet Ladder Webview panel.
 * @param {string} titleName
 * @param {Array<any>} previews
 * @param {string | null} errorBanner
 * @param {boolean} [allowDownload] Show the `Download .pcap` button (browser hosts such as `vscode.dev`).
 * @returns {string}
 */
function renderPacketLadderHtml(titleName, previews, errorBanner, allowDownload) {
  const nonce = createNonce();
  const totalBytes = previews.reduce((acc, p) => acc + (p.length || 0), 0);
  const durationMs =
    previews.length > 0 ? Number(previews[previews.length - 1].timestamp_ms || 0).toFixed(3) : '0.000';

  const rowsHtml = previews
    .map((pkt) => {
      const idx = Number(pkt.index || 0);
      const ts = Number(pkt.timestamp_ms || 0).toFixed(3);
      const srcDst = escapeHtml(pkt.source_dest || '');
      const proto = escapeHtml(pkt.protocol || 'RAW');
      const len = Number(pkt.length || 0);
      const summary = escapeHtml(pkt.summary || '');
      const hex = escapeHtml(pkt.hex || '');
      return `
        <tr class="pkt-row" data-idx="${idx}" title="Click to toggle raw Ethernet frame hex dump">
          <td class="num">${idx}</td>
          <td class="num">${ts}</td>
          <td class="mono">${srcDst}</td>
          <td><span class="proto-badge">${proto}</span></td>
          <td class="num">${len}</td>
          <td class="summary">${summary}</td>
        </tr>
        <tr class="hex-row" id="hex-${idx}" hidden>
          <td colspan="6">
            <div class="hex-box"><strong>Frame #${idx} (${len} bytes):</strong>\n${hex}</div>
          </td>
        </tr>`;
    })
    .join('\n');

  const errorHtml = errorBanner
    ? `<div class="error-banner"><strong>Compiler Diagnostic:</strong> ${escapeHtml(errorBanner)}</div>`
    : '';

  const downloadButtonHtml = allowDownload
    ? '<button class="action-btn" id="download-btn" type="button">Download .pcap</button>'
    : '';

  const emptyHtml =
    previews.length === 0 && !errorBanner
      ? '<tr><td colspan="6" class="empty">No frames emitted yet. Add a frame statement inside <code>compile { ... }</code>.</td></tr>'
      : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>FrameAssembly Packet Ladder</title>
  <style>
    :root {
      color-scheme: light dark;
    }
    body {
      font-family: var(--vscode-font-family, system-ui, -apple-system, sans-serif);
      font-size: var(--vscode-font-size, 13px);
      color: var(--vscode-editor-foreground);
      background: var(--vscode-editor-background);
      margin: 0;
      padding: 14px 16px;
    }
    .toolbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
      padding-bottom: 10px;
      margin-bottom: 12px;
      border-bottom: 1px solid var(--vscode-panel-border, rgba(128, 128, 128, 0.3));
    }
    .title-group {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    .title {
      font-weight: 600;
      font-size: 14px;
    }
    .stats {
      font-size: 12px;
      color: var(--vscode-descriptionForeground);
    }
    .btn-group {
      display: flex;
      gap: 8px;
    }
    button.action-btn {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border: none;
      border-radius: 3px;
      padding: 5px 11px;
      font-size: 12px;
      cursor: pointer;
      font-weight: 500;
    }
    button.action-btn:hover {
      background: var(--vscode-button-hoverBackground);
    }
    .error-banner {
      background: var(--vscode-inputValidation-errorBackground, rgba(220, 38, 38, 0.14));
      border: 1px solid var(--vscode-inputValidation-errorBorder, #ef4444);
      color: var(--vscode-editor-foreground);
      padding: 8px 10px;
      border-radius: 4px;
      margin-bottom: 12px;
      white-space: pre-wrap;
      font-size: 12px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: auto;
    }
    th {
      text-align: left;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--vscode-descriptionForeground);
      padding: 7px 8px;
      border-bottom: 1px solid var(--vscode-panel-border, rgba(128, 128, 128, 0.35));
      white-space: nowrap;
    }
    th.num, td.num {
      text-align: right;
      font-variant-numeric: tabular-nums;
      white-space: nowrap;
    }
    td {
      padding: 7px 8px;
      border-bottom: 1px solid var(--vscode-panel-border, rgba(128, 128, 128, 0.18));
      vertical-align: top;
    }
    tr.pkt-row {
      cursor: pointer;
    }
    tr.pkt-row:hover {
      background: var(--vscode-list-hoverBackground, rgba(128, 128, 128, 0.1));
    }
    .mono {
      font-family: var(--vscode-editor-font-family, ui-monospace, monospace);
      font-size: 12px;
      white-space: nowrap;
    }
    .summary {
      font-family: var(--vscode-editor-font-family, ui-monospace, monospace);
      font-size: 12px;
      word-break: break-word;
    }
    .proto-badge {
      display: inline-block;
      padding: 1px 6px;
      border-radius: 3px;
      font-size: 11px;
      font-weight: 600;
      font-family: var(--vscode-editor-font-family, ui-monospace, monospace);
      background: var(--vscode-badge-background);
      color: var(--vscode-badge-foreground);
    }
    .hex-box {
      font-family: var(--vscode-editor-font-family, ui-monospace, monospace);
      font-size: 11.5px;
      line-height: 1.5;
      background: var(--vscode-textCodeBlock-background, rgba(128, 128, 128, 0.12));
      padding: 8px 10px;
      border-radius: 4px;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .empty {
      text-align: center;
      color: var(--vscode-descriptionForeground);
      padding: 24px 8px;
    }
  </style>
</head>
<body>
  <div class="toolbar">
    <div class="title-group">
      <div class="title">${escapeHtml(titleName)}</div>
      <div class="stats">${previews.length} frame${previews.length === 1 ? '' : 's'} &bull; ${totalBytes} bytes &bull; ${durationMs} ms span (click any row for hex dump)</div>
    </div>
    <div class="btn-group">
      <button class="action-btn" id="compile-btn" type="button">Compile to .pcap</button>
      ${downloadButtonHtml}
    </div>
  </div>
  ${errorHtml}
  <table>
    <thead>
      <tr>
        <th class="num">#</th>
        <th class="num">Time (ms)</th>
        <th>Source -&gt; Destination</th>
        <th>Proto</th>
        <th class="num">Bytes</th>
        <th>Summary</th>
      </tr>
    </thead>
    <tbody>
      ${rowsHtml}
      ${emptyHtml}
    </tbody>
  </table>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const compileBtn = document.getElementById('compile-btn');
    if (compileBtn) {
      compileBtn.addEventListener('click', () => {
        vscode.postMessage({ command: 'compile' });
      });
    }
    const downloadBtn = document.getElementById('download-btn');
    if (downloadBtn) {
      downloadBtn.addEventListener('click', () => {
        vscode.postMessage({ command: 'download' });
      });
    }
    window.addEventListener('message', (event) => {
      const msg = event.data;
      if (msg && msg.command === 'download' && msg.bytes) {
        const blob = new Blob([msg.bytes], { type: 'application/vnd.tcpdump.pcap' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = msg.filename || 'capture.pcap';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      }
    });
    document.querySelectorAll('tr.pkt-row').forEach((row) => {
      row.addEventListener('click', () => {
        const idx = row.getAttribute('data-idx');
        const hexRow = document.getElementById('hex-' + idx);
        if (hexRow) {
          hexRow.hidden = !hexRow.hidden;
        }
      });
    });
  </script>
</body>
</html>`;
}

/**
 * Activates the FrameAssembly Packet Studio extension.
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  const diagnosticCollection = vscode.languages.createDiagnosticCollection('frameassembly');
  context.subscriptions.push(diagnosticCollection);

  /** @type {Map<string, ReturnType<typeof setTimeout>>} */
  const debounceTimers = new Map();
  /** @type {vscode.WebviewPanel | null} */
  let ladderPanel = null;
  /** @type {vscode.TextDocument | null} */
  let ladderDocument = null;
  /** @type {Array<any>} */
  let lastValidPreviews = [];

  /**
   * Validates a `.frasm` document via WASM and publishes UTF-16 diagnostics.
   * @param {vscode.TextDocument} doc
   */
  async function validateDocumentNow(doc) {
    if (!doc || doc.languageId !== 'frameassembly') {
      return;
    }
    try {
      const wasm = await ensureWasm(context);
      const source = doc.getText();
      const validateFn = resolveValidateFn(wasm);
      const rawDiags = validateFn(source) || [];

      const vscDiags = rawDiags.map((d) => {
        const startPos = clampPosition(doc, d.start_line, d.start_col);
        let endPos = clampPosition(doc, d.end_line, d.end_col);
        if (endPos.isEqual(startPos)) {
          const lineLen = doc.lineAt(startPos.line).text.length;
          if (startPos.character < lineLen) {
            endPos = new vscode.Position(startPos.line, startPos.character + 1);
          }
        }
        const fullMessage = d.help ? `${d.message}\nHelp: ${d.help}` : String(d.message || 'Validation error');
        const diag = new vscode.Diagnostic(
          new vscode.Range(startPos, endPos),
          fullMessage,
          vscode.DiagnosticSeverity.Error
        );
        diag.source = 'FrameAssembly';
        return diag;
      });

      diagnosticCollection.set(doc.uri, vscDiags);
    } catch (_err) {
      // Never surface unhandled background rejections during live typing if WASM fails to load
    }
  }

  /**
   * Refreshes the open Packet Ladder Webview panel for `doc`, if open.
   * @param {vscode.TextDocument} doc
   */
  async function refreshLadderPanel(doc) {
    if (!ladderPanel || !doc || doc.languageId !== 'frameassembly') {
      return;
    }
    ladderDocument = doc;
    const titleName = doc.uri.path.split('/').pop() || 'Untitled.frasm';
    try {
      const wasm = await ensureWasm(context);
      const previews = resolveInspectFn(wasm)(doc.getText()) || [];
      lastValidPreviews = previews;
      ladderPanel.webview.html = renderPacketLadderHtml(titleName, previews, null, doc.uri.scheme !== 'file');
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      ladderPanel.webview.html = renderPacketLadderHtml(titleName, lastValidPreviews, msg, doc.uri.scheme !== 'file');
    }
  }

  /**
   * Schedules a 120ms debounced validation (and live ladder refresh if active) for `doc`.
   * @param {vscode.TextDocument} doc
   */
  function scheduleValidation(doc) {
    if (!doc || doc.languageId !== 'frameassembly') {
      return;
    }
    const key = doc.uri.toString();
    const prev = debounceTimers.get(key);
    if (prev) {
      clearTimeout(prev);
    }
    const handle = setTimeout(() => {
      debounceTimers.delete(key);
      validateDocumentNow(doc);
      if (ladderPanel && (!ladderDocument || ladderDocument.uri.toString() === key)) {
        refreshLadderPanel(doc);
      }
    }, 120);
    debounceTimers.set(key, handle);
  }

  // Validate all currently open `.frasm` documents on activation
  for (const doc of vscode.workspace.textDocuments) {
    if (doc.languageId === 'frameassembly') {
      validateDocumentNow(doc);
    }
  }

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      if (doc.languageId === 'frameassembly') {
        validateDocumentNow(doc);
      }
    }),
    vscode.workspace.onDidChangeTextDocument((event) => {
      if (event.document.languageId === 'frameassembly') {
        scheduleValidation(event.document);
      }
    }),
    vscode.workspace.onDidCloseTextDocument((doc) => {
      const key = doc.uri.toString();
      const timer = debounceTimers.get(key);
      if (timer) {
        clearTimeout(timer);
        debounceTimers.delete(key);
      }
      diagnosticCollection.delete(doc.uri);
    }),
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor && editor.document.languageId === 'frameassembly') {
        validateDocumentNow(editor.document);
        if (ladderPanel) {
          lastValidPreviews = [];
          refreshLadderPanel(editor.document);
        }
      }
    })
  );

  // Feature 1B: 1-Click Quick Fix CodeActionProvider for `replace 'X' with 'y'` diagnostics
  const quickFixProvider = {
    provideCodeActions(document, _range, actionContext) {
      /** @type {vscode.CodeAction[]} */
      const actions = [];
      const replacePattern = /replace '([^']+)' with '([^']+)'/;

      for (const diagnostic of actionContext.diagnostics) {
        const match = replacePattern.exec(diagnostic.message);
        if (!match) {
          continue;
        }
        const [, oldToken, newToken] = match;
        let targetRange = diagnostic.range;
        const currentSlice = document.getText(targetRange);

        if (currentSlice !== oldToken) {
          const lineText = document.lineAt(targetRange.start.line).text;
          const idx = lineText.indexOf(oldToken, Math.max(0, targetRange.start.character - 2));
          const fallbackIdx = idx >= 0 ? idx : lineText.indexOf(oldToken);
          if (fallbackIdx >= 0) {
            targetRange = new vscode.Range(
              new vscode.Position(targetRange.start.line, fallbackIdx),
              new vscode.Position(targetRange.start.line, fallbackIdx + oldToken.length)
            );
          }
        }

        const fix = new vscode.CodeAction(
          `Replace '${oldToken}' with '${newToken}'`,
          vscode.CodeActionKind.QuickFix
        );
        fix.edit = new vscode.WorkspaceEdit();
        fix.edit.replace(document.uri, targetRange, newToken);
        fix.diagnostics = [diagnostic];
        fix.isPreferred = true;
        actions.push(fix);
      }

      return actions;
    },
  };

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { language: 'frameassembly' },
      quickFixProvider,
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );

  // Feature 2: Protocol-Scoped Autocomplete (`CompletionItemProvider`) across all 81 protocols
  const completionProvider = {
    async provideCompletionItems(document, position) {
      const linePrefixRaw = document.lineAt(position.line).text.slice(0, position.character);
      const lineState = analyzeLineState(linePrefixRaw);
      if (lineState.inCommentAtEnd || lineState.inStringAtEnd) {
        return [];
      }

      const schema = await ensureProtocolSchema(context);
      const ctx = inspectDocumentSymbolsAndBlock(document, position);
      /** @type {vscode.CompletionItem[]} */
      const items = [];

      // 1. Top-level structural blocks (`host`, `flow`, `compile`)
      if (ctx.blockKind === 'top') {
        for (const kw of schema.structural) {
          const item = new vscode.CompletionItem(kw, vscode.CompletionItemKind.Keyword);
          item.detail = 'FrameAssembly block declaration';
          items.push(item);
        }
        return items;
      }

      // 2. Inside `host <id> { ... }` -> `ip`, `mac`
      if (ctx.blockKind === 'host') {
        for (const field of schema.hostFields) {
          const item = new vscode.CompletionItem(field, vscode.CompletionItemKind.Property);
          item.detail = field === 'ip' ? 'IPv4 or IPv6 host address' : 'Ethernet MAC address';
          items.push(item);
        }
        return items;
      }

      // 3. Inside `flow` or `compile`
      const lineCode = lineState.code;

      // Duration unit completion right after `wait <digits>`
      if (/\bwait\s+\d+[a-z]*$/.test(lineCode)) {
        for (const unit of schema.timeUnits) {
          const item = new vscode.CompletionItem(unit, vscode.CompletionItemKind.Unit);
          item.detail = 'FrameAssembly wait duration unit';
          items.push(item);
        }
        return items;
      }

      const arrowMatch = /^(.*?)(->|<-)(.*)$/.exec(lineCode);
      const endpointPool =
        ctx.blockKind === 'flow' && ctx.activeFlowParams.length > 0
          ? Array.from(new Set([...ctx.activeFlowParams, ...ctx.hostNames]))
          : ctx.hostNames;

      // Before `->` or `<-`: suggest endpoints (and flow invocations inside `compile`)
      if (!arrowMatch) {
        if (ctx.blockKind === 'compile') {
          for (const [flowName, params] of ctx.flowDefs.entries()) {
            const item = new vscode.CompletionItem(flowName, vscode.CompletionItemKind.Function);
            item.detail = `flow ${flowName}(${params.join(', ')})`;
            const snippetArgs = params.map((p, i) => `\${${i + 1}:${p}}`).join(', ');
            item.insertText = new vscode.SnippetString(`${flowName}(${snippetArgs})`);
            item.sortText = `0_${flowName}`;
            items.push(item);
          }
        }
        for (const ep of endpointPool) {
          const item = new vscode.CompletionItem(ep, vscode.CompletionItemKind.Variable);
          item.detail = 'Declared endpoint identifier';
          item.sortText = `1_${ep}`;
          items.push(item);
        }
        return items;
      }

      // Immediately after `->` or `<-` (typing the peer endpoint)
      const afterArrow = arrowMatch[3];
      if (/^\s*[A-Za-z0-9_-]*$/.test(afterArrow)) {
        for (const ep of endpointPool) {
          const item = new vscode.CompletionItem(ep, vscode.CompletionItemKind.Variable);
          item.detail = 'Target endpoint identifier';
          items.push(item);
        }
        return items;
      }

      // Past `<src> -> <dst> `: inspect completed words after target endpoint
      const cleanAfterArrow = afterArrow.replace(/"(?:\\.|[^"\\])*"/g, '""');
      const endsWithSpace = /\s$/.test(cleanAfterArrow);
      const rawTokens = cleanAfterArrow.trim().split(/\s+/).filter(Boolean);
      // rawTokens[0] is `<dst>`; drop trailing token if cursor is still mid-word
      const completedWords = (endsWithSpace ? rawTokens.slice(1) : rawTokens.slice(1, -1)).map((w) =>
        w.toLowerCase()
      );

      const allProtocols = Object.keys(schema.protocols);
      const protocolSet = new Set(allProtocols);
      const l2TagProtos = new Set(['vlan', 'qinq', 'mpls']);

      let activeProtocol = null;
      let activeTagProto = null;
      for (const word of completedWords) {
        if (protocolSet.has(word)) {
          if (l2TagProtos.has(word)) {
            activeTagProto = word;
          } else {
            activeProtocol = word;
            break;
          }
        }
      }

      /** @type {Set<string>} */
      const seen = new Set();

      if (activeProtocol) {
        const protoMods = schema.protocols[activeProtocol] || [];
        for (const mod of protoMods) {
          if (seen.has(mod)) continue;
          seen.add(mod);
          const item = new vscode.CompletionItem(mod, vscode.CompletionItemKind.Field);
          item.detail = `${activeProtocol} modifier`;
          item.sortText = `0_${mod}`;
          items.push(item);
        }
        for (const umod of schema.universalModifiers) {
          if (seen.has(umod)) continue;
          seen.add(umod);
          const item = new vscode.CompletionItem(umod, vscode.CompletionItemKind.Property);
          item.detail = 'Cross-layer frame modifier';
          item.sortText = `1_${umod}`;
          items.push(item);
        }
      } else {
        // No inner protocol chosen yet: suggest all 81 protocols + L2 tag/universal modifiers
        for (const proto of allProtocols) {
          seen.add(proto);
          const item = new vscode.CompletionItem(proto, vscode.CompletionItemKind.Class);
          item.detail = 'FrameAssembly protocol';
          item.sortText = `0_${proto}`;
          items.push(item);
        }
        if (activeTagProto && schema.protocols[activeTagProto]) {
          for (const tmod of schema.protocols[activeTagProto]) {
            if (seen.has(tmod)) continue;
            seen.add(tmod);
            const item = new vscode.CompletionItem(tmod, vscode.CompletionItemKind.Field);
            item.detail = `${activeTagProto} modifier`;
            item.sortText = `0_${tmod}`;
            items.push(item);
          }
        }
        for (const umod of schema.universalModifiers) {
          if (seen.has(umod)) continue;
          seen.add(umod);
          const item = new vscode.CompletionItem(umod, vscode.CompletionItemKind.Property);
          item.detail = 'Cross-layer frame modifier';
          item.sortText = `1_${umod}`;
          items.push(item);
        }
      }

      return items;
    },
  };

  context.subscriptions.push(
    vscode.languages.registerCompletionItemProvider(
      { language: 'frameassembly' },
      completionProvider,
      ' ',
      '>',
      '-'
    )
  );

  /**
   * Compiles `doc` in memory and hands the `.pcap` bytes to the ladder Webview, which saves them
   * through a browser download. Used on `vscode.dev` / `github.dev` where no `file:` URI exists.
   * @param {vscode.TextDocument} doc
   */
  async function downloadCompiledPcap(doc) {
    try {
      if (!ladderPanel) {
        return;
      }
      const wasm = await ensureWasm(context);
      const source = doc.getText();
      const diags = resolveValidateFn(wasm)(source) || [];
      if (diags.length > 0) {
        const first = diags[0];
        vscode.window.showErrorMessage(
          `FrameAssembly compile failed (line ${first.start_line + 1}): ${first.message}`
        );
        return;
      }
      const pcapBytes = resolveCompileFn(wasm)(source);
      const stem = (doc.uri.path.split('/').pop() || 'capture').replace(/\.[^./]*$/, '') || 'capture';
      await ladderPanel.webview.postMessage({
        command: 'download',
        filename: `${stem}.pcap`,
        bytes: pcapBytes,
      });
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      vscode.window.showErrorMessage(`FrameAssembly download failed: ${msg}`);
    }
  }

  // Feature 3A: `frameassembly.compileToPcap` command
  const compileCmd = vscode.commands.registerCommand('frameassembly.compileToPcap', async (resourceUri) => {
    try {
      let doc = null;
      if (resourceUri instanceof vscode.Uri) {
        doc = await vscode.workspace.openTextDocument(resourceUri);
      } else if (vscode.window.activeTextEditor && vscode.window.activeTextEditor.document.languageId === 'frameassembly') {
        doc = vscode.window.activeTextEditor.document;
      } else if (ladderDocument) {
        doc = ladderDocument;
      }

      if (!doc) {
        vscode.window.showWarningMessage('Open a .frasm file first to compile it into a packet capture.');
        return;
      }

      const wasm = await ensureWasm(context);
      const source = doc.getText();
      const validateFn = resolveValidateFn(wasm);
      const diags = validateFn(source) || [];
      if (diags.length > 0) {
        await validateDocumentNow(doc);
        const first = diags[0];
        vscode.window.showErrorMessage(
          `FrameAssembly compile failed (line ${first.start_line + 1}): ${first.message}`
        );
        return;
      }

      const pcapBytes = resolveCompileFn(wasm)(source);
      let outUri;
      if (doc.isUntitled) {
        outUri = await vscode.window.showSaveDialog({
          defaultUri: vscode.Uri.file('capture.pcap'),
          filters: { 'Packet Capture': ['pcap', 'pcapng'] },
        });
        if (!outUri) {
          return;
        }
      } else {
        outUri = replaceUriExtension(doc.uri, '.pcap');
      }

      await vscode.workspace.fs.writeFile(outUri, pcapBytes);
      const previews = resolveInspectFn(wasm)(source) || [];
      const outName = outUri.path.split('/').pop() || outUri.toString();
      const openLabel = 'Open Capture';
      const revealLabel = 'Reveal in Explorer';
      const choice = await vscode.window.showInformationMessage(
        `Compiled ${previews.length} frame${previews.length === 1 ? '' : 's'} (${pcapBytes.byteLength} bytes) -> ${outName}`,
        openLabel,
        revealLabel
      );
      if (choice === openLabel) {
        await vscode.env.openExternal(outUri);
      } else if (choice === revealLabel) {
        await vscode.commands.executeCommand('revealFileInOS', outUri);
      }
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      vscode.window.showErrorMessage(`FrameAssembly compilation error: ${msg}`);
    }
  });

  // Feature 3B: `frameassembly.showPacketLadder` live Webview preview
  const showLadderCmd = vscode.commands.registerCommand('frameassembly.showPacketLadder', async () => {
    const editor = vscode.window.activeTextEditor;
    const doc =
      editor && editor.document.languageId === 'frameassembly' ? editor.document : ladderDocument;

    if (!doc) {
      vscode.window.showWarningMessage('Open a .frasm file to launch the Live Packet Ladder preview.');
      return;
    }

    ladderDocument = doc;
    if (ladderPanel) {
      ladderPanel.reveal(vscode.ViewColumn.Beside, true);
    } else {
      ladderPanel = vscode.window.createWebviewPanel(
        'frameassemblyPacketLadder',
        'FrameAssembly Packet Ladder',
        { viewColumn: vscode.ViewColumn.Beside, preserveFocus: true },
        { enableScripts: true, retainContextWhenHidden: true }
      );
      ladderPanel.onDidDispose(() => {
        ladderPanel = null;
      });
      ladderPanel.webview.onDidReceiveMessage((msg) => {
        if (msg && msg.command === 'compile' && ladderDocument) {
          vscode.commands.executeCommand('frameassembly.compileToPcap', ladderDocument.uri);
        } else if (msg && msg.command === 'download' && ladderDocument) {
          downloadCompiledPcap(ladderDocument);
        }
      });
    }

    lastValidPreviews = [];
    await refreshLadderPanel(doc);
  });

  // Feature 4: `frameassembly.reversePcap` Explorer right-click `.pcap` / `.pcapng` -> `.frasm`
  const reverseCmd = vscode.commands.registerCommand('frameassembly.reversePcap', async (resourceUri) => {
    try {
      let targetUri = resourceUri instanceof vscode.Uri ? resourceUri : null;
      if (!targetUri) {
        const picked = await vscode.window.showOpenDialog({
          canSelectMany: false,
          openLabel: 'Reverse Capture to .frasm',
          filters: { 'Packet Captures (.pcap, .pcapng)': ['pcap', 'pcapng'] },
        });
        if (!picked || picked.length === 0) {
          return;
        }
        targetUri = picked[0];
      }

      const wasm = await ensureWasm(context);
      const pcapBytes = await vscode.workspace.fs.readFile(targetUri);
      const reverseFn = wasm.reverse_pcap || wasm.reversePcap;
      const res = reverseFn(pcapBytes);

      const outUri = replaceUriExtension(targetUri, '.frasm');
      const encoded = new TextEncoder().encode(res.frasm || res.fasm);
      await vscode.workspace.fs.writeFile(outUri, encoded);

      const openedDoc = await vscode.workspace.openTextDocument(outUri);
      await vscode.window.showTextDocument(openedDoc, { preview: false });

      const inName = targetUri.path.split('/').pop() || 'capture.pcap';
      const outName = outUri.path.split('/').pop() || 'capture.frasm';
      vscode.window.showInformationMessage(
        `Reversed ${inName} -> ${outName} (${res.packetCount} packet${res.packetCount === 1 ? '' : 's'}, ${res.hostCount} host${res.hostCount === 1 ? '' : 's'})`
      );
    } catch (err) {
      const msg =
        err && typeof err === 'object' && err.message
          ? err.message
          : err && typeof err === 'object' && err.error
            ? err.error
            : String(err);
      vscode.window.showErrorMessage(`FrameAssembly reverse capture failed: ${msg}`);
    }
  });

  // Getting Started walkthrough launcher (also shown once on first activation)
  const walkthroughId = 'SteveWinschel.frameassembly-vscode#frameassembly.gettingStarted';
  const walkthroughCmd = vscode.commands.registerCommand('frameassembly.openWalkthrough', () =>
    vscode.commands.executeCommand('workbench.action.openWalkthrough', walkthroughId, false)
  );

  context.subscriptions.push(compileCmd, showLadderCmd, reverseCmd, walkthroughCmd);

  if (!context.globalState.get('frameassembly.walkthroughShown.v3')) {
    context.globalState.update('frameassembly.walkthroughShown.v3', true);
    vscode.commands.executeCommand('frameassembly.openWalkthrough');
  }
}

/**
 * Cleanly deactivates the FrameAssembly extension.
 */
function deactivate() {
  wasmApi = null;
  wasmInitPromise = null;
}

module.exports = {
  activate,
  deactivate,
};
