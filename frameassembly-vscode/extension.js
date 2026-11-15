/**
 * @file FrameAssembly (.frasm) live WebAssembly linter and 1-click typo quick-fix extension for VS Code.
 * Runs read-only in memory across Desktop and Browser Web Extension Hosts (`vscode.dev`, Restricted Mode).
 */
'use strict';

const vscode = require('vscode');

/** @type {Promise<any> | null} */
let wasmInitPromise = null;
/** @type {any | null} */
let wasmApi = null;

/**
 * Lazily loads `./wasm/frameassembly_wasm.js` + `frameassembly_wasm_bg.wasm` via `vscode.workspace.fs.readFile`.
 * @param {vscode.ExtensionContext} context
 * @returns {Promise<any>}
 */
async function ensureWasm(context) {
  if (wasmApi) return wasmApi;
  if (wasmInitPromise) return wasmInitPromise;

  wasmInitPromise = (async () => {
    const jsUri = vscode.Uri.joinPath(context.extensionUri, 'wasm', 'frameassembly_wasm.js');
    const wasmUri = vscode.Uri.joinPath(context.extensionUri, 'wasm', 'frameassembly_wasm_bg.wasm');
    let mod;
    if (jsUri.scheme === 'file') {
      const { pathToFileURL } = require('url');
      mod = await import(pathToFileURL(jsUri.fsPath).href);
    } else {
      try {
        mod = await import(jsUri.toString(true));
      } catch (_err) {
        const jsSource = new TextDecoder('utf-8').decode(await vscode.workspace.fs.readFile(jsUri));
        const blobUrl = URL.createObjectURL(new Blob([jsSource], { type: 'text/javascript' }));
        try {
          mod = await import(blobUrl);
        } finally {
          URL.revokeObjectURL(blobUrl);
        }
      }
    }
    const wasmBytes = await vscode.workspace.fs.readFile(wasmUri);
    if (typeof mod.initSync === 'function') {
      mod.initSync({ module: wasmBytes });
    } else if (typeof mod.default === 'function') {
      await mod.default({ module_or_path: wasmBytes });
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
 * Clamps a zero-based UTF-16 `(line, col)` pair into valid bounds for `document`.
 * @param {vscode.TextDocument} document
 * @param {number} line
 * @param {number} col
 * @returns {vscode.Position}
 */
function clampPosition(document, line, col) {
  const safeLine = Math.min(Math.max(0, line | 0), Math.max(0, document.lineCount - 1));
  const safeCol = Math.min(Math.max(0, col | 0), document.lineAt(safeLine).text.length);
  return new vscode.Position(safeLine, safeCol);
}

/**
 * Activates live read-only `.frasm` linting and 1-click keyword typo quick fixes.
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  const diagnostics = vscode.languages.createDiagnosticCollection('frameassembly');
  context.subscriptions.push(diagnostics);
  /** @type {Map<string, ReturnType<typeof setTimeout>>} */
  const debounceTimers = new Map();

  /**
   * Validates `doc` via WASM and updates its UTF-16 `DiagnosticCollection` entries.
   * @param {vscode.TextDocument} doc
   */
  async function validateDocumentNow(doc) {
    if (!doc || doc.languageId !== 'frameassembly') return;
    try {
      const wasm = await ensureWasm(context);
      const validateFn = wasm.validateFrasm || wasm.validate_frasm || wasm.validateFasm || wasm.validate_fasm;
      const rawDiags = validateFn(doc.getText()) || [];
      const vscDiags = rawDiags.map((d) => {
        const startPos = clampPosition(doc, d.start_line, d.start_col);
        let endPos = clampPosition(doc, d.end_line, d.end_col);
        if (endPos.isEqual(startPos) && startPos.character < doc.lineAt(startPos.line).text.length) {
          endPos = new vscode.Position(startPos.line, startPos.character + 1);
        }
        const message = d.help ? `${d.message}\nHelp: ${d.help}` : String(d.message || 'Validation error');
        const diag = new vscode.Diagnostic(new vscode.Range(startPos, endPos), message, vscode.DiagnosticSeverity.Error);
        diag.source = 'FrameAssembly';
        return diag;
      });
      diagnostics.set(doc.uri, vscDiags);
    } catch (_err) {
      // Ignore transient WASM load failures while typing
    }
  }

  /**
   * Schedules a 120ms debounced validation pass for `doc`.
   * @param {vscode.TextDocument} doc
   */
  function scheduleValidation(doc) {
    if (!doc || doc.languageId !== 'frameassembly') return;
    const key = doc.uri.toString();
    const prev = debounceTimers.get(key);
    if (prev) clearTimeout(prev);
    debounceTimers.set(key, setTimeout(() => { debounceTimers.delete(key); validateDocumentNow(doc); }, 120));
  }

  for (const doc of vscode.workspace.textDocuments) validateDocumentNow(doc);

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(validateDocumentNow),
    vscode.workspace.onDidChangeTextDocument((e) => scheduleValidation(e.document)),
    vscode.workspace.onDidCloseTextDocument((doc) => {
      const key = doc.uri.toString();
      const timer = debounceTimers.get(key);
      if (timer) { clearTimeout(timer); debounceTimers.delete(key); }
      diagnostics.delete(doc.uri);
    }),
    { dispose() { for (const t of debounceTimers.values()) clearTimeout(t); debounceTimers.clear(); } }
  );

  const replaceRe = /replace '([^']+)' with '([^']+)'/;
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { language: 'frameassembly' },
      {
        provideCodeActions(document, _range, actionContext) {
          const actions = [];
          for (const diagnostic of actionContext.diagnostics) {
            const match = replaceRe.exec(diagnostic.message);
            if (!match) continue;
            const [, oldToken, newToken] = match;
            let range = diagnostic.range;
            if (document.getText(range) !== oldToken) {
              const lineText = document.lineAt(range.start.line).text;
              const idx = lineText.indexOf(oldToken, Math.max(0, range.start.character - 2));
              const col = idx >= 0 ? idx : lineText.indexOf(oldToken);
              if (col >= 0) {
                range = new vscode.Range(new vscode.Position(range.start.line, col), new vscode.Position(range.start.line, col + oldToken.length));
              }
            }
            const fix = new vscode.CodeAction(`Replace '${oldToken}' with '${newToken}'`, vscode.CodeActionKind.QuickFix);
            fix.edit = new vscode.WorkspaceEdit();
            fix.edit.replace(document.uri, range, newToken);
            fix.diagnostics = [diagnostic];
            fix.isPreferred = true;
            actions.push(fix);
          }
          return actions;
        },
      },
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );
}

/**
 * Releases cached WASM handles when the extension deactivates.
 */
function deactivate() {
  wasmApi = null;
  wasmInitPromise = null;
}

module.exports = { activate, deactivate };
