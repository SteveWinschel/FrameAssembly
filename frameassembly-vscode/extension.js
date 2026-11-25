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

const IDENT_BOUNDARY_RE = /[A-Za-z0-9_-]/;
const TIME_UNITS = new Set(['ns', 'us', 'ms', 's', 'm']);

/**
 * Formats an error value into a concise string for the Output channel.
 * @param {unknown} err
 * @returns {string}
 */
function formatError(err) {
  if (!err) return 'Unknown error';
  if (err instanceof Error) return err.stack || err.message || String(err);
  if (typeof err === 'object' && err !== null && 'message' in err) {
    return String(err.message);
  }
  return String(err);
}

/**
 * Lazily loads `./wasm/frameassembly_wasm.js` + `frameassembly_wasm_bg.wasm` via `vscode.workspace.fs.readFile`.
 * @param {vscode.ExtensionContext} context
 * @param {vscode.OutputChannel} [outputChannel]
 * @returns {Promise<any>}
 */
async function ensureWasm(context, outputChannel) {
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
      } catch (importErr) {
        if (outputChannel) {
          outputChannel.appendLine(
            `[FrameAssembly] Direct WASM JS import failed (${jsUri.toString(true)}), falling back to Blob URL: ${formatError(importErr)}`
          );
        }
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
    if (outputChannel) {
      outputChannel.appendLine(
        `[FrameAssembly] Failed to initialize WebAssembly validator: ${formatError(err)}`
      );
    }
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
  const lineCount = Math.max(0, Number(document && document.lineCount) || 0);
  if (lineCount === 0) {
    return new vscode.Position(0, 0);
  }
  const rawLine = Number.isFinite(line) ? Math.trunc(line) : 0;
  const safeLine = Math.min(Math.max(0, rawLine), lineCount - 1);
  const lineText = document.lineAt(safeLine).text || '';
  const rawCol = Number.isFinite(col) ? Math.trunc(col) : 0;
  const safeCol = Math.min(Math.max(0, rawCol), lineText.length);
  return new vscode.Position(safeLine, safeCol);
}

/**
 * Clamps a raw WASM diagnostic span into a valid `vscode.Range`, safely handling EOF offsets
 * on empty trailing lines and highlighting the final character when zero-width at non-empty EOF.
 * @param {vscode.TextDocument} document
 * @param {{ start_line: number, start_col: number, end_line: number, end_col: number }} diag
 * @returns {vscode.Range}
 */
function clampDiagnosticRange(document, diag) {
  let startPos = clampPosition(document, diag && diag.start_line, diag && diag.start_col);
  let endPos = clampPosition(document, diag && diag.end_line, diag && diag.end_col);

  const isBefore =
    typeof endPos.isBefore === 'function'
      ? endPos.isBefore(startPos)
      : endPos.line < startPos.line ||
        (endPos.line === startPos.line && endPos.character < startPos.character);
  if (isBefore) {
    endPos = startPos;
  }

  const isEqual =
    typeof endPos.isEqual === 'function'
      ? endPos.isEqual(startPos)
      : endPos.line === startPos.line && endPos.character === startPos.character;

  if (isEqual && document && document.lineCount > 0) {
    const lineText = document.lineAt(startPos.line).text || '';
    if (startPos.character < lineText.length) {
      endPos = new vscode.Position(startPos.line, startPos.character + 1);
    } else if (lineText.length > 0) {
      const lastCode = lineText.charCodeAt(lineText.length - 1);
      const prevCode = lineText.length >= 2 ? lineText.charCodeAt(lineText.length - 2) : 0;
      const step =
        lastCode >= 0xdc00 && lastCode <= 0xdfff && prevCode >= 0xd800 && prevCode <= 0xdbff
          ? 2
          : 1;
      startPos = new vscode.Position(startPos.line, lineText.length - step);
      endPos = new vscode.Position(startPos.line, lineText.length);
    }
  }

  return new vscode.Range(startPos, endPos);
}

/**
 * Checks whether `oldToken` at `col` inside `lineText` sits on safe word/token boundaries so
 * Quick Fixes never clip longer identifiers or hyphenated host names (`host-01`, `my_host`, `sync`).
 * @param {string} lineText
 * @param {number} col
 * @param {string} oldToken
 * @param {string} newToken
 * @returns {boolean}
 */
function isBoundedTokenMatch(lineText, col, oldToken, newToken) {
  if (!oldToken || col < 0 || col + oldToken.length > lineText.length) {
    return false;
  }
  if (lineText.slice(col, col + oldToken.length) !== oldToken) {
    return false;
  }

  const prev = col > 0 ? lineText[col - 1] : '';
  const next = col + oldToken.length < lineText.length ? lineText[col + oldToken.length] : '';

  if (/[A-Za-z0-9_]/.test(oldToken)) {
    if (next && IDENT_BOUNDARY_RE.test(next)) {
      return false;
    }
    if (prev && IDENT_BOUNDARY_RE.test(prev)) {
      if (TIME_UNITS.has(newToken) && /^[0-9]$/.test(prev)) {
        let digitIdx = col - 1;
        while (digitIdx > 0 && /^[0-9]$/.test(lineText[digitIdx - 1])) {
          digitIdx--;
        }
        const beforeDigits = digitIdx > 0 ? lineText[digitIdx - 1] : '';
        return !beforeDigits || !/[A-Za-z_-]/.test(beforeDigits);
      }
      return false;
    }
    return true;
  }

  if (oldToken.startsWith('-') && prev === '-') return false;
  if (oldToken.endsWith('-') && next === '-') return false;
  if (oldToken.endsWith('>') && next === '>') return false;
  if (oldToken.startsWith('<') && prev === '<') return false;
  return true;
}

/**
 * Resolves a verified, word-boundary-safe single-line replacement `Range` for `oldToken`,
 * returning `null` if no bounded occurrence exists on the diagnostic line.
 * @param {vscode.TextDocument} document
 * @param {vscode.Range} diagRange
 * @param {string} oldToken
 * @param {string} newToken
 * @returns {vscode.Range | null}
 */
function findSafeReplacementRange(document, diagRange, oldToken, newToken) {
  if (
    !diagRange ||
    !oldToken ||
    diagRange.start.line < 0 ||
    diagRange.start.line >= document.lineCount
  ) {
    return null;
  }

  const targetLine = diagRange.start.line;
  const spansSameOrTrailingNewline =
    diagRange.end.line === targetLine ||
    (diagRange.end.line === targetLine + 1 && diagRange.end.character === 0);
  if (!spansSameOrTrailingNewline) {
    return null;
  }

  const lineText = document.lineAt(targetLine).text || '';
  if (
    diagRange.end.line === targetLine &&
    diagRange.end.character - diagRange.start.character === oldToken.length &&
    isBoundedTokenMatch(lineText, diagRange.start.character, oldToken, newToken)
  ) {
    return diagRange;
  }

  let bestCol = -1;
  let bestDist = Infinity;
  let searchFrom = 0;
  while (searchFrom <= lineText.length - oldToken.length) {
    const idx = lineText.indexOf(oldToken, searchFrom);
    if (idx < 0) break;
    if (isBoundedTokenMatch(lineText, idx, oldToken, newToken)) {
      const dist = Math.abs(idx - diagRange.start.character);
      if (dist < bestDist) {
        bestDist = dist;
        bestCol = idx;
      }
    }
    searchFrom = idx + 1;
  }

  if (bestCol < 0) {
    return null;
  }

  return new vscode.Range(
    new vscode.Position(targetLine, bestCol),
    new vscode.Position(targetLine, bestCol + oldToken.length)
  );
}

/**
 * Activates live read-only `.frasm` linting and 1-click keyword typo quick fixes.
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  const diagnostics = vscode.languages.createDiagnosticCollection('frameassembly');
  const outputChannel = vscode.window.createOutputChannel('FrameAssembly');
  context.subscriptions.push(diagnostics, outputChannel);
  /** @type {Map<string, ReturnType<typeof setTimeout>>} */
  const debounceTimers = new Map();

  /**
   * Validates `doc` via WASM and updates its UTF-16 `DiagnosticCollection` entries.
   * @param {vscode.TextDocument} doc
   */
  async function validateDocumentNow(doc) {
    if (!doc || doc.languageId !== 'frameassembly') return;
    try {
      const wasm = await ensureWasm(context, outputChannel);
      const validateFn =
        wasm && (wasm.validateFrasm || wasm.validate_frasm || wasm.validateFasm || wasm.validate_fasm);
      if (typeof validateFn !== 'function') {
        throw new Error('FrameAssembly WASM module does not export validateFrasm');
      }
      const rawDiags = validateFn(doc.getText()) || [];
      const vscDiags = rawDiags.map((d) => {
        const range = clampDiagnosticRange(doc, d);
        const message = d.help ? `${d.message}\nHelp: ${d.help}` : String(d.message || 'Validation error');
        const diag = new vscode.Diagnostic(range, message, vscode.DiagnosticSeverity.Error);
        diag.source = 'FrameAssembly';
        return diag;
      });
      diagnostics.set(doc.uri, vscDiags);
    } catch (err) {
      outputChannel.appendLine(
        `[FrameAssembly] Validation error for ${doc.uri ? doc.uri.toString() : '<unknown>'}: ${formatError(err)}`
      );
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
            if (diagnostic.source !== 'FrameAssembly') continue;
            const match = replaceRe.exec(diagnostic.message);
            if (!match) continue;
            const [, oldToken, newToken] = match;
            const range = findSafeReplacementRange(document, diagnostic.range, oldToken, newToken);
            if (!range) continue;
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
