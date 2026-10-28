/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
'use strict';

const darkTheme = {
  background: '#101c2b', foreground: '#e3ebf5', cursor: '#b5e4ff',
  selectionBackground: '#325b75',
  black: '#223149', red: '#fb7185', green: '#4ade80', yellow: '#facc15',
  blue: '#60a5fa', magenta: '#c084fc', cyan: '#22d3ee', white: '#cbd5e1',
  brightBlack: '#64748b', brightRed: '#fda4af', brightGreen: '#86efac',
  brightYellow: '#fde047', brightBlue: '#93c5fd', brightMagenta: '#d8b4fe',
  brightCyan: '#67e8f9', brightWhite: '#ffffff'
};
const lightTheme = {
  background: '#f5f8fc', foreground: '#142642', cursor: '#2559a8',
  selectionBackground: '#cfe1f7',
  black: '#1b2b40', red: '#b42332', green: '#147d3f', yellow: '#916300',
  blue: '#2358ad', magenta: '#9a3aae', cyan: '#006f7b', white: '#516071',
  brightBlack: '#63758a', brightRed: '#dc2626', brightGreen: '#16813f',
  brightYellow: '#a56b00', brightBlue: '#2d6cdf', brightMagenta: '#b14cb2',
  brightCyan: '#008999', brightWhite: '#142642'
};

const terminal = new Terminal({
  cols: 80,
  rows: 24,
  scrollback: 2000,
  cursorBlink: true,
  fontSize: 15,
  fontFamily: 'monospace',
  theme: matchMedia('(prefers-color-scheme: dark)').matches ? darkTheme : lightTheme
});
const fit = new FitAddon.FitAddon();
terminal.loadAddon(fit);
terminal.open(document.getElementById('terminal'));

let lastColumns = 0;
let lastRows = 0;
function fitAndReport() {
  fit.fit();
  if (terminal.cols !== lastColumns || terminal.rows !== lastRows) {
    lastColumns = terminal.cols;
    lastRows = terminal.rows;
    AndroidTerminal.resize(lastColumns, lastRows);
  }
}

terminal.onData(data => AndroidTerminal.input(data));
if (typeof ResizeObserver !== 'undefined') {
  new ResizeObserver(() => requestAnimationFrame(fitAndReport)).observe(document.getElementById('terminal'));
} else {
  window.setInterval(fitAndReport, 500);
}
if (window.visualViewport) window.visualViewport.addEventListener('resize', () => requestAnimationFrame(fitAndReport));
window.addEventListener('resize', () => requestAnimationFrame(fitAndReport));

window.sovaWrite = data => terminal.write(data, () => AndroidTerminal.drained());
window.sovaPaste = data => terminal.paste(data);
window.sovaFocus = () => terminal.focus();

requestAnimationFrame(() => {
  fitAndReport();
  AndroidTerminal.ready(terminal.cols, terminal.rows);
});
