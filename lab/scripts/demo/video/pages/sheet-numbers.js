// Numbering and flow marks on the lab map, matching the map artifact: tiles 5.1, 5.2 ... and orange chevrons between stations.
(function () {
  const lab = window.__lab; if (!lab) return;
  const svg = lab.svg, NS = 'http://www.w3.org/2000/svg';
  const mk = (t, a, p) => { const e = document.createElementNS(NS, t); for (const q in a) e.setAttribute(q, a[q]); p.appendChild(e); return e; };
  const num = {}; lab.L.st.forEach((s) => s.nodes.forEach((nd, j) => { num[nd.id] = `${s.i + 5}.${j + 1}`; }));
  svg.querySelectorAll('g.node[data-go^="tile:"]').forEach((g) => {
    const id = g.getAttribute('data-go').slice(5), nd = lab.NB[id]; if (!nd) return;
    const bg = mk('g', { class: 'tnum', transform: `translate(${-nd.size / 2 + 4},${-nd.size / 2 + 4})`, 'pointer-events': 'none' }, g);
    const label = num[id] || '', w = label.length * 11 + 14;
    mk('rect', { x: -w / 2, y: -13, width: w, height: 26, rx: 13, fill: '#16161A', stroke: '#FFFFFF', 'stroke-width': 3 }, bg);
    mk('text', { x: 0, y: 5, 'text-anchor': 'middle', 'font-size': 15, 'font-weight': 800, fill: '#FFFFFF', 'font-family': 'system-ui, -apple-system, sans-serif' }, bg).textContent = label;
  });
  const stX = lab.L.st.map((s) => s.x), gFlow = mk('g', { id: 'g-flow' }, svg);
  for (let i = 0; i < stX.length - 1; i++) { const x = (stX[i] + stX[i + 1]) / 2; mk('path', { d: `M${x - 14} -16L${x + 10} 0L${x - 14} 16`, fill: 'none', stroke: '#E8703A', 'stroke-width': 7, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, gFlow); }
})();
