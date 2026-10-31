// Sheet mode controls: Details (expand the compact panel) and Hide (give the map the whole sheet).
(function () {
  const p = document.getElementById('panel'); if (!p) return;
  const bar = document.createElement('div'); bar.id = 'sheetbtn';
  bar.innerHTML = '<button type="button" id="sbd">Details</button><button type="button" id="sbh">Hide</button>';
  p.prepend(bar); const sh = document.createElement('button'); sh.type = 'button'; sh.id = 'sheetshow'; sh.textContent = 'Show panel'; p.insertAdjacentElement('afterend', sh);
  const d = bar.querySelector('#sbd'), h = bar.querySelector('#sbh');
  const sync = () => { d.textContent = p.classList.contains('full') ? 'Less' : 'Details'; };
  d.addEventListener('click', () => { p.classList.toggle('full'); sync(); });
  h.addEventListener('click', () => { p.classList.add('off'); p.classList.remove('full'); sync(); });
  sh.addEventListener('click', () => { p.classList.remove('off'); sync(); });
  window.sheet = { full: (v) => { p.classList.toggle('full', !!v); sync(); }, panel: (v) => { p.classList.toggle('off', !v); sync(); } };
  sync();
})();
