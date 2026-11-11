# lab-map.html: links on the map

(Not in this public copy: `lab-map.html` and `v24.html` are over 1 MB each; see `demo/README.md`.)

`lab-map.html` is the Contoso Lab Map Alt with the
Lab Guide's 21 stops built in. Each stop's card shows the stop's say line and compact buttons:
**Open** (the real console or page, from `goto` in `readiness/lab-guide/stops.json`) and **Code**
(the file on GitHub, from `code`). Links open in a new tab (`target=_blank rel=noopener`).

Numbering: `data-stop` is the **guide's** stop number (1-21), not the map's own numbers.
Guide 1-5 = map setup 1-5; guide 6 = map tile 6.1 (HR); guide 7-15 = map lab 6-14;
guide 16-20 = map tiles KV, ADTIER, ADFS, OKTAMIG, SSM; guide 21 = map 15 (Delivery).

## Hooks

Bubbles (what you click to open a card):

| Selector | What |
|---|---|
| `[data-stop="N"][data-bubble="station"]` | the stop on the map (setup pill, lab station, delivery band) |
| `[data-stop="N"][data-bubble="tile"]` | stops that are a tile (6, 16-20) |
| `[data-stop="N"][data-bubble="chip"]` | the chip bar at the top (stops 1-5, 7-15, 21) |
| `[data-stop="N"][data-bubble="label"]` | the station labels shown when zoomed far out |
| `[data-stop="N"][data-bubble="board"]` | the cards on the overview board (shown at Fit) |
| `[data-stop-also="N"]` | other spots that open the same stop (the guide's `mapAlso`) |

Every bubble also has `data-spot` = its map target (`setup:3`, `lab:6`, `tile:HR`, `delivery`, `setup:4.1`).

Links (inside the open card, `#panel`):

`a[data-stop="N"][data-link="<slug>"]`, with `data-kind="open"` or `"code"`. The slug is the link's label in
lower case with dashes, e.g. stop 7: `hr-feed-workflow-runs`, `hr-front-door-entra`, `hr-spreadsheet`,
`hr-feed-workflow`, `sends-hr-rows-to-entra`. The card itself is `.glide[data-card="N"]`.

## From the cockpit

```js
await page.evaluate(() => window.__mapLinks.open(7));           // same as clicking stop 7's bubble
await page.locator('#panel a[data-stop="7"][data-link="hr-front-door-entra"]').click();  // real pointer
```

`window.__mapLinks.stops` lists every stop with its links (`{ n, id, title, mapTarget, mapAlso, say, links: [{ id, label, url, kind }] }`);
`__mapLinks.current()` is the stop whose card is open.

## Not linked

Four `code` entries are local-only files, so they have no button: stop 6 `hr-flow.md` (readiness),
stop 21 `1-rbac-lint.txt`, `2-scanner-selftest-ci.txt`, `4-not-yet-on.txt` (tour output).
Code links point at `main`, except stop 6's HR form files (branch `feat/hr-form-inbound`).
