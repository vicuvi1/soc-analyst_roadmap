// Browser smoke test. Run: npm test   (needs: npm i -D playwright, and Chrome or `npx playwright install chromium`)
// Builds are checked against the real page: quiz, challenges, exams, simulator scoring, placement, session, sync and transfer.
const path = require('path'), fs = require('fs');
let chromium; try { ({ chromium } = require('playwright')); } catch (e) { ({ chromium } = require(process.env.PLAYWRIGHT_PATH || '/opt/npm-tools/node_modules/playwright')); }
const U = 'file://' + path.join(__dirname, '..', 'index.html');
const ans = fs.existsSync(path.join(__dirname, '..', 'answers.json')) ? require('../answers.json') : null;
let failed = 0; const ok = (name, cond, extra) => { console.log((cond ? 'PASS ' : 'FAIL ') + name + (extra ? '  ' + extra : '')); if (!cond) failed++; };
const openAll = p => p.evaluate(() => document.querySelectorAll('details').forEach(d => d.open = true));

(async () => {
  const exe = process.env.CHROME || (fs.existsSync('/usr/bin/google-chrome') ? '/usr/bin/google-chrome' : undefined);
  const b = await chromium.launch({ executablePath: exe, args: ['--no-sandbox'] }), errs = [];
  const page = async (init) => { const c = await b.newContext({ viewport: { width: 1280, height: 900 }, acceptDownloads: true }); const p = await c.newPage(); p.on('pageerror', e => errs.push(e.message)); if (init) await p.addInitScript(init); return p; };

  // --- plain file: core learning loop
  let p = await page(); await p.goto(U);
  ok('home is the roadmap with the next TryHackMe room', (await p.textContent('.rm-next h1')).trim() === 'MITRE' && /tryhackme\.com\/room\/mitre/.test(await p.getAttribute('.rm-next a.btn', 'href')));
  ok('roadmap shows 12 weeks, 4 exams and all rooms', await p.evaluate(() => document.querySelectorAll('.rd-stop:not(.exam)').length === 12 && document.querySelectorAll('.rd-stop.exam').length === 4 && document.querySelectorAll('.rm:not(.other)').length === 66));
  ok('roadmap marks synced rooms done and one next', await p.evaluate(() => document.querySelectorAll('.rm.done').length === 19 && document.querySelectorAll('.rm.nx').length === 1 && /^18$/.test(document.querySelector('.rm-count b').textContent)));
  await p.goto(U + '#today');
  ok('today shows real next rooms', (await p.$$eval('.today-rooms b', e => e.map(x => x.textContent))).join(',') === 'MITRE,Summit');
  ok('path rooms synced from snapshot', /18\/65/.test(await p.textContent('.card .chip.fill')));
  await p.goto(U + '#week-1'); await openAll(p);
  ok('week 1 has synced rooms', (await p.$$('.tasks input:disabled')).length === 7);
  await p.click('[data-act=startQuiz]'); for (let i = 0; i < 7; i++) { await p.click('.opt >> nth=0'); await p.click('[data-act=nextQ]'); }
  ok('quiz completes and schedules reviews', await p.evaluate(() => Object.keys(S.q).length === 7 && !!S.wq[1]));
  ok('wrong challenge answer rejected', await (async () => { await openAll(p); await p.fill('#ci-1-0', 'nope'); await p.press('#ci-1-0', 'Enter'); return !(await p.$('#cq-1-0.ok')); })());
  if (ans) { await p.evaluate(() => { S.ex = { 1: { passed: true, best: 1, n: 1 }, 2: { passed: true, best: 1, n: 1 }, 3: { passed: true, best: 1, n: 1 } }; save(); });
    let good = 0, tot = 0; for (let w = 1; w <= 12; w++) { await p.goto(U + '#week-' + w); await p.reload(); await openAll(p); await p.waitForTimeout(40);
      for (let i = 0; i < ans[w].length; i++) { tot++; await p.fill(`#ci-${w}-${i}`, ' ' + ans[w][i].toUpperCase() + ' '); await p.press(`#ci-${w}-${i}`, 'Enter'); await p.waitForTimeout(15); if (await p.$(`#cq-${w}-${i}.ok`)) good++; } }
    ok('all challenge answers accepted', good === tot, good + '/' + tot); }
  await p.goto(U + '#exam-4'); await p.reload(); await p.click('[data-act=startExam]');
  await p.evaluate(() => ES.ids.forEach(id => document.getElementById('e-' + id + '-' + Q[id].a).click())); await p.click('[data-act=submitExam]');
  ok('final exam scores 100% when all correct', (await p.textContent('.big')).trim() === '100%');

  // --- simulator scoring
  p = await page(); await p.goto(U + '#sim'); await p.click('[data-act=simStart] >> nth=0');
  for (const [id, v] of await p.evaluate(() => SIM.alerts.slice().sort((a, b) => SEVW[b.sev] - SEVW[a.sev]).map(a => [a.id, a.v]))) { await p.click(`[data-act=simSel][data-id="${id}"]`); await p.click(`[data-act=simV][data-v=${v}]`); }
  await p.click('[data-act=simFinish]'); ok('perfect simulator run scores 100', (await p.textContent('.hero h1')).trim() === '100/100');
  await p.click('[data-act=simClose]'); await p.click('[data-act=simStart] >> nth=1');
  for (const [id, v] of await p.evaluate(() => SIM.alerts.map(a => [a.id, a.v === 'tp' ? 'fp' : 'tp']))) { await p.click(`[data-act=simSel][data-id="${id}"]`); await p.click(`[data-act=simV][data-v=${v}]`); }
  await p.click('[data-act=simFinish]'); ok('all-wrong simulator run scores 0', parseInt(await p.textContent('.hero h1')) === 0, await p.textContent('.hero h1'));

  // --- placement test and skill floor
  p = await page(); await p.goto(U + '#placement'); const before = await p.evaluate(() => skillIndex()); await p.click('[data-act=plStart]');
  for (let i = 0; i < 27; i++) { const a = await p.evaluate(() => Q[PL.ids[PL.i]].a); await p.click(`[data-act=plPick][data-o="${a}"]`); }
  ok('placement records 27/27', await p.evaluate(() => S.place && S.place.by.reduce((a, b) => a + b, 0) === 27));
  ok('placement raises the skill index', await p.evaluate(() => skillIndex()) > before + 20, before + ' -> ' + await p.evaluate(() => skillIndex()));

  // --- guided session
  p = await page(); await p.goto(U + '#session'); await p.click('[data-act=sessStart]');
  ok('session starts the timer', await p.evaluate(() => !!S.timer && !!SESS));
  let guard = 0; while (await p.evaluate(() => SESS && SESS.steps[SESS.i] !== 'done') && guard++ < 6) await p.click('[data-act=sessNext] >> nth=0');
  ok('session reaches summary and stops the timer', await p.evaluate(() => SESS.steps[SESS.i] === 'done' && !S.timer));

  // --- transfer and backups
  p = await page(); await p.goto(U + '#week-1'); await openAll(p); await p.check('#r-1-0'); const code = await p.evaluate(() => toCode());
  const q = await page(); await q.goto(U + '#today'); await q.fill('#impCode', code); await q.click('[data-act=impCode]'); await q.click('[data-act=impYes]');
  ok('progress code imports into a fresh browser', await q.evaluate(() => Object.keys(S.res).length === 1));
  await q.reload(); ok('daily backup is written', await q.evaluate(() => localBackups().length >= 1));

  // --- hosted capabilities (mocked): cloud sync, tutor, apps, system check
  p = await page(() => { window.__calls = [];
    const sample = async () => ({ text: 'OK' }); sample.json = async pr => /Write 5 NEW/.test(pr) ? Array.from({ length: 5 }, (_, i) => ({ q: 'G' + i + '?', o: ['a', 'b', 'c', 'd'], a: i % 4, why: 'w' })) : { rubric: [20, 25, 25, 15, 15].map(m => ({ points: m, comment: 'ok' })), fixes: [] };
    const store = {}; const db = { doc: path => ({ get: async () => store[path] ? { exists: true, data: () => store[path] } : { exists: false }, set: async d => { store[path] = d; }, onSnapshot: n => { if (path === 'sync/thm') setTimeout(() => n({ exists: true, data: () => ({ user: 'vicuvi1', at: Date.now() + 1000, source: 'scheduled', codes: ['mitre'] }) }), 200); return () => {}; } }) };
    const mcp = { callTool: async (s, t, i) => { window.__calls.push([s, t, i]); return { payload: {} }; }, listTools: async n => ({ servers: [{ server: n, authStatus: 'connected', tools: [] }] }) };
    window.claude = { use: async n => ({ sample, db, mcp, user: { id: async () => 'u1' } })[n] || null }; });
  await p.goto(U + '#today'); await p.waitForSelector('[data-act=calAdd]'); await p.waitForTimeout(500);
  ok('cloud sync ticks a newly finished room', (await p.$$eval('.today-rooms b', e => e.map(x => x.textContent))).join(',') === 'Summit,Eviction');
  await p.click('[data-act=calAdd]'); await p.waitForFunction(() => /Done/.test(document.querySelector('#calMsg').textContent));
  await p.click('[data-act=todoAdd]'); await p.waitForFunction(() => /Done/.test(document.querySelector('#todoMsg').textContent));
  const calls = await p.evaluate(() => window.__calls);
  ok('calendar gets 4 well-formed events', calls.filter(c => c[1] === 'create_event').length === 4 && /^\d{4}-\d\d-\d\dT\d\d:\d\d:00$/.test(calls[0][2].startTime));
  ok('todoist gets tasks due today', (calls.find(c => c[1] === 'add-tasks') || [])[2].tasks.every(t => t.dueString === 'today'));
  await p.goto(U + '#skills'); await p.waitForSelector('[data-act=aiQ]'); await p.click('[data-act=aiQ] >> nth=0'); await p.waitForSelector('.opt');
  ok('generated questions join the bank', await p.evaluate(() => Object.keys(S.bank).length === 5));
  await p.goto(U + '#check'); await p.click('[data-act=checkAll]'); await p.waitForFunction(() => S.diag && Object.keys(S.diag.r).length === 6 && !document.querySelector('[data-act=checkAll]').disabled);
  ok('system check passes db, ai, thm, calendar, todoist', await p.evaluate(() => ['db', 'ai', 'thm', 'cal', 'todo'].every(k => S.diag.r[k][0] === 1)), JSON.stringify(await p.evaluate(() => Object.fromEntries(Object.entries(S.diag.r).map(([k, v]) => [k, v[0]])))));

  // --- phone width: no sideways scroll
  const c = await b.newContext({ viewport: { width: 390, height: 800 } }); const m = await c.newPage(); m.on('pageerror', e => errs.push(e.message));
  for (const h of ['today', 'week-2', 'skills', 'sim', 'weekly', 'review', 'roadmap']) { await m.goto(U + '#' + h); await m.reload(); const over = await m.evaluate(() => document.documentElement.scrollWidth - window.innerWidth); ok('no sideways scroll at 390px: ' + h, over <= 1, over > 1 ? over + 'px over' : ''); }
  if (process.env.SHOTS) { await m.goto(U + '#today'); await m.screenshot({ path: process.env.SHOTS + '/phone-today.png' }); await m.goto(U + '#session'); await m.screenshot({ path: process.env.SHOTS + '/phone-session.png' }); }

  ok('no page errors', errs.length === 0, errs.join(' | '));
  await b.close(); console.log(failed ? `\n${failed} FAILED` : '\nall passed'); process.exit(failed ? 1 : 0);
})();
