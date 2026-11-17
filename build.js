const fs = require('fs'), path = require('path');
const { weeks, stages } = require('./content.js');
const norm = s => String(s).toLowerCase().replace(/\s+/g, '');
function hash(str) { let h1 = 0xdeadbeef ^ 77, h2 = 0x41c6ce57 ^ 77; for (let i = 0, ch; i < str.length; i++) { ch = str.charCodeAt(i); h1 = Math.imul(h1 ^ ch, 2654435761); h2 = Math.imul(h2 ^ ch, 1597334677); } h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909); h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909); return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36); }

const answers = {};
const data = {
  weeks: weeks.map((w, wi) => {
    if (w.quiz.length !== 7) throw new Error('week ' + (wi + 1) + ' quiz length');
    if (!w.res || w.res.filter(r => r[5]).length !== 2 || w.res.some(r => !/^https?:\/\//.test(r[2]))) throw new Error('week ' + (wi + 1) + ' resources');
    w.quiz.forEach(q => { if (q.o.length !== 4 || q.a < 0 || q.a > 3) throw new Error('bad question ' + q.q); });
    answers[wi + 1] = w.chal.qs.map(q => q[1][0]);
    return { ...w, chal: { ...w.chal, qs: w.chal.qs.map(q => ({ p: q[0], h: [...new Set(q[1].map(a => hash(norm(a))))], hint: q[2] })) } };
  }),
  stages,
};
stages.forEach(s => s.extra.forEach(q => { if (q.o.length !== 4) throw new Error('bad extra'); }));
const json = JSON.stringify(data).replace(/</g, '\\u003c');
const html = fs.readFileSync(path.join(__dirname, 'template.html'), 'utf8').replace('/*DATA*/null', () => json);
fs.writeFileSync(path.join(__dirname, 'index.html'), html);
fs.writeFileSync(path.join(__dirname, 'answers.json'), JSON.stringify(answers, null, 1));
const nq = weeks.reduce((a, w) => a + w.quiz.length, 0) + stages.reduce((a, s) => a + s.extra.length, 0);
console.log('built', (html.length / 1024).toFixed(0) + ' KB,', nq, 'questions,', weeks.reduce((a, w) => a + w.chal.qs.length, 0), 'challenge answers');
// answer-position balance
const pos = [0, 0, 0, 0]; weeks.forEach(w => w.quiz.forEach(q => pos[q.a]++)); stages.forEach(s => s.extra.forEach(q => pos[q.a]++)); console.log('answer positions', pos);
console.log('total hours', weeks.reduce((a, w) => a + w.tasks.reduce((b, t) => b + t[2], 0), 0));
