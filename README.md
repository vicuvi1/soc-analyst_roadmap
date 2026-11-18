# SOC Study Center (SOC Analyst in 12 Weeks)

A personal learning system for becoming a junior SOC analyst in 12 weeks at about 8 hours a week. It sits on top of TryHackMe (SOC Level 1 path) and pwn.college: it says which labs to do each week, then tests whether the knowledge stuck.

## What is in it

- **Roadmap home page**: the page opens on the roadmap. One line runs through the 12 weeks and 4 stage exams; every week shows its real TryHackMe rooms as chips (done, next, to do) that open the room on TryHackMe. The top shows the next room to do and a TryHackMe sync panel (rooms done of 65, profile, last read, check now, manual sync). The old Today page is now Roadmap > Overview.
- **4 stages of 3 weeks**: networks and frameworks; email, web and Windows; Linux, malware and SIEM; triage, cloud/AD and incident response.
- **Each week is five steps**: learn (curated videos, reference pages and tools), labs, coach notes with a self-check, a 7-question quiz, and a hands-on challenge on real-looking evidence (logs, packet output, email headers, encoded PowerShell).
- **Library**: all 128 resources in one place, filterable by type.
- **Cheat sheets**: every reference table and command list on one printable page.
- **Interview questions**: three per week with model answers.
- **TryHackMe integration**: the labs are the 65 real rooms of the SOC Level 1 path, each linked. `Start SOC Analyst.bat` reads your public TryHackMe profile on start and then every 2 minutes in a hidden background PowerShell (`sync-thm.ps1 -Loop`, username `vicuvi1` by default, stops after 12 hours). The open page re-reads the result every minute, ticks newly completed rooms without a reload, and adds them to the study calendar. Today shows the next two rooms to do.
- **Skills**: a score per area (50% knowledge retained, 30% labs, 20% challenges), a radar that shows today against an earlier day, a retention figure from review answers, a daily weak-spot drill, and a skill index over time.
- **Alert simulator**: a timed queue of eight alerts with logs and a reference sheet; verdicts, priority order and speed are scored, then a case report is written. Two built-in scenarios; the hosted version generates new ones.
- **Mistake notebook**: every question answered wrongly, with the right answer and reason, on the Review tab. Stage exam answers now count toward skill scores.
- **Placement test**: 27 scenario questions across nine areas set a starting floor for the skill scores.
- **Today's session**: one button walks through due reviews, the next room and a drill, with the timer started and stopped automatically.
- **Backups and system check**: a daily automatic backup kept for seven days with restore, and a page that tests each connection for real.
- **Study timer and weekly review**: a start/stop timer in the top bar logs real minutes; the Weekly tab shows hours against the 8-hour target, rooms, answer accuracy, skill change and one thing to change.
- **AI tutor and connected apps (Claude-hosted version only)**: Claude writes fresh questions per area, explains wrong answers, grades incident reports against a rubric and grades interview answers; the page can add the week's four sessions to Google Calendar and send today's plan to Todoist. These need the page's ask-Claude and connector capabilities, so they are hidden when `index.html` is opened as a local file.
- **Study calendar**: a GitHub-style activity grid in gold, with streaks.
- **Move to another PC**: download one HTML copy that carries your progress inside it, or export and import a progress file or code.
- **Spaced repetition**: quiz questions return after 1, 3, 7, 14 and 30 days. A wrong answer resets the question to the next day.
- **Stage exams**: 20 questions in 25 minutes, 80% to pass, 12-hour wait after a fail. Passing unlocks the next stage.
- **Final test**: a 30-question exam across all 12 weeks plus a capstone incident investigated across four log sources.

## Run it

**Windows**: download or clone this repo, then double-click `Start SOC Analyst.bat`. It opens the site in its own app window (Edge or Chrome app mode, otherwise your default browser). Double-click `Create desktop shortcut.bat` once to get a Desktop icon.

**Any system**: open `index.html` in a browser.

It is a single self-contained page; only the fonts load from the network. Progress is saved in the browser's localStorage, tied to the folder the file is in, so keep the folder in one place.

## Edit it

| File | Purpose |
| --- | --- |
| `content.js` | All curriculum content: weeks, lessons, quiz questions, challenges and their answers |
| `template.html` | The app: styles, views, quiz/exam/review logic |
| `build.js` | Hashes the challenge answers and injects the content into the template |
| `index.html` | Built output |
| `Start SOC Analyst.bat` | Windows launcher |
| `Create desktop shortcut.bat` | Creates a Desktop icon pointing at the launcher |
| `icon.ico` | Icon for the shortcut |
| `sync-thm.ps1` | Reads completed rooms from a public TryHackMe profile into `thm.js` |

After changing `content.js` or `template.html`:

```
node build.js
```

Run the browser tests (needs `npm install` once, and Chrome or `npx playwright install chromium`):

```
npm test
```

The build also writes `answers.json` (plain challenge answers, for testing). It is git-ignored.

## Note on answers

`index.html` stores challenge answers only as hashes. `content.js` holds them in plain text, so do not read the `chal` sections of a week you have not solved yet.
