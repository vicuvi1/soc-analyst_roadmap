# SOC Analyst in 12 Weeks

A personal learning system for becoming a junior SOC analyst in 12 weeks at about 8 hours a week. It sits on top of TryHackMe (SOC Level 1 path) and pwn.college: it says which labs to do each week, then tests whether the knowledge stuck.

## What is in it

- **4 stages of 3 weeks**: networks and frameworks; email, web and Windows; Linux, malware and SIEM; triage, cloud/AD and incident response.
- **Each week is five steps**: learn (curated videos, reference pages and tools), labs, coach notes with a self-check, a 7-question quiz, and a hands-on challenge on real-looking evidence (logs, packet output, email headers, encoded PowerShell).
- **Library**: all 128 resources in one place, filterable by type.
- **Cheat sheets**: every reference table and command list on one printable page.
- **Interview questions**: three per week with model answers.
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

After changing `content.js` or `template.html`:

```
node build.js
```

The build also writes `answers.json` (plain challenge answers, for testing). It is git-ignored.

## Note on answers

`index.html` stores challenge answers only as hashes. `content.js` holds them in plain text, so do not read the `chal` sections of a week you have not solved yet.
