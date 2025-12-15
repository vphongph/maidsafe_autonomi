---
alwaysApply: true
---
Copied from /Users/vphongph/.claude/CLAUDE.md

# Good coding practice
- Always compile after writing Rust code. If there are errors, fix them! If there are warnings, fix them!

- Always compile after writing code for the Python bindings written in Rust. But in this case the compilation process is different. Use uv and maturin, you must activate the venv (source autonomi/.venv/bin/activate) and compile using maturin develop --uv.

- Always play safe, investigate the proofs and read carefully the code you need to have the best context, no assumptions out of nowhere!

- Don't be a DUMB SHIT!

- Produce production code, no unnecessary comments or emojis to talk to me when we are developing or explanation between us. If you put a comment it's for everyone to understand, devs and users.

- Do simple code, code should have maximum 3 indentations, 1 for the function, 1 for a loop or a if, an other one for an additional loop or if. You can put more indentations if it's absolutely necessary but it this case you have to tell it to me and explain it to me, then I will decide if I keep it or find an other solution.

- Always explain in details what you do! Like if you had to teach knowledge to a class of students!
As always, no assumptions, proofs only! Ask questions in return if you are not confident in your action!

- Do simple code, all the time, the SIMPLEST, the BEST, readability is over all!

- Always test the code you write!

- Always explain what you do, and say exactly what you do and why you do it, especially when you are submitting code to me to accept!