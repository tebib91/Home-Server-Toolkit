# 🏠 Home Server Toolkit

**A simple toolkit for running multiple home server management and security scripts in one go.**

> Clone the repo, run a single command, and execute all included scripts sequentially.

---

## 🚀 Quickstart

```bash
# 1) Clone the repository
git clone https://github.com/<you>/home-server-toolkit.git
cd home-server-toolkit

# 2) Make all scripts executable
chmod +x scripts/*.sh

# 3) Run all scripts (requires sudo for certain checks)
./run-all.sh
```

`run-all.sh` will:

1. Detect and install missing dependencies.
2. Run each script inside the `scripts/` folder in a predefined order.
3. Save outputs/logs in a local `reports/` folder.

---

## 📂 Scripts folder

Inside the `scripts/` folder, you’ll find:

* Individual Bash scripts for different security and maintenance tasks.
* A dedicated `README.md` inside `scripts/` explaining the purpose, usage, and options of each script.

---

## 📦 Requirements

* Linux host (Ubuntu/Debian recommended).
* `sudo` access for some scripts.
* Internet connectivity for installing dependencies.

---

## 🛡️ Security Notes

* All scripts are local-only — no sensitive data is sent externally.
* Some scripts (like network scans) may need to be run from outside your LAN for full accuracy.

---

## ⚖️ License

MIT — see `LICENSE`.

---

## 🚧 Roadmap

* [x] Add `home-sec-check.sh` as the first script
* [ ] Add more scripts (firewall baseline, Docker hygiene, backup checks)
* [ ] Create unified `run-all.sh`
* [ ] Enhance reports and logging
