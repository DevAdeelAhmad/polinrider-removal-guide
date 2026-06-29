# PolinRider npm Supply-Chain Malware — Detection & Removal Guide (macOS)

A practical, field-tested guide for identifying, containing, and removing the
PolinRider-family loader that injects itself into JavaScript/TypeScript project
config files and re-runs via the Node toolchain. Written for developers on macOS
using Node, npm/pnpm, and editors like VS Code / Cursor.

> **Disclaimer:** This is a community write-up based on hands-on remediation, not
> official vendor guidance. Malware mutates. Treat the *behaviours* below as the
> reliable signal, not any single string or filename. If you handle sensitive
> credentials or infrastructure, assume compromise and rotate everything (see
> the Credentials section) regardless of how clean your machine looks afterward.

---

## TL;DR

1. A hidden, heavily obfuscated `node -e` process keeps spawning and tries to read
   your `github.com` credential from the keychain (you get a repeating keychain
   password prompt).
2. The source is an obfuscated blob **appended to your project config files**
   (`postcss.config.*`, `tailwind.config.*`, etc.), pushed off-screen by whitespace.
3. It re-runs whenever your editor/toolchain loads those configs, and can ride in
   through editor features that auto-run `npm install`/`npm exec` (e.g. TypeScript
   Automatic Type Acquisition, MCP servers).
4. Fix = find & strip the injected blob from source files, clear build/exec caches,
   reinstall Node, verify nothing respawns, then **rotate all credentials from a
   different device**.

---

## 1. How to identify it

### Symptom checklist

- A macOS keychain prompt that reappears constantly:
  *"security wants to use your confidential information stored in 'github.com'"* —
  and clicking **Deny** just makes it pop again.
- Your IDE, language server, or `localhost` dev server stops working correctly.
- Many near-identical `node` processes in Activity Monitor (same thread/port counts).
- High background CPU or fan activity with no obvious cause.

### Confirm with the terminal

Look for the obfuscated loader process. The signature pattern starts with a global
assignment and a custom string-shuffle de-obfuscator:

```bash
ps -Awwo pid,ppid,command | grep "global\['_V'\]" | grep -v grep
```

Common markers seen in this family (any of these in a process or file is a red flag):

- `global['_V']='A10'` or `global['!']='10'`
- A self-decoding function that builds strings via `String.fromCharCode(127)` and
  `.split().join()` chains
- Calls like `nWk(9608)`, and obfuscated identifiers such as `_$_1e42`, `_$_16d1`
- An inline `node -e "<huge one-liner>"` invocation
- `global["_t_t"]`, `global["_t_c"]`, `clientCode`, `global._R` scaffolding

> **Why it's hard to spot:** the payload often runs *inline* via `node -e`, so there
> may be no obvious malicious file sitting on disk. The reliable on-disk source is
> usually the **injected config files** (next section), not a standalone script.

### Count whether it's actively respawning

```bash
ps -Awwo command | grep -c "global\['_V'\]"
```

`0` means nothing is running *at this instant*. Because the loader only fires on a
trigger, watch it over time instead of trusting a single check:

```bash
for i in $(seq 1 36); do
  echo "$(date +%H:%M:%S) count=$(ps -Awwo command | grep -c "global\['_V'\]")"
  sleep 5
done
```

Run this for a few minutes **while you open your editor and projects**. If the count
jumps from 0 to 1+ when you open a folder or edit a file, you've reproduced the
trigger.

---

## 2. Find the source on disk

The loader is typically appended to legitimate project config files, separated from
the real config by a long run of whitespace so it's hidden when you scroll. Search
your code directory:

```bash
grep -rIl \
  -e "global\['_V'\]='A10'" \
  -e "global\['!'\]='10'" \
  -e "_\$_1e42" \
  -e "nWk(9608)" \
  ~/Code \
  --include="*.js" --include="*.mjs" --include="*.cjs" --include="*.ts" --include="*.tsx" \
  2>/dev/null | grep -vE "node_modules|/\.next/"
```

(Replace `~/Code` with wherever your repos live.)

### Telling real hits from false positives

Some legitimate files contain large base64/encoded blobs and may match a loose grep.
**Do not delete these:**

- Prisma engine files: `query_compiler_*.wasm-base64.js` / `.mjs`
- WASM bundles: `HermesParserWASM.js` and similar
- Your own build output under `.next/`, `dist/`, `build/` (regenerated — just
  rebuild after cleaning source)
- Any scanner scripts you or others added (e.g. files literally named for this
  malware) — they contain the signature *on purpose* to detect it

**The real hits** are hand-written config files that should be short and readable,
such as:

- `postcss.config.mjs` / `postcss.config.js`
- `tailwind.config.js` / `tailwind.config.ts`
- `next.config.*`, `vite.config.*`, and similar

Inspect a suspect to confirm — look at the first and last lines:

```bash
f=~/Code/path/to/postcss.config.mjs
wc -l "$f"; echo "--- head ---"; head -5 "$f"; echo "--- tail ---"; tail -5 "$f"
```

A confirmed infection looks like a normal config (ending in e.g. `export default
config;`), then a wall of spaces, then `global['!']='10';var _$_1e42=...` on the
same final line.

---

## 3. Remove the injected payload

Back up each file, then strip everything from the injection marker to end-of-file
(this preserves your real config and removes only the malicious tail):

```bash
for f in \
  ~/Code/path/to/postcss.config.mjs \
  ~/Code/path/to/tailwind.config.js; do
  cp "$f" "$f.infected.bak"
  # delete from the injected marker through the end of the file
  perl -0pi -e "s/\s*global\['!'\]='10';.*\$//s" "$f"
  echo "=== $f ==="
  tail -3 "$f"
  echo "signature remaining: $(grep -c "_\$_1e42\|global\['!'\]" "$f")"
done
```

`signature remaining: 0` on each file means it's clean. Verify the file still ends
with your real config.

> If your variant uses a different marker (e.g. `global['_V']='A10'`), adjust the
> `perl` substitution accordingly. Always confirm by eye that only the malicious
> block was removed.

After verifying the cleaned files, delete the `.infected.bak` quarantine copies:

```bash
rm ~/Code/path/to/*.infected.bak
```

### Clear contaminated build output and caches

Build artifacts compiled from the poisoned configs carry the payload. Delete them so
they regenerate clean:

```bash
rm -rf ~/Code/*/.next ~/Code/*/dist ~/Code/*/build
```

Also clear toolchain caches that may have executed or stored tainted installs:

```bash
rm -rf ~/Library/Caches/typescript   # TypeScript auto-acquired @types cache
rm -rf ~/.npm/_npx                    # npx exec cache (re-created cleanly on demand)
```

---

## 4. Stop it from re-running (close the trigger paths)

Cleaning files isn't enough if an editor feature keeps auto-running installs that
re-trigger the loader. Two known trigger paths:

### a) TypeScript Automatic Type Acquisition (ATA)

Editors auto-run `npm install @types/...` when you open/edit TS files. Disable it in
your editor's `settings.json`:

```json
{
  "typescript.disableAutomaticTypeAcquisition": true
}
```

### b) MCP servers that `npm exec` a package on startup

Editor MCP integrations can launch packages via `npm exec` every time the editor
starts. Audit your MCP config and disable any server you don't fully trust, then
confirm none are spawning the loader (see verification below).

### c) Block install lifecycle scripts globally (defense-in-depth)

```bash
npm config set ignore-scripts true
pnpm config set ignore-scripts true
```

> Trade-off: native modules that need a build step won't compile under this. When
> you trust a specific project, re-enable scripts just for that install rather than
> turning the global setting off.

---

## 5. Reinstall the Node toolchain (recommended)

If the loader survives config cleanup — i.e. it still spawns from a fresh trigger
with clean source files — the injection may be living in the Node/npm execution
layer rather than in a file you can grep. Reinstalling Node replaces that layer
without wiping your OS or projects (Homebrew example):

```bash
# stop anything running first
pkill -9 -f "global\['_V'\]"

# remove node + all its caches
brew uninstall --ignore-dependencies node
rm -rf ~/.npm ~/.npmrc ~/.node-gyp ~/Library/Caches/typescript
rm -rf /opt/homebrew/lib/node_modules

# reinstall
brew install node
```

Reinstall your global packages fresh afterward (only what you actually use), e.g.:

```bash
npm install -g pnpm
# plus your own essentials, kept minimal
```

Prefer keeping tools like Prisma, Next, Tailwind, ESLint, and Prettier as project
`devDependencies` rather than global installs — smaller exec surface.

---

## 6. Verify you're clean

Run a timed watch **while triggering everything** (open your editor, open projects,
let MCP servers start, edit a TS/config file):

```bash
for i in $(seq 1 36); do
  echo "$(date +%H:%M:%S) count=$(ps -Awwo command | grep -c "global\['_V'\]")"
  sleep 5
done
```

A clean result is `count=0` on every line across the full window, including when
triggers fire. Also re-run the source sweep from Section 2 — it should return
nothing (or only intentional scanner scripts).

Re-check that a previously-infected config does **not** get re-written after you
edit it in your editor:

```bash
grep -c "global\['!'\]='10'" ~/Code/path/to/postcss.config.mjs   # expect 0
```

---

## 7. Credentials — do this regardless (from a different, clean device)

The loader's purpose is credential theft (the repeating keychain prompt is it trying
to read your GitHub credential). Cleaning the machine does **not** un-leak anything
that already left it. From a phone or another trusted computer:

- **GitHub:** change your password; revoke **all** Personal Access Tokens, SSH keys,
  and authorized OAuth apps; re-check 2FA.
- **npm / pnpm:** rotate tokens. Check your npm account for any package versions
  published without your knowledge (this family can republish through your token).
- **Anything else the machine held:** server/VPS SSH keys and root passwords, secrets
  managers, object-storage keys, cloud provider credentials.

Delete the stale keychain entry locally so your tools re-store a fresh credential:

```bash
security delete-internet-password -a <your-username> -s github.com
```

---

## 8. Stop reinfection (the part people miss)

If injected config files were **committed to git**, the malware lives in your history
and possibly on your remote — so a fresh `clone`/`pull` re-infects you. For each repo:

```bash
cd ~/Code/path/to/repo
git status
git diff <config-file>                      # confirm only the payload is removed
git log --oneline -5 -- <config-file>        # see when it was introduced
git show HEAD:<config-file> | grep -c "global\['!'\]='10'"   # 0 = remote/committed copy is clean
```

- If the committed/remote copy still contains the payload, clean it there too, commit
  the fix, and push. Audit every repo in the affected org.
- Check any other machine, teammate, CI runner, or server that clones these repos.
- Until the remote is clean, assume each clone is a reinfection vector.

---

## Quick reference — one-shot health check

```bash
echo "=== running loaders ==="; ps -Awwo pid,command | grep "global\['_V'\]" | grep -v grep
echo "loader count: $(ps -Awwo command | grep -c "global\['_V'\]")"
echo "=== keychain-theft processes ==="; ps -Awwo pid,command | grep "find-internet-password.*github" | grep -v grep
echo "=== inline node -e processes ==="; pgrep -fl "node -e" | grep -v grep
echo "=== source sweep ==="; grep -rIl "global\['!'\]='10'\|global\['_V'\]='A10'\|_\$_1e42" ~/Code \
  --include="*.js" --include="*.mjs" --include="*.cjs" --include="*.ts" --include="*.tsx" 2>/dev/null \
  | grep -vE "node_modules|/\.next/|\.infected\.bak"
echo "=== done — all sections should be empty ==="
```

---

## Notes & caveats

- Obfuscated strings, numeric constants, and marker names **change between variants**.
  Rely on the structural fingerprint (inline `node -e`, string-shuffle decoder,
  config-tail injection, keychain access for `github.com`) rather than exact bytes.
- A single point-in-time "0 processes" check is not proof. Verify across triggers and
  over time.
- If the loader survives config cleanup **and** a full Node reinstall with cleared
  caches, the persistence is likely below the toolchain. At that point a full OS
  reinstall is the honest path — restore project code only from a commit known to
  predate the infection, and install dependencies with scripts disabled until audited.
- The single non-negotiable step is credential rotation from a clean device. Do it
  even if everything else looks fine.

---

*Share freely. Adapt paths and markers to your environment.*
