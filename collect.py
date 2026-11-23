"""
Clash-Sammler – läuft automatisch bei GitHub (siehe .github/workflows/collect.yml).

Speichert für alle Clans aus clans.json:
  - normale Clankriege mit allen Angriffen     -> data/wars/<clan>_<kriegsbeginn>.json
  - CWL-Gruppe und alle CWL-Kriege der Gruppe  -> data/cwl/<saison>/...

Normale Kriege sind über die API nur sichtbar, solange sie laufen. Deshalb läuft das Skript
regelmäßig und wartet bei einem Krieg, der gleich endet, bis kurz nach Kriegsende.

Zugangsdaten kommen aus den GitHub-Secrets COC_EMAIL und COC_PASSWORD.
"""
import base64, threading, http.cookiejar, json, os, sys, time, urllib.error, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
API = "https://api.clashofclans.com/v1"
DEV = "https://developer.clashofclans.com/api"
KEY_NAME = os.environ.get("KEY_NAME", "sammler")  # eigener Key-Name je Sammler, damit sie sich nicht die Keys löschen
MAX_WAIT = 28 * 60            # so lange wartet das Skript höchstens auf ein Kriegsende
KEEP_DAYS = 190               # ältere Kriege werden automatisch gelöscht (6 Monate + Puffer)
INACTIVE_DAYS = 180           # Spieler ohne Kriegs-/CWL-Angriff so lange -> nicht mehr verfolgen

SEEN_ATTACKERS = set()        # alle Angreifer, die in diesem Lauf in einem Krieg auftauchen
WORKERS = 8                   # so viele Clans werden gleichzeitig abgefragt
_lock = threading.Lock()

TOKEN = ""


# ---------------- Zugang ----------------
def dev_request(opener, path, body):
    req = urllib.request.Request(DEV + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with opener.open(req, timeout=20) as r:
        return json.load(r)


def auto_token(email, password):
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    login = dev_request(opener, "/login", {"email": email, "password": password})
    payload = login["temporaryAPIToken"].split(".")[1]
    payload += "=" * (-len(payload) % 4)
    ip = json.loads(base64.urlsafe_b64decode(payload))["limits"][1]["cidrs"][0].split("/")[0]
    keys = dev_request(opener, "/apikey/list", {}).get("keys", [])
    for k in keys:
        if k["name"] == KEY_NAME and ip in k.get("cidrRanges", []):
            return k["key"]
    for k in keys:                       # alte Sammler-Keys (andere IP) aufräumen
        if k["name"] == KEY_NAME:
            dev_request(opener, "/apikey/revoke", {"id": k["id"]})
    key = dev_request(opener, "/apikey/create", {
        "name": KEY_NAME, "description": "Clash-Sammler (GitHub Actions)",
        "cidrRanges": [ip], "scopes": ["clash"]})["key"]["key"]
    print(f"Neuer API-Key für {ip} erstellt.")
    return key


def get(path):
    """Fehler (Wartungsarbeiten, Zeitüberschreitung …) bringen nie den ganzen Lauf zum Absturz."""
    req = urllib.request.Request(API + path, headers={"Authorization": f"Bearer {TOKEN}"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and attempt < 3:
                time.sleep(2 + 2 * attempt)
                continue
            if e.code == 503:
                print(f"  API antwortet nicht (503 – vermutlich Wartungsarbeiten): {path}")
            return {"_error": e.code}
        except Exception as e:                       # Netzwerk, Zeitüberschreitung, kaputtes JSON
            if attempt < 3:
                time.sleep(2 + 2 * attempt)
                continue
            print(f"  Abfrage fehlgeschlagen ({type(e).__name__}): {path}")
            return {"_error": "netz"}
    return {"_error": 429}


def q(tag):
    return urllib.parse.quote(tag)


# ---------------- Speichern ----------------
def save(path, obj):
    """Schreibt nur, wenn sich der Inhalt geändert hat (spart Commits)."""
    path = os.path.join(DATA, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    new = json.dumps(obj, ensure_ascii=False, indent=1, sort_keys=True)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            if f.read() == new:
                return False
    with open(path, "w", encoding="utf-8") as f:
        f.write(new)
    return True


def parse_time(s):
    return datetime.strptime(s, "%Y%m%dT%H%M%S.%fZ").replace(tzinfo=timezone.utc)


def clean(tag):
    return tag.lstrip("#")


# ---------------- Kompaktes Format ----------------
def compact(war, kind, our_tag, extra=None):
    """Nur das Nötige speichern: Teilnehmer und jeder einzelne Angriff (ca. 5–10 KB statt 50–100 KB)."""
    sides = [war.get("clan", {}), war.get("opponent", {})]
    if sides[1].get("tag") == our_tag:            # unser Clan immer als "clan"
        sides.reverse()
    th = {m["tag"]: m.get("townhallLevel") for s_ in sides for m in s_.get("members", [])}
    def side(s_):
        return {"tag": s_.get("tag"), "name": s_.get("name"), "stars": s_.get("stars"),
                "destruction": s_.get("destructionPercentage"),
                "members": [{"tag": m["tag"], "name": m.get("name"), "th": m.get("townhallLevel"),
                             "pos": m.get("mapPosition")} for m in s_.get("members", [])]}
    attacks = []
    for i, s_ in enumerate(sides):
        for m in s_.get("members", []):
            for at in m.get("attacks", []):
                attacks.append({"side": "clan" if i == 0 else "gegner",
                                "a": at.get("attackerTag"), "d": at.get("defenderTag"),
                                "ath": th.get(at.get("attackerTag")), "dth": th.get(at.get("defenderTag")),
                                "s": at.get("stars"), "p": at.get("destructionPercentage"),
                                "o": at.get("order"), "dur": at.get("duration")})
    attacks.sort(key=lambda x: x["o"] or 0)
    with _lock:
        SEEN_ATTACKERS.update(x["a"] for x in attacks if x["a"])
    out = {"type": kind, "state": war.get("state"), "teamSize": war.get("teamSize"),
           "attacksPerMember": war.get("attacksPerMember"),
           "start": war.get("startTime"), "end": war.get("endTime"),
           "clan": side(sides[0]), "opponent": side(sides[1]), "attacks": attacks}
    out.update(extra or {})
    return out


# ---------------- Normale Clankriege ----------------
def collect_war(clan):
    war = get(f"/clans/{q(clan['tag'])}/currentwar")
    if "_error" in war:
        if war["_error"] == 403:
            print(f"  {clan['name']}: Kriegsprotokoll ist privat – bitte im Spiel auf öffentlich stellen.")
        return None
    state = war.get("state")
    if state not in ("inWar", "warEnded") or "preparationStartTime" not in war:
        return None
    if war.get("isCwl") or war.get("warType") == "cwl":
        return None
    data = compact(war, "krieg", clan["tag"])
    name = f"wars/{clean(clan['tag'])}/{war['preparationStartTime'][:15]}.json"
    if save(name, data):
        n = sum(1 for x in data["attacks"] if x["side"] == "clan")
        print(f"  {clan['name']}: Krieg gespeichert ({state}, {n} Angriffe)")
    return war


# ---------------- CWL ----------------
def already_final(path):
    p = os.path.join(DATA, path)
    if not os.path.exists(p):
        return False
    with open(p, encoding="utf-8") as f:
        return json.load(f).get("state") == "warEnded"


def collect_cwl(clan):
    group = get(f"/clans/{q(clan['tag'])}/currentwar/leaguegroup")
    if "_error" in group or group.get("state") not in ("preparation", "inWar", "ended"):
        return
    season = group.get("season", "unbekannt")
    gpath = f"cwl/{season}/{clean(clan['tag'])}/gruppe.json"
    liga = None
    if os.path.exists(os.path.join(DATA, gpath)):
        with open(os.path.join(DATA, gpath), encoding="utf-8") as f:
            liga = json.load(f).get("liga")
    if not liga and group.get("state") in ("preparation", "inWar"):
        # Liga dieser CWL merken (nach Saisonende zeigt die API schon die neue Liga nach Auf-/Abstieg)
        info = get(f"/clans/{q(clan['tag'])}")
        liga = (info.get("warLeague") or {}).get("name") if "_error" not in info else None
    save(gpath, {
        "season": season, "state": group.get("state"), "liga": liga,
        "clans": [{"tag": c["tag"], "name": c.get("name"),
                   "members": [{"tag": m["tag"], "name": m.get("name"), "th": m.get("townHallLevel")}
                               for m in c.get("members", [])]} for c in group.get("clans", [])]})
    count = 0
    for rnd_no, rnd in enumerate(group.get("rounds", []), 1):
        for wt in rnd.get("warTags", []):
            if wt == "#0":
                continue
            path = f"cwl/{season}/{clean(clan['tag'])}/runde{rnd_no}.json"
            if already_final(path):              # beendete Kriege nicht erneut abfragen
                break
            war = get(f"/clanwarleagues/wars/{q(wt)}")
            if "_error" in war:
                continue
            if clan["tag"] in (war.get("clan", {}).get("tag"), war.get("opponent", {}).get("tag")):
                data = compact(war, "cwl", clan["tag"], {"season": season, "round": rnd_no, "warTag": wt})
                if save(path, data):
                    count += 1
                break                             # pro Runde hat unser Clan genau einen Krieg
    if count:
        print(f"  {clan['name']}: {count} CWL-Kriege aktualisiert (Saison {season})")


# ---------------- Aufräumen ----------------
def prune():
    """Löscht Kriege, die älter als KEEP_DAYS sind (Datum aus dem Kriegsende in der Datei)."""
    limit = datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)
    removed = 0
    for root, _, files in os.walk(DATA):
        for f in files:
            if not f.endswith(".json") or f in ("letzter_lauf.json", "gruppe.json", "spieler.json", "clan_namen.json"):
                continue
            path = os.path.join(root, f)
            try:
                with open(path, encoding="utf-8") as fh:
                    end = json.load(fh).get("end")
                if end and parse_time(end) < limit:
                    os.remove(path)
                    removed += 1
            except Exception:
                pass
    # leere Ordner (inkl. alter CWL-Saisons mit nur noch gruppe.json) entfernen
    for root, dirs, files in os.walk(DATA, topdown=False):
        if root != DATA and files == ["gruppe.json"]:
            os.remove(os.path.join(root, "gruppe.json"))
            files = []
        if root != DATA and not os.listdir(root):
            os.rmdir(root)
    if removed:
        print(f"Aufgeräumt: {removed} Kriege älter als {KEEP_DAYS} Tage gelöscht.")


# ---------------- Ablauf ----------------
# ---------------- Spieler verfolgen ----------------
def load_players():
    p = os.path.join(DATA, "spieler.json")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    return {}


def update_players(clans, extra_tags):
    """Merkt sich alle Mitglieder der eigenen Clans (+ zusätzliche Tags aus clans.json).
    Wer in den letzten KEEP_DAYS Tagen in einem eigenen Clan war, wird weiter verfolgt – auch auswärts."""
    players = load_players()
    today = datetime.now(timezone.utc).date().isoformat()
    current = set()
    for clan in clans:
        res = get(f"/clans/{q(clan['tag'])}/members")
        for m in res.get("items", []) if "_error" not in res else []:
            current.add(m["tag"])
            p = players.setdefault(m["tag"], {"erstmals": today})
            p.update({"name": m.get("name"), "zuletzt_bei_uns": today, "clan": clan["tag"]})
    for tag in extra_tags:
        players.setdefault(tag, {"erstmals": today, "manuell": True})
    return players, current


def finish_players(players, current):
    """Wer einmal bei uns war, bleibt verfolgt, solange er aktiv Krieg spielt.
    Raus fällt nur, wer INACTIVE_DAYS lang weder bei uns war noch einen Angriff gemacht hat."""
    today = datetime.now(timezone.utc).date().isoformat()
    for tag in SEEN_ATTACKERS & set(players):
        players[tag]["letzter_angriff"] = today
    limit = (datetime.now(timezone.utc) - timedelta(days=INACTIVE_DAYS)).date().isoformat()
    keep, dropped = {}, 0
    for tag, p in players.items():
        last = max(p.get("zuletzt_bei_uns", ""), p.get("letzter_angriff", ""), p.get("erstmals", ""))
        if p.get("manuell") or tag in current or last >= limit:
            keep[tag] = p
        else:
            dropped += 1
    if dropped:
        print(f"{dropped} inaktive Spieler werden nicht mehr verfolgt.")
    save("spieler.json", keep)


def foreign_clans(players, current, own_tags):
    """Findet die Clans, in denen verfolgte Spieler gerade außerhalb der eigenen Clans sind."""
    found = {}
    for tag, p in players.items():
        if tag in current:
            continue                                   # ist gerade bei uns -> wird schon erfasst
        prof = get(f"/players/{q(tag)}")
        c = prof.get("clan") if "_error" not in prof else None
        if c and c["tag"] not in own_tags:
            found.setdefault(c["tag"], {"name": c.get("name", c["tag"]), "tag": c["tag"], "spieler": []})
            found[c["tag"]]["spieler"].append(prof.get("name", tag))
    return list(found.values())


def resolve(entries):
    """Erlaubt in clans.json nur Tags ("#ABC") oder {"name":…, "tag":…}. Fehlende Namen holt die API
    (einmalig, danach aus data/clan_namen.json). Prüft dabei, ob es den Clan gibt."""
    path = os.path.join(DATA, "clan_namen.json")
    names = json.load(open(path, encoding="utf-8")) if os.path.exists(path) else {}
    items = []
    for e in entries:
        tag = "#" + (e if isinstance(e, str) else e["tag"]).strip().lstrip("#").upper().replace("O", "0")
        items.append((tag, None if isinstance(e, str) else e.get("name")))
    missing = [t for t, n in items if not n and t not in names]

    def lookup(tag):
        info = get(f"/clans/{q(tag)}")
        return tag, None if "_error" in info else info.get("name", tag)
    with ThreadPoolExecutor(WORKERS) as pool:
        for tag, name in pool.map(lookup, missing):
            if name is None:
                print(f"  ⚠ Clan {tag} wurde nicht gefunden – Tag in clans.json prüfen.")
            else:
                names[tag] = name
    save("clan_namen.json", names)
    return [{"name": n or names[t], "tag": t} for t, n in items if n or t in names]


def main():
    global TOKEN
    email, password = os.environ.get("COC_EMAIL"), os.environ.get("COC_PASSWORD")
    if not email or not password:
        sys.exit("COC_EMAIL / COC_PASSWORD fehlen (GitHub-Secrets).")
    try:
        TOKEN = auto_token(email, password)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:300]
        sys.exit(f"Login/API-Key bei developer.clashofclans.com fehlgeschlagen ({e.code}): {body}\n"
                 "Häufige Ursache: zu viele API-Keys (max. 10). Auf developer.clashofclans.com alte Keys löschen.")
    with open(os.path.join(HERE, "clans.json"), encoding="utf-8") as f:
        cfg = json.load(f)
    clans = resolve(cfg["clans"])                     # eigene Clans: Mitglieder werden verfolgt
    more = resolve(cfg.get("weitere_clans", []))      # weitere Clans: nur deren Kriege sammeln
    known_tags = {c["tag"] for c in clans + more}

    players, current = update_players(clans, cfg.get("zusaetzliche_spieler", []))
    away = foreign_clans(players, current, known_tags)
    print(f"{len(players)} Spieler verfolgt, {len(away)} Clans mit Auswärts-Spielern.")

    def work(clan):
        try:
            war = collect_war(clan)
            collect_cwl(clan)
        except Exception as e:                       # ein kaputter Clan stoppt nicht den ganzen Lauf
            print(f"  {clan.get('name', clan['tag'])}: Fehler {type(e).__name__}: {e}")
            return None
        if war and war.get("state") == "inWar":
            left = (parse_time(war["endTime"]) - datetime.now(timezone.utc)).total_seconds()
            if 0 < left < MAX_WAIT:
                return (left, clan)
        return None

    targets = clans + more + [dict(c, fremd=True) for c in away]
    for c in away:
        print(f"Auswärts: {c['name']} ({', '.join(c['spieler'])})")
    with ThreadPoolExecutor(WORKERS) as pool:
        ending = [r for r in pool.map(work, targets) if r]
    print(f"{len(targets)} Clans geprüft.")

    # Krieg endet bald -> bis kurz nach Kriegsende warten und den Endstand holen
    if ending:
        wait = max(left for left, _ in ending) + 45
        print(f"Krieg endet in {int(wait // 60)} Min – warte auf den Endstand …")
        time.sleep(wait)
        for _, clan in ending:
            collect_war(clan)

    finish_players(players, current)
    prune()
    save("letzter_lauf.json", {"zeit": datetime.now(timezone.utc).isoformat(timespec="seconds")})


if __name__ == "__main__":
    main()
