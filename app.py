import os, re, secrets, sqlite3, time, math
from flask import Flask, g, jsonify, request, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from twilio.rest import Client
except ImportError:
    Client = None

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "roommatch.db"))
LISTING_FEE = 20
APPLICATION_FEE = 15

app = Flask(__name__, static_folder="static", static_url_path="")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 14,
    MAX_CONTENT_LENGTH=64 * 1024,
)


def _secret():
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    p = os.path.join(BASE, ".secret_key")
    if not os.path.exists(p):
        with open(p, "w") as f:
            f.write(secrets.token_hex(32))
    return open(p).read().strip()


app.secret_key = _secret()

TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_WHATSAPP_NUMBER = os.environ.get(
    "TWILIO_WHATSAPP_NUMBER", "whatsapp:+14155238886"
)

twilio_client = None
if Client and TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
    try:
        twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    except Exception as e:
        print(f"Twilio init failed: {e}")
        twilio_client = None


SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS listings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK(type IN ('Room','Roommate','Sublet')),
  title TEXT NOT NULL, city TEXT NOT NULL, price REAL NOT NULL,
  description TEXT NOT NULL DEFAULT '', contact TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  payment_status TEXT NOT NULL DEFAULT 'pending',
  payment_method TEXT NOT NULL DEFAULT 'zelle',
  listing_fee REAL NOT NULL DEFAULT 20,
  application_fee REAL NOT NULL DEFAULT 15);
CREATE TABLE IF NOT EXISTS favorites(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id, listing_id));
CREATE TABLE IF NOT EXISTS login_attempts(
  ip TEXT, email TEXT, ts INTEGER);
"""


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    db_path = DB_PATH
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
        except PermissionError:
            db_path = os.path.join(BASE, "roommatch.db")
    c = sqlite3.connect(db_path)
    c.executescript(SCHEMA)
    c.commit()
    c.close()


init_db()


def err(msg, code=400):
    return jsonify(error=msg), code


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return db().execute(
        "SELECT id,email,name,is_admin FROM users WHERE id=?", (uid,)
    ).fetchone()


def require_json():
    if not request.is_json:
        return err("Expected JSON", 415)
    return None


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@app.post("/api/register")
def register():
    bad = require_json()
    if bad:
        return bad
    d = request.get_json(silent=True) or {}
    email = str(d.get("email", "")).strip()[:200]
    name = str(d.get("name", "")).strip()[:60]
    pw = str(d.get("password", ""))
    if not EMAIL_RE.match(email):
        return err("Enter a valid email.")
    if not name:
        return err("Enter your name.")
    if len(pw) < 8:
        return err("Password must be at least 8 characters.")
    try:
        cur = db().execute(
            "INSERT INTO users(email,name,password_hash,created_at) VALUES(?,?,?,?)",
            (email, name, generate_password_hash(pw), int(time.time())),
        )
        db().commit()
    except sqlite3.IntegrityError:
        return err("An account with that email already exists.", 409)
    session.clear()
    session.permanent = True
    session["uid"] = cur.lastrowid
    return jsonify(
        user=dict(id=cur.lastrowid, email=email, name=name, is_admin=0)
    ), 201


@app.post("/api/login")
def login():
    bad = require_json()
    if bad:
        return bad
    d = request.get_json(silent=True) or {}
    email = str(d.get("email", "")).strip()
    pw = str(d.get("password", ""))
    ip = request.remote_addr or ""
    now = int(time.time())
    c = db()
    c.execute("DELETE FROM login_attempts WHERE ts<?", (now - 900,))
    n = c.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE (ip=? OR email=?) AND ts>=?",
        (ip, email.lower(), now - 900),
    ).fetchone()[0]
    if n >= 10:
        c.commit()
        return err("Too many attempts. Try again in 15 minutes.", 429)
    u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not u or not check_password_hash(u["password_hash"], pw):
        c.execute(
            "INSERT INTO login_attempts VALUES(?,?,?)",
            (ip, email.lower(), now),
        )
        c.commit()
        return err("Incorrect email or password.", 401)
    session.clear()
    session.permanent = True
    session["uid"] = u["id"]
    return jsonify(
        user=dict(
            id=u["id"], email=u["email"], name=u["name"], is_admin=u["is_admin"]
        )
    )


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    u = current_user()
    if not u:
        return jsonify(user=None)
    return jsonify(
        user=dict(id=u["id"], email=u["email"], name=u["name"], is_admin=u["is_admin"])
    )


@app.get("/api/listings")
def listings():
    u = session.get("uid") or 0
    rows = db().execute(
        """SELECT l.id,l.type,l.title,l.city,l.price,
        l.description AS desc,l.contact,l.created_at,
        l.payment_status, l.payment_method, l.listing_fee, l.application_fee,
        u.name AS owner_name, (l.user_id=?) AS mine,
        EXISTS(SELECT 1 FROM favorites f WHERE f.listing_id=l.id AND f.user_id=?) AS saved
        FROM listings l JOIN users u ON u.id=l.user_id
        ORDER BY l.id DESC LIMIT 500""",
        (u, u),
    ).fetchall()
    return jsonify(listings=[dict(r) for r in rows])


@app.post("/api/listings")
def add_listing():
    u = current_user()
    if not u:
        return err("Please sign in.", 401)
    bad = require_json()
    if bad:
        return bad
    d = request.get_json(silent=True) or {}
    t = d.get("type")
    title = str(d.get("title", "")).strip()[:120]
    city = str(d.get("city", "")).strip()[:80]
    desc = str(d.get("desc", "")).strip()[:1000]
    contact = str(d.get("contact", "")).strip()[:120]
    try:
        price = float(d.get("price"))
    except (TypeError, ValueError):
        return err("Enter a valid price.")
    if (
        not math.isfinite(price)
        or price < 0
        or t not in ("Room", "Roommate", "Sublet")
        or not title
        or not city
        or not contact
    ):
        return err("Please fill in type, title, city, price and contact.")
    cur = db().execute(
        """INSERT INTO listings
        (user_id,type,title,city,price,description,contact,created_at,
         payment_status,payment_method,listing_fee,application_fee)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            u["id"], t, title, city, price, desc, contact, int(time.time()),
            "pending", "zelle", LISTING_FEE, APPLICATION_FEE,
        ),
    )
    db().commit()
    return jsonify(id=cur.lastrowid), 201


@app.delete("/api/listings/<int:lid>")
def del_listing(lid):
    u = current_user()
    if not u:
        return err("Please sign in.", 401)
    cur = db().execute(
        "DELETE FROM listings WHERE id=? AND user_id=?", (lid, u["id"])
    )
    db().commit()
    if cur.rowcount:
        return jsonify(ok=True)
    return err("Not found.", 404)


@app.put("/api/favorites/<int:lid>")
def fav(lid):
    u = current_user()
    if not u:
        return err("Please sign in.", 401)
    db().execute("INSERT OR IGNORE INTO favorites VALUES(?,?)", (u["id"], lid))
    db().commit()
    return jsonify(ok=True)


@app.delete("/api/favorites/<int:lid>")
def unfav(lid):
    u = current_user()
    if not u:
        return err("Please sign in.", 401)
    db().execute(
        "DELETE FROM favorites WHERE user_id=? AND listing_id=?",
        (u["id"], lid),
    )
    db().commit()
    return jsonify(ok=True)


@app.get("/api/listings/<int:lid>/payment")
def listing_payment(lid):
    u = current_user()
    if not u:
        return err("Please sign in.", 401)
    cur = db().execute(
        """SELECT user_id, payment_status, payment_method,
        listing_fee, application_fee FROM listings WHERE id=?""",
        (lid,),
    ).fetchone()
    if not cur:
        return err("Listing not found.", 404)
    if cur["user_id"] != u["id"] and not u["is_admin"]:
        return err("Access denied.", 403)
    return jsonify(
        payment_status=cur["payment_status"],
        payment_method=cur["payment_method"],
        listing_fee=cur["listing_fee"],
        application_fee=cur["application_fee"],
    )


@app.post("/api/listings/<int:lid>/confirm-payment")
def confirm_payment(lid):
    u = current_user()
    if not u:
        return err("Please sign in.", 401)
    if not u["is_admin"]:
        return err("Admin access required.", 403)
    db().execute(
        "UPDATE listings SET payment_status='paid' WHERE id=?", (lid,)
    )
    db().commit()
    return jsonify(ok=True, payment_status="paid")


@app.get("/api/payment-methods")
def payment_methods():
    methods = [
        {
            "key": "zelle",
            "name": "Zelle",
            "instructions": "Transfer to: roommatch@roommatch.example",
            "fee": LISTING_FEE,
        },
        {
            "key": "cashapp",
            "name": "CashApp",
            "instructions": "$RoomMatchHousing",
            "fee": LISTING_FEE,
        },
        {
            "key": "usdt",
            "name": "USDT (Tether)",
            "instructions": "Wallet: 0xRoomMatch123456789",
            "fee": LISTING_FEE,
        },
    ]
    return jsonify(methods=methods)


@app.post("/api/whatsapp/webhook")
def whatsapp_webhook():
    if not twilio_client:
        return err("Twilio not configured", 503)
    incoming_msg = request.form.get("Body", "")
    from_number = request.form.get("From", "")
    msg_lower = incoming_msg.lower().strip()
    response = None
    if "hello" in msg_lower or "hi" in msg_lower:
        response = (
            "Hello! Thanks for messaging RoomMatch. Type 'listings' to see "
            "available rooms or 'help' for options."
        )
    elif msg_lower == "listings":
        try:
            rows = db().execute(
                "SELECT id, title, city, price, type FROM listings "
                "ORDER BY created_at DESC LIMIT 5"
            ).fetchall()
            if rows:
                lines = [
                    f"{r['type']}: {r['title']} in {r['city']} - ${r['price']}/mo"
                    for r in rows
                ]
                response = "Recent listings:\n" + "\n".join(lines)
            else:
                response = "No listings currently available."
        except Exception as e:
            response = f"Error fetching listings: {e}"
    elif msg_lower == "help":
        response = (
            "Available commands:\n"
            "- hello/hi - Greeting\n"
            "- listings - Show available rooms\n"
            "- help - This help message"
        )
    else:
        response = (
            "I'm not sure how to respond to that. Type 'help' for available commands."
        )
    if response and twilio_client:
        try:
            twilio_client.messages.create(
                body=response, from_=TWILIO_WHATSAPP_NUMBER, to=from_number
            )
        except Exception as e:
            print(f"Twilio error: {e}")
    return jsonify(status="ok"), 200


@app.get("/api/whatsapp/status")
def whatsapp_status():
    return jsonify(
        status="active" if twilio_client else "inactive",
        twilio_configured=bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN),
    )


@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:"
    )
    if request.path.startswith("/api/"):
        r.headers["Cache-Control"] = "no-store"
    return r


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify(error="Not found"), 404
    return send_from_directory(app.static_folder, "index.html")


@app.errorhandler(500)
def internal_error(e):
    return jsonify(error="Internal server error"), 500


# ---------------------------------------------------------------------------
# SEED DATA
# ---------------------------------------------------------------------------

SEED_USERS = [
    # email, name, password, is_admin
    ("admin@roommatch.test", "Admin", "adminpass123", 1),
    ("alex@roommatch.test", "Alex Rivera", "password123", 0),
    ("jamie@roommatch.test", "Jamie Chen", "password123", 0),
    ("morgan@roommatch.test", "Morgan Patel", "password123", 0),
    ("taylor@roommatch.test", "Taylor Brooks", "password123", 0),
    ("casey@roommatch.test", "Casey Nguyen", "password123", 0),
    ("riley@roommatch.test", "Riley Johnson", "password123", 0),
    ("drew@roommatch.test", "Drew Martinez", "password123", 0),
]

# Each tuple: (owner_email, type, title, city, price, description, contact)
SEED_LISTINGS = [
    # ------------------------- ROOMS (12) -------------------------
    ("alex@roommatch.test", "Room",
     "Sunny Studio in Hell's Kitchen",
     "New York, NY", 1850,
     "Bright 1BR studio, hardwood floors, walk-in closet. Steps from the C/E "
     "subway. Building has gym, doorman, and roof deck. Utilities included.",
     "alex.rivera@email.com"),

    ("alex@roommatch.test", "Room",
     "Private Room in Downtown Brooklyn",
     "Brooklyn, NY", 1300,
     "Furnished private room in a 3BR walk-up, shared kitchen and bath with "
     "two friendly roommates. 5 min to Atlantic Terminal. Pet friendly.",
     "alex.rivera@email.com"),

    ("jamie@roommatch.test", "Room",
     "Quiet Room in Astoria",
     "Queens, NY", 1050,
     "Private room in a shared house, quiet street, off-street parking. "
     "Laundry on-site. 15 min walk to N/W. Non-smoking preferred.",
     "jamie.chen@email.com"),

    ("jamie@roommatch.test", "Room",
     "Modern 1BR in Capitol Hill",
     "Seattle, WA", 1750,
     "Modern 1BR with in-unit washer/dryer and balcony. Walk to Whole Foods "
     "and light rail. Cat okay with small deposit.",
     "jamie.chen@email.com"),

    ("morgan@roommatch.test", "Room",
     "Sunny Room Near UT Campus",
     "Austin, TX", 900,
     "Bright room in a 4BR house, 10 min bike to UT. Shared kitchen, backyard "
     "with grill. Utilities split evenly. Grad students welcome.",
     "morgan.patel@email.com"),

    ("morgan@roommatch.test", "Room",
     "Furnished Room in Wicker Park",
     "Chicago, IL", 1100,
     "Furnished room in a 2BR flat. Exposed brick, hardwood floors, walk to "
     "Blue Line. 1-year lease preferred, short-term considered.",
     "morgan.patel@email.com"),

    ("taylor@roommatch.test", "Room",
     "Room in Mission District Victorian",
     "San Francisco, CA", 2100,
     "Charming room in a 4BR Victorian. Shared kitchen with two roommates. "
     "Walk to BART, cafes, and Dolores Park. Clean and quiet household.",
     "taylor.brooks@email.com"),

    ("taylor@roommatch.test", "Room",
     "Private Room in Capitol Hill",
     "Denver, CO", 1200,
     "Private room in a townhouse. Shared living room, kitchen, and patio. "
     "Walk to Cheesman Park. Dog-friendly building.",
     "taylor.brooks@email.com"),

    ("casey@roommatch.test", "Room",
     "Ocean-view Room in Santa Monica",
     "Santa Monica, CA", 2200,
     "Light-filled room in a 2BR apartment, 3 blocks to the beach. Building "
     "has pool and gym. 6-month minimum. No pets, sorry.",
     "casey.nguyen@email.com"),

    ("casey@roommatch.test", "Room",
     "Cozy Room in Beacon Hill",
     "Boston, MA", 1500,
     "Historic brownstone, gas fireplace, bay windows. Shared with one other "
     "professional. Heat and hot water included. Walk to MGH.",
     "casey.nguyen@email.com"),

    ("riley@roommatch.test", "Room",
     "Modern Room Near Midtown",
     "Atlanta, GA", 1150,
     "Room in a new construction high-rise. Rooftop pool, gym, co-working "
     "lounge. 5 min walk to MARTA. Internet included.",
     "riley.johnson@email.com"),

    ("riley@roommatch.test", "Room",
     "Bright Room in Wynwood",
     "Miami, FL", 1400,
     "Bright room in a 2BR apartment near Wynwood Walls. Shared kitchen and "
     "living room. 10 min drive to the beach. Utilities included.",
     "riley.johnson@email.com"),

    # ------------------------- ROOMMATES (10) -------------------------
    ("drew@roommatch.test", "Roommate",
     "Looking for roommate in Bushwick",
     "Brooklyn, NY", 950,
     "Two professionals seeking a third to share a 3BR loft. Rent $950/mo + "
     "utilities. Clean, respectful, no drama. Must be employed and pet-free.",
     "drew.martinez@email.com"),

    ("drew@roommatch.test", "Roommate",
     "Female roommate wanted in Lakeview",
     "Chicago, IL", 900,
     "28F professional seeking a female roommate for a 2BR near Wrigley. Rent "
     "$900 + utilities. Night owl okay. Shared Netflix and coffee. Non-smoker.",
     "drew.martinez@email.com"),

    ("alex@roommatch.test", "Roommate",
     "Roommate needed in Silver Lake",
     "Los Angeles, CA", 1100,
     "Creative professional looking for a roommate for a 2BR bungalow. Rent "
     "$1100 + utilities. Vegetarian household. Street parking.",
     "alex.rivera@email.com"),

    ("jamie@roommatch.test", "Roommate",
     "Grad student seeking roommate",
     "Boston, MA", 1200,
     "PhD student looking for a quiet roommate in a 2BR in Cambridge. $1200/mo "
     "+ utilities. No parties. Study-heavy household. Cat okay.",
     "jamie.chen@email.com"),

    ("morgan@roommatch.test", "Roommate",
     "Roommate wanted in South Congress",
     "Austin, TX", 850,
     "Looking for a roommate for a 2BR near SoCo. $850 + utilities. Chill "
     "household, weekend BBQs. Must love dogs, we have one.",
     "morgan.patel@email.com"),

    ("taylor@roommatch.test", "Roommate",
     "Clean roommate needed in Fremont",
     "Seattle, WA", 1000,
     "Seeking a clean, respectful roommate for a 2BR near Google campus. "
     "$1000 + utilities. No smoking inside. Quiet weeknight household.",
     "taylor.brooks@email.com"),

    ("casey@roommatch.test", "Roommate",
     "Roommate for 2BR in Mission",
     "San Francisco, CA", 1600,
     "Looking for a friendly roommate in the Mission. $1600/mo + utilities. "
     "Shared kitchen and living room. 9-5 professional preferred.",
     "casey.nguyen@email.com"),

    ("riley@roommatch.test", "Roommate",
     "Roommate wanted in Capitol Hill",
     "Denver, CO", 800,
     "Three people looking for a fourth in a 4BR house. $800 + utilities. "
     "Shared chores, quiet household, mountain weekend trips.",
     "riley.johnson@email.com"),

    ("drew@roommatch.test", "Roommate",
     "Looking for a roommate near U Street",
     "Washington, DC", 1050,
     "Government professional seeking a roommate for a 2BR in Shaw. $1050 + "
     "utilities. Walk to metro. No pets, clean and quiet preferred.",
     "drew.martinez@email.com"),

    ("taylor@roommatch.test", "Roommate",
     "Roommate in Philadelphia for fall",
     "Philadelphia, PA", 750,
     "Seeking a roommate for a 2BR in Fishtown starting September. $750 + "
     "utilities. Bike-friendly, two cats. Monthly board game night.",
     "taylor.brooks@email.com"),

    # ------------------------- SUBLETS (8) -------------------------
    ("casey@roommatch.test", "Sublet",
     "Furnished sublet in Tribeca",
     "New York, NY", 3000,
     "Fully furnished 1BR sublet in a luxury building. 3-month lease, Feb-Apr. "
     "Doorman, gym, laundry. All utilities included.",
     "casey.nguyen@email.com"),

    ("casey@roommatch.test", "Sublet",
     "Summer sublet near Harvard",
     "Cambridge, MA", 1800,
     "Bright 1BR sublet, June-August. 5 min walk to Harvard Yard. Fully "
     "furnished with utilities included. Perfect for a summer internship.",
     "casey.nguyen@email.com"),

    ("alex@roommatch.test", "Sublet",
     "Short-term sublet in Bed-Stuy",
     "Brooklyn, NY", 1600,
     "Charming sublet in a historic brownstone. 6-month lease, flexible "
     "start. Hardwood floors, shared garden, cat-friendly.",
     "alex.rivera@email.com"),

    ("jamie@roommatch.test", "Sublet",
     "Sublet in Capitol Hill townhouse",
     "Seattle, WA", 1500,
     "Nice sublet in a Capitol Hill townhouse. 3-month lease. Close to bars, "
     "restaurants, and light rail. Utilities + WiFi included.",
     "jamie.chen@email.com"),

    ("morgan@roommatch.test", "Sublet",
     "Summer sublet in Logan Square",
     "Chicago, IL", 1200,
     "Furnished sublet, May-August. 1BR + office. Walk to Blue Line. Perfect "
     "for interns or summer travelers. No smoking.",
     "morgan.patel@email.com"),

    ("taylor@roommatch.test", "Sublet",
     "Downtown LA sublet with view",
     "Los Angeles, CA", 2000,
     "High-rise sublet with skyline views. 4-month lease. Pool, gym, valet "
     "parking. Walk to Crypto.com Arena and Whole Foods.",
     "taylor.brooks@email.com"),

    ("riley@roommatch.test", "Sublet",
     "Corporate sublet in Midtown",
     "New York, NY", 2800,
     "Corporate-style sublet, 1-month minimum. All utilities and weekly "
     "cleaning included. Steps from Grand Central.",
     "riley.johnson@email.com"),

    ("drew@roommatch.test", "Sublet",
     "Furnished sublet near Vanderbilt",
     "Nashville, TN", 1400,
     "3-month sublet, furnished, near Vanderbilt. 2BR townhome. Fenced "
     "backyard. Perfect for traveling nurses or visiting faculty.",
     "drew.martinez@email.com"),
]


def seed():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM listings")
    if c.fetchone()[0] > 0:
        print("Seed data already present — skipping.")
        conn.close()
        return

    print("Seeding demo users and listings...")
    email_to_id = {}
    now = int(time.time())

    for email, name, pw, is_admin in SEED_USERS:
        existing = c.execute(
            "SELECT id FROM users WHERE email=?", (email,)
        ).fetchone()
        if existing:
            email_to_id[email] = existing["id"]
            continue
        cur = c.execute(
            "INSERT INTO users(email,name,password_hash,created_at,is_admin) "
            "VALUES(?,?,?,?,?)",
            (email, name, generate_password_hash(pw), now, is_admin),
        )
        email_to_id[email] = cur.lastrowid

    # Insert listings; stagger created_at so the "Newest" sort is meaningful
    base_ts = now - (len(SEED_LISTINGS) * 3600)
    for i, (owner_email, ltype, title, city, price, desc, contact) in enumerate(SEED_LISTINGS):
        owner_id = email_to_id[owner_email]
        created = base_ts + (i * 3600)  # 1 hour apart, oldest first
        c.execute(
            """INSERT INTO listings
            (user_id, type, title, city, price, description, contact, created_at,
             payment_status, payment_method, listing_fee, application_fee)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (owner_id, ltype, title, city, price, desc, contact, created,
             "paid", "zelle", LISTING_FEE, APPLICATION_FEE),
        )

    conn.commit()
    counts = {
        row["type"]: row["n"]
        for row in c.execute(
            "SELECT type, COUNT(*) AS n FROM listings GROUP BY type"
        ).fetchall()
    }
    conn.close()

    print(
        f"Seeded {len(SEED_USERS)} users and {len(SEED_LISTINGS)} listings "
        f"({counts.get('Room', 0)} rooms, "
        f"{counts.get('Roommate', 0)} roommates, "
        f"{counts.get('Sublet', 0)} sublets)."
    )
    print("Demo logins (password shown after email):")
    for email, _, pw, is_admin in SEED_USERS:
        tag = " [admin]" if is_admin else ""
        print(f"  {email} / {pw}{tag}")


if __name__ == "__main__":
    seed()
    print("\nRoomMatch running at http://localhost:5000\n")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
