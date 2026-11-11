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
            "instructions": "Transfer to: payments@roommatch.app",
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
# INITIAL INVENTORY
#
# Populates a fresh database with real, ready-to-browse listings on first
# startup. Idempotent: if any listings already exist, this does nothing.
#
# Ops note — account passwords (change after first deploy):
#   admin@roommatch.app  / adminpass123   (admin)
#   All other accounts:   / password123
# ---------------------------------------------------------------------------

INITIAL_USERS = [
    # email, name, password, is_admin
    ("admin@roommatch.app", "Jordan Ellis", "adminpass123", 1),
    ("alex.rivera@roommatch.app", "Alex Rivera", "password123", 0),
    ("jamie.chen@roommatch.app", "Jamie Chen", "password123", 0),
    ("morgan.patel@roommatch.app", "Morgan Patel", "password123", 0),
    ("taylor.brooks@roommatch.app", "Taylor Brooks", "password123", 0),
    ("casey.nguyen@roommatch.app", "Casey Nguyen", "password123", 0),
    ("riley.johnson@roommatch.app", "Riley Johnson", "password123", 0),
    ("drew.martinez@roommatch.app", "Drew Martinez", "password123", 0),
    ("priya.sharma@roommatch.app", "Priya Sharma", "password123", 0),
    ("marcus.williams@roommatch.app", "Marcus Williams", "password123", 0),
    ("sofia.reyes@roommatch.app", "Sofia Reyes", "password123", 0),
    ("ethan.kim@roommatch.app", "Ethan Kim", "password123", 0),
]

# (owner_email, type, title, city, price, description, contact, days_ago)
INITIAL_LISTINGS = [
    # ------------------------------ ROOMS ------------------------------
    ("alex.rivera@roommatch.app", "Room",
     "Sunny Studio in Hell's Kitchen",
     "New York, NY", 1850,
     "Bright 1BR studio with hardwood floors, walk-in closet, and a small "
     "kitchenette. Steps from the C/E subway. Building has a gym, doorman, "
     "and shared roof deck. Heat and hot water included. Available now.",
     "alex.rivera@roommatch.app", 2),

    ("alex.rivera@roommatch.app", "Room",
     "Private Room in Downtown Brooklyn",
     "Brooklyn, NY", 1300,
     "Furnished private room in a 3BR walk-up shared with two friendly "
     "roommates. Shared kitchen and bath. 5 minutes to Atlantic Terminal "
     "(2/3/4/5/B/D/N/Q/R). Pet-friendly building, laundry in basement.",
     "alex.rivera@roommatch.app", 4),

    ("jamie.chen@roommatch.app", "Room",
     "Quiet Room in Astoria",
     "Queens, NY", 1050,
     "Private room in a shared house on a quiet tree-lined street. "
     "Off-street parking, laundry on-site. 15-minute walk to the N/W. "
     "Non-smoking preferred. Utilities split evenly among three tenants.",
     "jamie.chen@roommatch.app", 5),

    ("jamie.chen@roommatch.app", "Room",
     "Modern 1BR in Capitol Hill",
     "Seattle, WA", 1750,
     "Modern 1BR with in-unit washer/dryer, stainless appliances, and a "
     "private balcony. Walk to Whole Foods and the light rail. Cat okay "
     "with a small deposit. 12-month lease, move-in ready.",
     "jamie.chen@roommatch.app", 6),

    ("morgan.patel@roommatch.app", "Room",
     "Sunny Room Near UT Campus",
     "Austin, TX", 900,
     "Bright room in a 4BR house, 10-minute bike to UT Austin. Shared "
     "kitchen and backyard with grill. Utilities split evenly. Grad "
     "students and young professionals welcome. Available for fall semester.",
     "morgan.patel@roommatch.app", 3),

    ("morgan.patel@roommatch.app", "Room",
     "Furnished Room in Wicker Park",
     "Chicago, IL", 1100,
     "Furnished room in a 2BR flat with exposed brick and hardwood floors. "
     "Walk to the Blue Line. 1-year lease preferred, short-term considered "
     "for the right fit. No pets.",
     "morgan.patel@roommatch.app", 8),

    ("taylor.brooks@roommatch.app", "Room",
     "Room in Mission District Victorian",
     "San Francisco, CA", 2100,
     "Charming room in a 4BR Victorian shared with two roommates. Shared "
     "kitchen with gas range. Walk to BART, cafes, and Dolores Park. Clean, "
     "quiet household. Utilities and internet included.",
     "taylor.brooks@roommatch.app", 1),

    ("taylor.brooks@roommatch.app", "Room",
     "Private Room in Capitol Hill",
     "Denver, CO", 1200,
     "Private room in a townhouse with shared living room, kitchen, and "
     "patio. Walk to Cheesman Park. Dog-friendly building. Two blocks to "
     "the 12 bus. Utilities + WiFi included.",
     "taylor.brooks@roommatch.app", 7),

    ("casey.nguyen@roommatch.app", "Room",
     "Ocean-view Room in Santa Monica",
     "Santa Monica, CA", 2200,
     "Light-filled room in a 2BR apartment, 3 blocks to the beach. Building "
     "has a pool and gym. 6-month minimum. No pets, sorry. Utilities "
     "included. Perfect for a remote worker.",
     "casey.nguyen@roommatch.app", 9),

    ("casey.nguyen@roommatch.app", "Room",
     "Cozy Room in Beacon Hill",
     "Boston, MA", 1500,
     "Historic brownstone with gas fireplace and bay windows. Shared with "
     "one other professional. Heat and hot water included. Walk to MGH "
     "and the Red Line. Available September 1.",
     "casey.nguyen@roommatch.app", 10),

    ("riley.johnson@roommatch.app", "Room",
     "Modern Room Near Midtown",
     "Atlanta, GA", 1150,
     "Room in a new construction high-rise with rooftop pool, gym, and "
     "co-working lounge. 5-minute walk to MARTA. Internet included. "
     "12-month lease. Garage parking available for $75/mo.",
     "riley.johnson@roommatch.app", 11),

    ("riley.johnson@roommatch.app", "Room",
     "Bright Room in Wynwood",
     "Miami, FL", 1400,
     "Bright room in a 2BR apartment near Wynwood Walls. Shared kitchen "
     "and living room. 10-minute drive to the beach. Utilities included. "
     "Furnished common areas, unfurnished bedroom.",
     "riley.johnson@roommatch.app", 12),

    ("priya.sharma@roommatch.app", "Room",
     "Furnished Room in Nob Hill",
     "San Francisco, CA", 1950,
     "Furnished room in a 3BR flat in Nob Hill. Shared with two quiet "
     "professionals. Cable car at the corner, walk to Union Square. "
     "Utilities + internet included. No smoking.",
     "priya.sharma@roommatch.app", 3),

    ("marcus.williams@roommatch.app", "Room",
     "Private Room in Queen Village",
     "Philadelphia, PA", 850,
     "Private room in a 3BR rowhouse shared with two roommates. Fenced "
     "backyard, washer/dryer in unit. Walk to South Street and the Italian "
     "Market. Cat okay. Utilities split three ways.",
     "marcus.williams@roommatch.app", 6),

    ("sofia.reyes@roommatch.app", "Room",
     "Sunny Room in North Loop",
     "Minneapolis, MN", 950,
     "Sunny room in a modern 2BR near Target Field. Shared with one other "
     "professional. In-unit laundry, bike storage, rooftop deck. Winter "
     "is cozy thanks to great insulation. Available now.",
     "sofia.reyes@roommatch.app", 4),

    ("ethan.kim@roommatch.app", "Room",
     "Room Near Pearl District",
     "Portland, OR", 1100,
     "Room in a bright 2BR loft in the Pearl District. Shared with one "
     "roommate. Walk to Powell's Books, breweries, and the streetcar. "
     "Bike storage in the building. No pets.",
     "ethan.kim@roommatch.app", 8),

    # ---------------------------- ROOMMATES ----------------------------
    ("drew.martinez@roommatch.app", "Roommate",
     "Looking for a roommate in Bushwick",
     "Brooklyn, NY", 950,
     "Two professionals seeking a third to share a 3BR loft. Rent $950/mo "
     "+ utilities. Clean, respectful, no drama. Must be employed and "
     "pet-free. Move-in October 1, 12-month lease.",
     "drew.martinez@roommatch.app", 1),

    ("drew.martinez@roommatch.app", "Roommate",
     "Female roommate wanted in Lakeview",
     "Chicago, IL", 900,
     "28F professional seeking a female roommate for a 2BR near Wrigley "
     "Field. Rent $900 + utilities. Night owl okay. Shared Netflix and "
     "coffee. Non-smoker preferred, no pets.",
     "drew.martinez@roommatch.app", 5),

    ("alex.rivera@roommatch.app", "Roommate",
     "Roommate needed in Silver Lake",
     "Los Angeles, CA", 1100,
     "Creative professional looking for a roommate for a 2BR bungalow. "
     "Rent $1100 + utilities. Vegetarian household. Street parking. "
     "Backyard with lemon tree. Move-in ASAP.",
     "alex.rivera@roommatch.app", 2),

    ("jamie.chen@roommatch.app", "Roommate",
     "Grad student seeking roommate",
     "Boston, MA", 1200,
     "PhD student looking for a quiet roommate in a 2BR in Cambridge. "
     "$1200/mo + utilities. No parties. Study-heavy household. Cat okay. "
     "Walk to Harvard and MIT shuttles.",
     "jamie.chen@roommatch.app", 7),

    ("morgan.patel@roommatch.app", "Roommate",
     "Roommate wanted in South Congress",
     "Austin, TX", 850,
     "Looking for a roommate for a 2BR near SoCo. $850 + utilities. Chill "
     "household, weekend BBQs. Must love dogs—we have one. Street parking. "
     "6-month minimum.",
     "morgan.patel@roommatch.app", 3),

    ("taylor.brooks@roommatch.app", "Roommate",
     "Clean roommate needed in Fremont",
     "Seattle, WA", 1000,
     "Seeking a clean, respectful roommate for a 2BR near the Google "
     "campus. $1000 + utilities. No smoking inside. Quiet weeknight "
     "household. Move-in October 15.",
     "taylor.brooks@roommatch.app", 9),

    ("casey.nguyen@roommatch.app", "Roommate",
     "Roommate for 2BR in the Mission",
     "San Francisco, CA", 1600,
     "Looking for a friendly roommate in the Mission. $1600/mo + "
     "utilities. Shared kitchen and living room. 9-to-5 professional "
     "preferred. No pets. Laundry in unit.",
     "casey.nguyen@roommatch.app", 4),

    ("riley.johnson@roommatch.app", "Roommate",
     "Roommate wanted in Capitol Hill",
     "Denver, CO", 800,
     "Three people looking for a fourth in a 4BR house. $800 + utilities. "
     "Shared chores, quiet household, mountain weekend trips. Garage "
     "parking. Dog-friendly.",
     "riley.johnson@roommatch.app", 6),

    ("drew.martinez@roommatch.app", "Roommate",
     "Looking for a roommate near U Street",
     "Washington, DC", 1050,
     "Government professional seeking a roommate for a 2BR in Shaw. "
     "$1050 + utilities. Walk to metro. No pets, clean and quiet "
     "preferred. Move-in November 1.",
     "drew.martinez@roommatch.app", 10),

    ("taylor.brooks@roommatch.app", "Roommate",
     "Roommate in Philadelphia for fall",
     "Philadelphia, PA", 750,
     "Seeking a roommate for a 2BR in Fishtown starting September. $750 + "
     "utilities. Bike-friendly, two cats. Monthly board game night. "
     "Garden out back.",
     "taylor.brooks@roommatch.app", 11),

    ("priya.sharma@roommatch.app", "Roommate",
     "Roommate wanted in Logan Square",
     "Chicago, IL", 1050,
     "31F seeking a roommate for a 2BR in Logan Square. $1050 + utilities. "
     "Non-smoker, no pets. Shared kitchen and living room. Walk to the "
     "Blue Line. 12-month lease.",
     "priya.sharma@roommatch.app", 2),

    ("marcus.williams@roommatch.app", "Roommate",
     "Roommate for 2BR in Williamsburg",
     "Brooklyn, NY", 1400,
     "Looking for a roommate for a 2BR in Williamsburg. $1400 + utilities. "
     "Shared with one other professional. Walk to the L train. No pets, "
     "non-smoker. Move-in October.",
     "marcus.williams@roommatch.app", 5),

    ("sofia.reyes@roommatch.app", "Roommate",
     "Female roommate wanted in Uptown",
     "Minneapolis, MN", 800,
     "27F seeking a female roommate for a 2BR in Uptown. $800 + utilities. "
     "Cat-friendly, quiet household. Walk to Lake Calhoun. Non-smoker.",
     "sofia.reyes@roommatch.app", 8),

    ("ethan.kim@roommatch.app", "Roommate",
     "Roommate near Hawthorne",
     "Portland, OR", 950,
     "Seeking a roommate for a 2BR near Hawthorne. $950 + utilities. "
     "Bike storage, garden in back. Quiet weeknight household, weekend "
     "hiking. Non-smoker, no pets.",
     "ethan.kim@roommatch.app", 12),

    # ----------------------------- SUBLETS -----------------------------
    ("casey.nguyen@roommatch.app", "Sublet",
     "Furnished sublet in Tribeca",
     "New York, NY", 3000,
     "Fully furnished 1BR sublet in a luxury building. 3-month lease, "
     "Feb–Apr. Doorman, gym, laundry. All utilities included. Steps from "
     "the 1/2/3 and A/C/E. Perfect for a short-term work assignment.",
     "casey.nguyen@roommatch.app", 1),

    ("casey.nguyen@roommatch.app", "Sublet",
     "Summer sublet near Harvard",
     "Cambridge, MA", 1800,
     "Bright 1BR sublet, June–August. 5-minute walk to Harvard Yard. "
     "Fully furnished with utilities included. Perfect for a summer "
     "internship. Central AC, in-unit laundry.",
     "casey.nguyen@roommatch.app", 4),

    ("alex.rivera@roommatch.app", "Sublet",
     "Short-term sublet in Bed-Stuy",
     "Brooklyn, NY", 1600,
     "Charming sublet in a historic brownstone. 6-month lease, flexible "
     "start. Hardwood floors, shared garden, cat-friendly. Walk to the "
     "A/C and J/M/Z. Utilities included.",
     "alex.rivera@roommatch.app", 7),

    ("jamie.chen@roommatch.app", "Sublet",
     "Sublet in Capitol Hill townhouse",
     "Seattle, WA", 1500,
     "Nice sublet in a Capitol Hill townhouse. 3-month lease. Close to "
     "bars, restaurants, and light rail. Utilities + WiFi included. "
     "Furnished with a queen bed and desk.",
     "jamie.chen@roommatch.app", 9),

    ("morgan.patel@roommatch.app", "Sublet",
     "Summer sublet in Logan Square",
     "Chicago, IL", 1200,
     "Furnished sublet, May–August. 1BR + office. Walk to the Blue Line. "
     "Perfect for interns or summer travelers. No smoking. Utilities "
     "included. AC in every room.",
     "morgan.patel@roommatch.app", 11),

    ("taylor.brooks@roommatch.app", "Sublet",
     "Downtown LA sublet with view",
     "Los Angeles, CA", 2000,
     "High-rise sublet with skyline views. 4-month lease. Pool, gym, "
     "valet parking. Walk to Crypto.com Arena and Whole Foods. Furnished, "
     "utilities included.",
     "taylor.brooks@roommatch.app", 2),

    ("riley.johnson@roommatch.app", "Sublet",
     "Corporate sublet in Midtown",
     "New York, NY", 2800,
     "Corporate-style sublet, 1-month minimum. All utilities and weekly "
     "cleaning included. Steps from Grand Central. Furnished with a queen "
     "bed and workspace. Perfect for business travel.",
     "riley.johnson@roommatch.app", 5),

    ("drew.martinez@roommatch.app", "Sublet",
     "Furnished sublet near Vanderbilt",
     "Nashville, TN", 1400,
     "3-month sublet, furnished, near Vanderbilt. 2BR townhome. Fenced "
     "backyard. Perfect for traveling nurses or visiting faculty. "
     "Utilities + WiFi included.",
     "drew.martinez@roommatch.app", 8),

    ("priya.sharma@roommatch.app", "Sublet",
     "Sublet in Pacific Heights",
     "San Francisco, CA", 2400,
     "Furnished 1BR sublet in Pacific Heights, 3-month lease. Walk to "
     "Fillmore Street and the Presidio. Utilities included. No pets. "
     "Perfect for a short-term relocation.",
     "priya.sharma@roommatch.app", 3),

    ("marcus.williams@roommatch.app", "Sublet",
     "Summer sublet in Old City",
     "Philadelphia, PA", 1300,
     "Furnished 1BR sublet in Old City, June–August. Walk to Independence "
     "Hall and the Market–Frankford line. Utilities included. Ideal for "
     "summer interns.",
     "marcus.williams@roommatch.app", 6),

    ("sofia.reyes@roommatch.app", "Sublet",
     "Winter sublet in North Loop",
     "Minneapolis, MN", 1100,
     "Furnished 1BR sublet in the North Loop, December–February. Walk to "
     "Target Field and the light rail. Utilities included. Perfect for "
     "a winter contract.",
     "sofia.reyes@roommatch.app", 10),

    ("ethan.kim@roommatch.app", "Sublet",
     "Sublet near Alberta Arts",
     "Portland, OR", 1250,
     "Furnished 1BR sublet near Alberta Arts, 3-month lease. Walk to "
     "coffee shops and galleries. Utilities included. Bike storage in "
     "the basement.",
     "ethan.kim@roommatch.app", 12),

    ("alex.rivera@roommatch.app", "Sublet",
     "Short-term sublet in Astoria",
     "Queens, NY", 1450,
     "Furnished 1BR sublet in Astoria, 2-month minimum. Walk to the N/W. "
     "Utilities included. Great for a short NYC stay. No pets. Available "
     "immediately.",
     "alex.rivera@roommatch.app", 13),

    ("jamie.chen@roommatch.app", "Sublet",
     "Fall sublet in Ballard",
     "Seattle, WA", 1400,
     "Furnished 1BR sublet in Ballard, September–November. Walk to the "
     "Sunday Farmers Market and breweries. Utilities included. No pets. "
     "Quiet street.",
     "jamie.chen@roommatch.app", 14),
]


def load_initial_inventory():
    """Populate a fresh database with listings on first startup.

    Idempotent: if any listings already exist, this returns immediately
    without touching the database.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    existing = c.execute("SELECT COUNT(*) FROM listings").fetchone()[0]
    if existing > 0:
        conn.close()
        return

    now = int(time.time())
    email_to_id = {}

    for email, name, pw, is_admin in INITIAL_USERS:
        row = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if row:
            email_to_id[email] = row["id"]
            continue
        cur = c.execute(
            "INSERT INTO users(email,name,password_hash,created_at,is_admin) "
            "VALUES(?,?,?,?,?)",
            (email, name, generate_password_hash(pw), now, is_admin),
        )
        email_to_id[email] = cur.lastrowid

    for owner_email, ltype, title, city, price, desc, contact, days_ago in INITIAL_LISTINGS:
        owner_id = email_to_id[owner_email]
        created = now - (days_ago * 86400) + (hash(title) % 3600)
        c.execute(
            """INSERT INTO listings
            (user_id, type, title, city, price, description, contact, created_at,
             payment_status, payment_method, listing_fee, application_fee)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (owner_id, ltype, title, city, price, desc, contact, created,
             "paid", "zelle", LISTING_FEE, APPLICATION_FEE),
        )

    conn.commit()
    total = c.execute("SELECT COUNT(*) FROM listings").fetchone()[0]
    conn.close()
    print(f"Inventory loaded: {total} listings across {len(INITIAL_USERS)} accounts.")


# Load inventory on every app startup. Idempotent — skips if data exists.
# Runs under gunicorn/WSGI as well as `python app.py`.
try:
    load_initial_inventory()
except Exception as e:
    print(f"Inventory load skipped: {e}")


if __name__ == "__main__":
    print("\nRoomMatch running at http://localhost:5000\n")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
