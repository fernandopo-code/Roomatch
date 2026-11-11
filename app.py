import os, re, secrets, sqlite3, time, math
from flask import Flask, g, jsonify, request, session, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.rest import Client

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "roommatch.db"))
LISTING_FEE = 20

app = Flask(__name__, static_folder="static", static_url_path="")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",  # set to 1 behind HTTPS
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
# Twilio WhatsApp config
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_WHATSAPP_NUMBER = os.environ.get("TWILIO_WHATSAPP_NUMBER", "whatsapp:+14155238886")
twilio_client = None
if Client and TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
    twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

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
    if d: d.close()

def init_db():
    # Determine the database path, fallback to local if /data is not writable
    db_path = DB_PATH
    # Ensure the directory for the database exists
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
        except PermissionError:
            # Fall back to local database if /data is not writable (e.g., Render without persistent disk)
            db_path = os.path.join(BASE, "roommatch.db")
    c = sqlite3.connect(db_path)
    c.executescript(SCHEMA); c.commit(); c.close()
init_db()

def err(msg, code=400):
    return jsonify(error=msg), code

def current_user():
    uid = session.get("uid")
    if not uid: return None
    return db().execute("SELECT id,email,name FROM users WHERE id=?", (uid,)).fetchone()

def require_json():
    # JSON-only writes + SameSite cookies blocks cross-site form CSRF
    if not request.is_json: return err("Expected JSON", 415)
    return None

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

@app.post("/api/register")
def register():
    bad = require_json()
    if bad: return bad
    d = request.get_json(silent=True) or {}
    email = str(d.get("email", "")).strip()[:200]; name = str(d.get("name", "")).strip()[:60]
    pw = str(d.get("password", ""))
    if not EMAIL_RE.match(email): return err("Enter a valid email.")
    if not name: return err("Enter your name.")
    if len(pw) < 8: return err("Password must be at least 8 characters.")
    try:
        cur = db().execute("INSERT INTO users(email,name,password_hash,created_at) VALUES(?,?,?,?)",
                           (email, name, generate_password_hash(pw), int(time.time())))
        db().commit()
    except sqlite3.IntegrityError:
        return err("An account with that email already exists.", 409)
    session.clear(); session.permanent = True; session["uid"] = cur.lastrowid
    return jsonify(user=dict(id=cur.lastrowid, email=email, name=name)), 201

@app.post("/api/login")
def login():
    bad = require_json()
    if bad: return bad
    d = request.get_json(silent=True) or {}
    email = str(d.get("email", "")).strip(); pw = str(d.get("password", ""))
    ip = request.remote_addr or ""; now = int(time.time())
    c = db()
    c.execute("DELETE FROM login_attempts WHERE ts<?", (now - 900,))
    n = c.execute("SELECT COUNT(*) FROM login_attempts WHERE (ip=? OR email=?) AND ts>=?", (ip, email.lower(), now - 900)).fetchone()[0]
    if n >= 10:
        c.commit(); return err("Too many attempts. Try again in 15 minutes.", 429)
    u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not u or not check_password_hash(u["password_hash"], pw):
        c.execute("INSERT INTO login_attempts VALUES(?,?,?)", (ip, email.lower(), now)); c.commit()
        return err("Incorrect email or password.", 401)
    session.clear(); session.permanent = True; session["uid"] = u["id"]
    return jsonify(user=dict(id=u["id"], email=u["email"], name=u["name"]))

@app.post("/api/logout")
def logout():
    session.clear(); return jsonify(ok=True)

@app.post("/api/whatsapp/webhook")
def whatsapp_webhook():
    """Handle incoming WhatsApp messages via Twilio webhook."""
    if not twilio_client:
        return err("Twilio not configured", 503)
    
    incoming_msg = request.form.get("Body", "")
    from_number = request.form.get("From", "")
    
    # Parse the message and respond
    msg_lower = incoming_msg.lower().strip()
    
    # Simple response logic
    response = None
    if "hello" in msg_lower or "hi" in msg_lower:
        response = "Hello! Thanks for messaging RoomMatch. Type 'listings' to see available rooms or 'help' for options."
    elif msg_lower == "listings":
        # Fetch recent listings and send back
        try:
            rows = db().execute("SELECT id, title, city, price, type FROM listings ORDER BY created_at DESC LIMIT 5").fetchall()
            if rows:
                listing_summaries = []
                for row in rows:
                    listing_summaries.append(f"{row['type']}: {row['title']} in {row['city']} - ${row['price']}/mo")
                response = "Recent listings:\n" + "\n".join(listing_summaries)
            else:
                response = "No listings currently available."
        except Exception as e:
            response = f"Error fetching listings: {str(e)}"
    elif msg_lower == "help":
        response = "Available commands:\n- hello/hi - Greeting\n- listings - Show available rooms\n- help - This help message\n- contact [id] - Contact listing owner"
    else:
        response = "I'm not sure how to respond to that. Type 'help' for available commands."
    
    # Send response via Twilio
    if response and twilio_client:
        try:
            message = twilio_client.messages.create(
                body=response,
                from_=TWILIO_WHATSAPP_NUMBER,
                to=from_number
            )
        except Exception as e:
            print(f"Twilio error: {e}")
    
    return jsonify(status="ok"), 200

@app.get("/api/whatsapp/status")
def whatsapp_status():
    """Check WhatsApp service status."""
    if twilio_client:
        return jsonify(status="active", twilio_configured=bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN))
    return jsonify(status="inactive", twilio_configured=False)

@app.get("/api/listings/<int:lid>/payment")
def listing_payment(lid):
    """Check payment status for a listing."""
    u = current_user()
    if not u: return err("Please sign in.", 401)
    cur = db().execute("SELECT payment_status, payment_method, listing_fee, application_fee FROM listings WHERE id=?", (lid,)).fetchone()
    if not cur: return err("Listing not found.", 404)
    if cur["user_id"] != u["id"] and not u.get("is_admin", False): return err("Access denied.", 403)
    return jsonify({
        "payment_status": cur["payment_status"],
        "payment_method": cur["payment_method"],
        "listing_fee": cur["listing_fee"],
        "application_fee": cur["application_fee"]
    })

@app.post("/api/listings/<int:lid>/confirm-payment")
def confirm_payment(lid):
    """Mark payment as complete (admin only)."""
    u = current_user()
    if not u: return err("Please sign in.", 401)
    if not u.get("is_admin", False): return err("Admin access required.", 403)
    db().execute("UPDATE listings SET payment_status='paid' WHERE id=?", (lid,))
    db().commit()
    return jsonify(ok=True, payment_status="paid")

@app.get("/api/payment-methods")
def payment_methods():
    """Get available payment methods and instructions."""
    methods = [
        {
            "key": "zelle",
            "name": "Zelle",
            "instructions": "Transfer to: roommatch@roommatch.example",
            "fee": LISTING_FEE
        },
        {
            "key": "cashapp",
            "name": "CashApp",
            "instructions": "$RoomMatchHousing",
            "fee": LISTING_FEE
        },
        {
            "key": "usdt",
            "name": "USDT (Tether)",
            "instructions": "Wallet: 0xRoomMatch123456789",
            "fee": LISTING_FEE
        }
    ]
    return jsonify(methods=methods)
@app.get("/api/me")
def me():
    u = current_user()
    return jsonify(user=dict(u) if u else None)

@app.get("/api/listings")
def listings():
    u = session.get("uid") or 0
    rows = db().execute("""SELECT l.id,l.type,l.title,l.city,l.price,l.description AS desc,l.contact,l.created_at,
        u.name AS owner_name, (l.user_id=?) AS mine,
        EXISTS(SELECT 1 FROM favorites f WHERE f.listing_id=l.id AND f.user_id=?) AS saved
        FROM listings l JOIN users u ON u.id=l.user_id ORDER BY l.id DESC LIMIT 500""", (u, u)).fetchall()
    return jsonify(listings=[dict(r) for r in rows])

LISTING_FEE = 20
APPLICATION_FEE = 15

@app.post("/api/listings")
def add_listing():
    u = current_user()
    if not u: return err("Please sign in.", 401)
    bad = require_json()
    if bad: return bad
    d = request.get_json(silent=True) or {}
    t = d.get("type"); title = str(d.get("title", "")).strip()[:120]; city = str(d.get("city", "")).strip()[:80]
    desc = str(d.get("desc", "")).strip()[:1000]; contact = str(d.get("contact", "")).strip()[:120]
    try: price = float(d.get("price"))
    except (TypeError, ValueError): return err("Enter a valid price.")
    if not math.isfinite(price) or price < 0 or t not in ("Room", "Roommate", "Sublet") or not title or not city or not contact:
        return err("Please fill in type, title, city, price and contact.")
    cur = db().execute("INSERT INTO listings(user_id,type,title,city,price,description,contact,created_at,payment_status,payment_method,listing_fee,application_fee) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                       (u["id"], t, title, city, price, desc, contact, int(time.time()), "paid", "zelle", LISTING_FEE, APPLICATION_FEE))
    db().commit()
    return jsonify(id=cur.lastrowid), 201

@app.delete("/api/listings/<int:lid>")
def del_listing(lid):
    u = current_user()
    if not u: return err("Please sign in.", 401)
    cur = db().execute("DELETE FROM listings WHERE id=? AND user_id=?", (lid, u["id"])); db().commit()
    return jsonify(ok=True) if cur.rowcount else err("Not found.", 404)

@app.put("/api/favorites/<int:lid>")
def fav(lid):
    u = current_user()
    if not u: return err("Please sign in.", 401)
    db().execute("INSERT OR IGNORE INTO favorites VALUES(?,?)", (u["id"], lid)); db().commit()
    return jsonify(ok=True)

@app.delete("/api/favorites/<int:lid>")
def unfav(lid):
    u = current_user()
    if not u: return err("Please sign in.", 401)
    db().execute("DELETE FROM favorites WHERE user_id=? AND listing_id=?", (u["id"], lid)); db().commit()
    return jsonify(ok=True)

@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
    if request.path.startswith("/api/"):
        r.headers["Cache-Control"] = "no-store"
    return r

@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.errorhandler(404)
def not_found(e):
    return jsonify(error="Not found"), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify(error="Internal server error"), 500

if __name__ == "__main__":
    init_db()
    # Seed sample data if database is empty
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM listings")
    count = c.fetchone()[0]
    if count == 0:
        # Insert sample users first (needed for foreign key constraints)
        c.execute("INSERT OR IGNORE INTO users (email, name, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?, ?)",
                  ('admin@roommatch.test', 'Admin', 'hashed', 1700000000, 1))
        c.execute("INSERT OR IGNORE INTO users (email, name, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?, ?)",
                  ('user1@roommatch.test', 'John Doe', 'hashed', 1700000000, 0))
        c.execute("INSERT OR IGNORE INTO users (email, name, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?, ?)",
                  ('user2@roommatch.test', 'Jane Smith', 'hashed', 1700000000, 0))
        # Now insert sample listings - Rooms (type=1), Roommates (type=2), Sublets (type=3)
        # Each: (user_id, type, title, city, price, description, contact)
        sample_listings = [
            # Rooms - user_id=1
            (1, "Room", "Cozy Studio in Manhattan", "New York", 1800,
             "Sunny 1BR studio in Hell's Kitchen, modern appliances, gym access",
             "john.doe@email.com"),
            (1, "Room", "Downtown Brooklyn Apartment", "New York", 1500,
             "2BR apartment in Downtown Brooklyn, close to transit, pet-friendly",
             "jane.smith@email.com"),
            (1, "Room", "Quiet Room in Queens", "New York", 950,
             "Private room in shared house, quiet neighborhood, parking available",
             "mike.brown@email.com"),
            (1, "Room", "Luxury Upper West Side", "New York", 2200,
             "Executive studio with doorman, concierge, fitness center",
             "lisa.white@email.com"),
            # Roommates - user_id=2
            (2, "Roommate", "Looking for roommate in Manhattan", "New York", 800,
             "Male roommate wanted, clean, non-smoker, $800 share",
             "roommate.seek@email.com"),
            (2, "Roommate", "Female roommate needed in Brooklyn", "New York", 750,
             "Friendly female roommate, $750/month, close to subway",
             "roommate2.seek@email.com"),
            (2, "Roommate", "Silent roommate needed in Queens", "New York", 650,
             "Looking for quiet professional roommate, $650/month",
             "quiet.roommate@email.com"),
            # Sublets - user_id=3
            (3, "Sublet", "Fully furnished sublet in Tribeca", "New York", 3000,
             "Fully furnished 1BR sublet, 3-month lease, luxury building",
             "sublet.tribeca@email.com"),
            (3, "Sublet", "Short-term sublet in Bed-Stuy", "New York", 1600,
             "Charming sublet in historic Brownstone, 6-month lease",
             "sublet.bedstuy@email.com"),
            (3, "Sublet", "Corporate sublet in Midtown", "New York", 2800,
             "Corporate housing, 1-month minimum, all utilities included",
             "corporate.sublet@email.com"),
        ]
        for user_id, lst_type, title, city, price, desc, contact in sample_listings:
            c.execute("""INSERT INTO listings
                       (user_id, type, title, city, price, description, contact, created_at,
                        payment_status, payment_method, listing_fee, application_fee)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (user_id, lst_type, title, city, price, desc, contact,
                       1700000000, 'pending', 'zelle', 20, 15))
        conn.commit()
        print("Added " + str(len(sample_listings)) + " sample NYC listings!")
    else:
        print("Listings already exist - skipping seed data.")
    conn.close()
    
    print("\nDatabase seeding complete!")
    print("Run 'python app.py' to start the RoomMatch server.")
