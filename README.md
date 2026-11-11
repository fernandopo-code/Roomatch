# RoomMatch – roommate, room & sublet listings (Flask + SQLite)

## Run locally
    pip install -r requirements.txt
    python app.py            # http://localhost:5000

The SQLite database (`roommatch.db`) and a session signing key (`.secret_key`) are created on first run.

## Deploy
    COOKIE_SECURE=1 SECRET_KEY=<long random string> DB_PATH=/data/roommatch.db \
      gunicorn -w 2 -b 0.0.0.0:$PORT app:app

- Serve over HTTPS and set `COOKIE_SECURE=1`.
- Put `DB_PATH` on persistent disk (on Render/Fly/Railway attach a volume), or the database resets on redeploy.
- Back up by copying the `.db` file.

## Security notes
Passwords are hashed (scrypt via Werkzeug), sessions use signed HttpOnly SameSite=Lax cookies, writes require JSON (blocks cross-site form posts), all SQL is parameterized, and login is rate limited (10 failures / 15 min per IP or email).
Not included: email verification and password reset (these need an email service).
