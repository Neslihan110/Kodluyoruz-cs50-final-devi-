import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

app.jinja_env.filters["usd"] = usd
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
db = SQL("sqlite:///finance.db")
@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks = db.execute("SELECT symbol, id, name, current_price, SUM(shares) as sum FROM purchases WHERE user_id=:user_id GROUP BY symbol HAVING sum > 0",
                        user_id=session["user_id"])
    grand_total = 0
    
    for stock in stocks:
        current_stock = lookup(stock["symbol"])
        db.execute("UPDATE purchases SET current_price=:current_price WHERE symbol=:symbol AND user_id=:user_id",
                   current_price=current_stock['price'], symbol=stock['symbol'], user_id=session["user_id"])
        grand_total = grand_total + (stock["current_price"] * stock["sum"])

    user = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])
    grand_total = grand_total + user[0]["cash"]
    return render_template("index.html", stocks=stocks, user=user, grand_total=grand_total)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        stock = lookup(request.form.get("symbol"))
        if (not request.form.get("symbol")) or (not stock):
            return apology("must provide valid symbol", 400)
        shares = request.form.get("shares")
        if (not request.form.get("shares")) or (not shares.isdigit()) or (int(shares) <= 0):
            return apology("must provide positive integer as number of shares", 400)
        rows = db.execute("SELECT * FROM users WHERE id = :id", id=session["user_id"])
        cash = rows[0]["cash"]
        total = stock["price"] * int(shares)
        if cash < total:
            return apology("can't afford")
        else:
            db.execute("INSERT INTO purchases (user_id, symbol, price, shares, name, current_price) VALUES (:user_id, :symbol, :price, :shares, :name, :current_price)",
                       user_id=session["user_id"], symbol=stock["symbol"], price=stock["price"], shares=int(shares), name=stock["name"], current_price=stock["price"])
            db.execute("UPDATE users SET cash = :cash WHERE id = :id", cash=cash-total, id=session["user_id"])
            flash("Bought!")
            return redirect("/")
    else:
        return render_template("buy.html")
@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    if not request.args.get("username"):
        return apology("must provide username", 400)
    if len(request.args.get("username")) <= 1:
        return apology("username must be more than 1 character", 400)
    rows = db.execute("SELECT * FROM users WHERE username = :username",
                      username=request.args.get("username"))

    if len(rows) != 0:
        return jsonify(False)
    else:
        return jsonify(True)
@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    stocks = db.execute("SELECT symbol, name, shares, price, date, time FROM purchases WHERE user_id=:user_id",
                        user_id=session["user_id"])
    return render_template("history.html", stocks=stocks)
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("login.html")
@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()
    return redirect("/")
@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":
        if (not request.form.get("symbol")) or (not lookup(request.form.get("symbol"))):
            return apology("must provide valid symbol", 400)

        else:
            return render_template("quoted.html", stock=lookup(request.form.get("symbol")))
    else:
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 400)
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 400)
        hash = generate_password_hash(request.form.get("password"))
        result = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                            username=request.form.get("username"), hash=hash)
        if not result:
            return apology("username is taken", 400)
        session["user_id"] = result
        return redirect("/")
    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must select symbol", 400)

        shares = request.form.get("shares")
        if (not shares) or (not shares.isdigit()) or (int(shares) <= 0):
            return apology("must provide positive integer as number of shares")

        selected_stock = db.execute("SELECT SUM(shares) as sum FROM purchases WHERE user_id=:user_id AND symbol=:symbol GROUP BY symbol HAVING sum > 0",
                                    user_id=session["user_id"], symbol=request.form.get("symbol"))
        if (not selected_stock) or (selected_stock[0]["sum"] < int(shares)):
            return apology("must own enough shares of selected stock", 400)

        stock = lookup(request.form.get("symbol"))
        db.execute("UPDATE purchases SET current_price=:current_price WHERE symbol=:symbol",
                   current_price=stock['price'], symbol=stock['symbol'])

        db.execute("INSERT INTO purchases (user_id, symbol, price, shares, name, current_price) VALUES (:user_id, :symbol, :price, :shares, :name, :current_price)",
                   user_id=session["user_id"], symbol=stock["symbol"], price=stock["price"], shares=-int(shares), name=stock["name"], current_price=stock["price"])
        user = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])
        change = stock["price"] * int(shares)
        db.execute("UPDATE users SET cash=:cash WHERE id=:id", cash=(user[0]["cash"]+change), id=session["user_id"])
        flash("Sold!")
        return redirect("/")
    else:
        choices = db.execute("SELECT symbol, SUM(shares) as shares FROM purchases WHERE user_id=:user_id GROUP BY symbol HAVING SUM(shares) > 0",
                             user_id=session["user_id"])
        return render_template("sell.html", choices=choices)

@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """Allows users to change their password"""
    if request.method == "POST":
        if not request.form.get("password"):
            return apology("must provide password", 400)

        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 400)

        hash = generate_password_hash(request.form.get("password"))

        user = db.execute("SELECT username FROM users WHERE id=:id", id=session["user_id"])
        db.execute("UPDATE users SET hash=:hash WHERE username=:username",
                   username=user[0]["username"], hash=hash)
        flash("Sold!")
        return redirect("/")

    else:
        return render_template("change.html")
def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
