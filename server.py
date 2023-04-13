import os
from modules import encdec as ed
from modules import auth
from modules import dbhandler as dbh

from modules import encdec
from modules import config

from flask import Flask, render_template_string, render_template, \
     request, g, redirect, url_for, make_response, Markup
from functools import wraps


app = Flask(__name__, template_folder='security')
app.config['DEBUG'] = True

db = dbh.db()
Auth = auth.Auth(db)
Ec = ed.EncDec(config.SEED)


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, public, max-age=0"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/debug")
def debug():
    check = Auth.validate_session({"sessionid":request.cookies.get("sessionid"), "browser_fp":request.cookies.get("fp")})
    if not check:
        return redirect("/login")
    data = db.get_user_full_data_DEBUG({"user_uid":check})
    code = ""
    #print(len(config.USER_DEBUG_FIELD_MAPPER_PUBLIC), len(data[0]))
    for i, key in zip(data[0], config.USER_DEBUG_FIELD_MAPPER_PUBLIC):
        
        try:
            #print(key, key in config.USER_DEBUG_FIELD_MAPPER_PUBLIC,str(Ec.decrypt(i)))
            code += "<p>%s (%s) - %s</p>" % (config.USER_DEBUG_FIELD_MAPPER_PUBLIC[key], key, str(Ec.decrypt(i)))
        except Exception:
            print(key, key in config.USER_DEBUG_FIELD_MAPPER_PUBLIC,i)
            code += "<p>%s (%s) - %s</p>" % (config.USER_DEBUG_FIELD_MAPPER_PUBLIC[key], key, str(i))

    for i, key in zip(data[1], config.USER_DEBUG_FIELD_MAPPER_PROTECTED):
        #print(key, key in config.USER_DEBUG_FIELD_MAPPER_PUBLIC,i)
        try:
            code += "<p>%s (%s) - %s</p>" % (config.USER_DEBUG_FIELD_MAPPER_PROTECTED[key], key, str(Ec.decrypt(i)))
        except Exception:
            code += "<p>%s (%s) - %s</p>" % (config.USER_DEBUG_FIELD_MAPPER_PROTECTED[key], key, str(i))

    return Markup(code+ "</br><a href=/logout>Logout</a>")


@app.route("/")
def home():
    check = Auth.validate_session({"sessionid":request.cookies.get("sessionid"), "browser_fp":request.cookies.get("fp")})
    if not check:
        return redirect("/login")
    data = db.get_user_full_data_DEBUG({"user_uid":check})

    return render_template('index.html')

@app.route("/login", methods = ["POST", "GET"])
def login():
    print(request.cookies.get("token"))
    print(request.cookies.get("fp"))
    
    if Auth.validate_session({"sessionid":request.cookies.get("sessionid"), "browser_fp":request.cookies.get("fp")}):
        return redirect("/")

    if request.method == "GET":
        if request.args.get("fido") == "1":
            return render_template('login-fido-currently-disabled.html', randomStringFromServer = Auth.generate_user_2fa())
        return render_template('login.html')
    else:
        email = request.form.get("email")
        password = request.form.get("password")
        visitorId = request.form.get('visitorId')
        print(email,password, visitorId)
        user_data = {"email":email, "password":password, "browserId":visitorId}
        auth_resp = Auth.validate_creds(user_data)
        print(auth_resp)
        if auth_resp["auth"] and auth_resp["require_2fa"]:
            resp = make_response(redirect("/2fa?token=%s&fp=%s" % (auth_resp['token'],auth_resp['browser_fp'].decode())))
            resp.set_cookie("sid","1234")
            resp.set_cookie("token",auth_resp['token'].replace('"',""))
            resp.set_cookie("fp",auth_resp['browser_fp'])
        elif auth_resp["auth"] and not auth_resp["require_2fa"]:
            resp = make_response(redirect("/"))
            resp.set_cookie("sid","123")
        else:
            resp = make_response(redirect("/login"))
        return resp

@app.route("/2fa", methods = ["GET", "POST"])
def tfa():
    if request.method == "GET":
        if Auth.validate_session({"token":request.args.get("token"), "browser_fp":request.args.get("fp")}):
            return render_template("login-2fa.html", token = request.args.get("token"))
        else:
            return redirect('/')
    else:
        tfa_code = request.form.get("tfa_code")
        if Auth.validate_2fa({"tfa_code":tfa_code, "token":request.args.get("token")}):
            resp = make_response(redirect("/"))
            sessionid = Auth.generate_permament_session_id({"token":request.args.get("token"), "browser_fp":request.cookies.get("fp")})
            resp.set_cookie("sessionid", sessionid)
            return resp
        else:
            return "TFC NOT CORRECT!" + Markup("<a href='/logout'>logout</a>")

@app.route("/logout", methods = ["GET"])
def logout():
    resp = make_response(redirect("/"))
    resp.set_cookie("sid","")
    resp.set_cookie("token","")
    resp.set_cookie("fp","")
    resp.set_cookie("sessionid","")
    return resp

@app.route("/api", methods = ["GET", "POST"])
def api():
    return True

if __name__ == '__main__':
    # run application (can also use flask run)
    app.run()