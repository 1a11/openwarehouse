from modules import dbhandler as dbh
from modules import auth
from modules import encdec
from modules import config
import pyotp

import qrcode


d = dbh.db()
#d.create_table_users()
ec = encdec.EncDec(config.SEED)
Auth = auth.Auth(d)
seed = Auth.generate_user_2fa()
data = {
        "user_email":"spbrcc@test.kitchen",
        "user_fname":"Тестовая",
        "user_lname":"Кухня",
        "user_phone":"+71234567890",
        "user_dept":"ППГП Монетная",
        "user_role":"Admin",
        "user_role_public":"Информационные системы",
        "user_account_status":"1",
        "user_pass_plaintext":"123456",
        "user_uid":"",
        "user_pass_hash":"",
        "user_pass_salt":"",
        "user_tfa_key":seed,
        "user_known_browser_fp":"",
        "user_known_ips":('{}',),
        "user_last_browser_fp":"",
        "user_last_ip":"127.0.0.1",
        "user_require_rekey":False
    }
print(data)
r = d.create_user(data)
print(r)



uid = d.get_uuid_by_email({"user_email":"spbrcc@test.kitchen"})
print(uid)

salt, phash, last_fp = d.get_auth_data_by_uuid({"user_uid":uid})
print(salt, phash, last_fp)

passw = "123456"

uphash = ec.hash_data(passw, salt)

print(uphash == phash)

tfa_seed = d.get_user_2fa_seed_by_uuid({"user_uid":uid})
print(tfa_seed)

totp = pyotp.TOTP(tfa_seed)

print(totp.now())

url = pyotp.totp.TOTP(tfa_seed).provisioning_uri(name='spbrcc@test.kitchen', issuer_name='Команда ППГА Красного креста')

print(url)

img = qrcode.make(url)
img.save("some_file.png")