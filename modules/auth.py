from . import encdec as ed
from . import config
import pyotp
import time
from datetime import datetime, timedelta
import ast

Ec = ed.EncDec(config.SEED)

class Auth():
    def __init__(self, dbh) -> None:
        self.db = dbh
        self.factors = {
            "password":0,
            "user_email":0,
            "fingerprint":0,
            "lastloging":0
        }
        self.token_mapper = {}
    
    def validate_against_recorded(self, data):
        uid = self.db.get_uuid_by_email(data)
        if not uid:
            return False
        salt, phash, browserfp = self.db.get_auth_data_by_uuid({"user_uid":uid})
        uphash = Ec.hash_data(data['user_pass'], salt)

        token_tempsalt = Ec.gen_user_salt()
        print(token_tempsalt,salt,uid,data["user_last_browser_fp"])
        token = token_tempsalt+"@"+Ec.hash_data(uid+salt+data["user_last_browser_fp"]+"@Req:2FA", salt)
        
        self.token_mapper[token] = uid
        return {"auth": phash == uphash, "require_2fa":data["user_last_browser_fp"] != browserfp, "token":token, "browser_fp":Ec.encrypt(data["user_last_browser_fp"])}

    def validate_creds(self, data):
        decision = {
            "points":0,
            "2faREQ":False,
            "valid":False
        }
        return self.validate_against_recorded({"user_email":data['email'], "user_pass":data['password'], "user_last_browser_fp":data["browserId"]})
    
    def validate_2fa(self, data):
        if data['token'] not in self.token_mapper:
            return False
        uid = self.token_mapper[data['token']]
        seed = self.db.get_user_2fa_seed_by_uuid({"user_uid":uid})

        totp = pyotp.TOTP(seed)
        return totp.verify(data['tfa_code'])
    
    def generate_user_2fa(self):
        return pyotp.random_base32()

    def validate_session(self, data):
        if "sessionid" in data:
            if data["sessionid"] == None:
                return False
            try:
                sessionid = Ec.decrypt(data['sessionid'])
            except Exception:
                return False
            sessionid = ast.literal_eval(sessionid)
            print(sessionid)    
            print(data)
            browser_fp = Ec.decrypt(data['browser_fp'])
            print(browser_fp, sessionid['user_client_fp'])
            if sessionid["user_client_fp"] == browser_fp:
                print("FP Valid", time.time())
                if int(sessionid['session_expire_stamp']) > int(time.time()):
                    print("Time Valid")
                    if self.db.check_if_uuid_exists({"user_uid":sessionid['user_uid']}):
                        print("UID Valid")
                        return sessionid['user_uid']
                    else:
                        return False
                else:
                    return False
            else:
                return False


        #print(self.token_mapper)
        if data['token'] not in self.token_mapper:
            return False
        
        #print(data['token'])
        token_tempsalt = data['token'].split("@")[0]
        #print(token_tempsalt.split("@")[0])

        uid = self.token_mapper[data['token']]
        client_fp = data["browser_fp"]
        client_fp = Ec.decrypt(client_fp)
        salt, phash, browserfp = self.db.get_auth_data_by_uuid({"user_uid":uid})
        token_gen_untrusted = token_tempsalt+"@"+Ec.hash_data(uid+salt+client_fp+"@Req:2FA", salt)

        return token_gen_untrusted in self.token_mapper
    
    def generate_permament_session_id(self, data):
        user_client_fp = Ec.decrypt(data['browser_fp'])
        user_uid = self.token_mapper[data['token']]
        self.token_mapper.pop(data['token'])
        session_random_id = self.generate_user_2fa()
        session_generated_stamp = int(datetime.timestamp(datetime.today()))
        session_expire_stamp = int(datetime.timestamp(datetime.today() + timedelta(days=30)))
        print(user_client_fp, user_uid, session_random_id, session_generated_stamp, session_expire_stamp)
        structure = {
            "user_client_fp":user_client_fp,
            "user_uid":user_uid,
            "session_random_id":session_random_id,
            "session_generated_stamp":session_generated_stamp,
            "session_expire_stamp":session_expire_stamp,

        }
        structure = str(structure)
        print(structure)
        structure = Ec.encrypt(structure)
        print(structure)
        return structure.decode()
    
    
