import psycopg2
from . import logger
from . import config
from . import encdec
from . import security


ec = encdec.EncDec(config.SEED)
logger = logger.logging.getLogger('database')

class db():
    def __init__(self) -> None:
        try:
            self.conn = psycopg2.connect(dbname=config.dbname, user=config.DB_LOGIN, password=config.DB_PASSWORD)
            self.cursor = self.conn.cursor()

        except Exception as e:
            logger.exception("Can't connect to database", e)
        
    def create_table_users(self):
        REQUEST = """
        CREATE TABLE IF NOT EXISTS users_public (
            user_seq_id SERIAL,
            user_uid UUID,
            user_email TEXT,
            user_fname TEXT,
            user_lname TEXT,
            user_phone TEXT,
            user_picture TEXT,
            user_dept TEXT,
            user_role TEXT,
            user_role_public TEXT,
            user_account_status TEXT
        )"""
        self.cursor.execute(REQUEST)
        REQUEST = """
        CREATE TABLE IF NOT EXISTS users_protected (
            user_seq_id SERIAL,
            user_uid UUID,
            user_pass_hash TEXT,
            user_pass_salt TEXT,
            user_tfa_key TEXT,
            user_known_browser_fp TEXT,
            user_known_ips JSON,
            user_last_browser_fp TEXT,
            user_last_ip CIDR,
            user_require_rekey BOOLEAN
        )"""
        self.cursor.execute(REQUEST)
        self.conn.commit()

    def create_table_users_sessions(self):
        REQUEST = """
        CREATE TABLE IF NOT EXISTS users_sessions (
            user_seq_id SERIAL,
            user_uid UUID,
            user_sessions_tokens 
        )"""
        self.cursor.execute(REQUEST)

    def craft_insert_request(self, data, table_name):
        field_names = list(data.keys())

        REQUEST = "INSERT INTO %s(%s) VALUES (" % \
                  (
                        security.sanitize_string(table_name, SQL=True),\
                        ", ".join(list(data.keys()))
                  )
        for value in data:
            if type(data[value]) == bool:
                REQUEST += "%s, " % str(data[value]).upper()
            elif type(data[value]) == tuple:
                REQUEST += "('%s'), " % data[value]
            else:
                REQUEST += "'%s', " % data[value]
        REQUEST = REQUEST[:-2]
        REQUEST += ");"
        print(REQUEST)
        return REQUEST


    def create_user(self, data):
        user_salt = ec.gen_user_salt()

        for key in data:
            if type(data[key]) not in [bool, list, tuple]:
                data[key] = security.sanitize_string(data[key], SQL = True)

        data["user_uid"] = ec.get_uid()
        data["user_pass_salt"] = user_salt
        data["user_pass_hash"] = ec.hash_data(data['user_pass_plaintext'], user_salt)
        data.pop("user_pass_plaintext")

        users_protected = dict.fromkeys(config.SQL_USER_PROTECTED)

        for key in users_protected:
            if key in config.SQL_DONT_ENCRYPT:
                users_protected[key] = data[key]
            else:
                users_protected[key] = ec.encrypt(data[key]).decode()
        REQUEST = self.craft_insert_request(users_protected, "users_protected")
        print(REQUEST)
        self.cursor.execute(REQUEST)
        self.conn.commit()

        users_public = {}
        for key in data:
            if key not in config.SQL_USER_PROTECTED or key in config.SQL_USER_SPECIAL:
                if key in config.SQL_DONT_ENCRYPT:
                    users_public[key] = data[key]
                else:
                    users_public[key] = ec.encrypt(data[key]).decode()
        REQUEST = self.craft_insert_request(users_public, "users_public")
        self.cursor.execute(REQUEST)
        self.conn.commit()

        return data
    
    def get_uuid_by_email(self, data):
        REQUEST = "SELECT user_uid FROM users_public WHERE user_email = '%s'" % \
        security.sanitize_string(data['user_email'], SQL = True)

        self.cursor.execute(REQUEST)
        r = self.cursor.fetchall()
        if len(r) != 0:
            return r[0][0]
        else:
            return False
        
    def get_auth_data_by_uuid(self, data):
        REQUEST = "SELECT user_pass_salt, user_pass_hash, user_last_browser_fp FROM users_protected WHERE user_uid = '%s'" % \
        security.sanitize_string(data['user_uid'], SQL = True)

        self.cursor.execute(REQUEST)
        r = self.cursor.fetchall()
        dec = ec.decrypt(str(r[0][-1]).encode())
        if len(r) != 0:
            return r[0][:-1] + (dec,)
        else:
            return False
    
    def get_user_2fa_seed_by_uuid(self, data):
        REQUEST = "SELECT user_tfa_key FROM users_protected WHERE user_uid = '%s'" % \
        security.sanitize_string(data['user_uid'], SQL=True)
        self.cursor.execute(REQUEST)
        r = self.cursor.fetchall()

        if len(r) != 0:
            return ec.decrypt(r[0][0])
        else:
            return False

    def check_if_uuid_exists(self, data):
        REQUEST = "SELECT user_email FROM users_public WHERE user_uid='%s'" % \
        security.sanitize_string(data['user_uid'], SQL=True)
        self.cursor.execute(REQUEST)
        r = self.cursor.fetchall()

        if len(r) != 0:
            return True
        else:
            return False
        
    def get_user_full_data_DEBUG(self, data):
        REQUEST = "SELECT * FROM users_public WHERE user_uid='%s'" % \
        security.sanitize_string(data['user_uid'], SQL=True)
        self.cursor.execute(REQUEST)
        r = self.cursor.fetchall()
        data_r = []
        data_r.append(r[0])

        REQUEST = "SELECT * FROM users_protected WHERE user_uid='%s'" % \
        security.sanitize_string(data['user_uid'], SQL=True)
        self.cursor.execute(REQUEST)
        r = self.cursor.fetchall()

        data_r.append(r[0])

        if len(data_r) != 0:
            return data_r
        else:
            return False
