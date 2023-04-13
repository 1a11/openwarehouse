import os

#CHANGE BEFORE PUSHING

os.environ['SEED'] = "SUPERSECRETSERVERSEED" #    TODO: CHANGE ME 
os.environ['DB_LOGIN'] = "postgres"
os.environ['DB_PASSWORD'] = "sudo"

#CHANGE BEFORE PUSHING

SEED = os.getenv('SEED')

DB_LOGIN = os.getenv("DB_LOGIN")
DB_PASSWORD = os.getenv("DB_PASSWORD")
dbname = 'spbrccdev'


#DISALLOW LIST FOR STRING SANIT
FORMS_DISALLOW = """!"#$%&'()*,-/:;<=>?[\]^`{|}~"""
SQL_DISALLOW = [
    " INSERT ",
    " SELECT ",
    " DROP ",
    " IF ",
    " WHERE ",
    "INSERT",
    "SELECT",
    "DROP",
    "IF",
    "WHERE"
]

#PROTECTED FIELDS FOR USER
SQL_USER_PROTECTED = [
    "user_uid",
    "user_pass_hash",
    "user_pass_salt",
    "user_tfa_key",
    "user_known_browser_fp",
    "user_known_ips",
    "user_last_browser_fp",
    "user_last_ip",
    "user_require_rekey"
]

SQL_USER_SPECIAL = [
    "user_uid"
]

SQL_TRUSTED = [
    "user_known_ips"
]

SQL_DONT_ENCRYPT = [
    "user_email",
    "user_uid",
    "user_pass_hash",
    "user_pass_salt",
    "user_known_ips",
    "user_require_rekey",
    "user_last_ip"
]

USER_DEBUG_FIELD_MAPPER_PUBLIC = {
        "user_sequential":"Порядковый номер",
        "user_uid":"Идентификатор",
        "user_email":"E-Mail",
        "user_fname":"Имя",
        "user_lname":"Фамилия",
        "user_phone":"Телефон",
        "user_picture":"Фото профиля",
        "user_dept":"Отдел",
        "user_role":"Роль (Публичная)",
        "user_role_public":"Роль (Внутренняя)",
        "user_account_status":"Статус аккаунта"
}

USER_DEBUG_FIELD_MAPPER_PROTECTED = {
        "user_sequential":"Порялковый номер",
        "user_uid":"Идентификатор",
        "user_pass_hash":"Хэш пароля",
        "user_pass_salt":"Соль хэша",
        "user_tfa_key":"Ключ 2FA",
        "user_known_browser_fp":"Известные отпечатки браузера",
        "user_known_ips":"Известные IP",
        "user_last_browser_fp":"Последний известный опечаток браузера",
        "user_last_ip":"Последний известный IP",
        "user_require_rekey":"Требуется смена пароля"
}