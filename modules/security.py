from . import config

def sanitize_string(string, SQL=False):
    if type(string) not in [bool, list, tuple, dict]:
        #print(string, "FSDBFHSKDBf")
        clean_data = string.strip()
        if SQL:
            for i in config.SQL_DISALLOW:
                clean_data = clean_data.replace(i, "")
                clean_data = clean_data.replace(i.lower(), "")
                clean_data = clean_data.replace(i.strip(), "")
                clean_data = clean_data.replace(i.strip().lower(), "")
        for i in config.FORMS_DISALLOW:
            clean_data = clean_data.replace(i, "")
        
        
        return clean_data.strip()
    else:
        return string