from werkzeug.security import safe_str_cmp
from user import User

users = [
    User(1, 'bob', 'asdf')
]



username_mapping = {u.username: u for u in users}
userid_mapping = {u.id: u for u in users}


def authenticate(username, password):
    # finding user by user name. .get() is another way of accessing dictionary. It will take key and provide data, if no data found then it will return None. 
    user = username_mapping.get(username, None)
    if user and safe_str_cmp(user.password, password):
        return user
    
def identity(payload):
    # it takes in payload. The payload is the content of jwt token. and we r going to extract the userid from the payload. 
    user_id = payload["identity"]
    return userid_mapping.get(user_id, None)



