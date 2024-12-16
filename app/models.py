import uuid

class User:
    def __init__(self, name, email, password):
        self.uid = uuid.uuid4()
        self.name = name
        self.email = email
        self.password = password
        self.profilepic = None

class Journal:
    def __init__(self, title, body, user_id):
        self.title = title
        self.body = body
        self.user_id = user_id