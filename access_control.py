# Arquivo para gerenciar perfis de usuário e autenticação

class User:
    def __init__(self, username, password, role):
        self.username = username
        self.password = password
        self.role = role

class AccessControl:
    def __init__(self):
        self.users = []

    def add_user(self, username, password, role):
        user = User(username, password, role)
        self.users.append(user)

    def authenticate(self, username, password):
        for user in self.users:
            if user.username == username and user.password == password:
                return user
        return None

    def authorize(self, user, required_role):
        return user.role == required_role 
