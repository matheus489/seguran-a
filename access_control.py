# Arquivo para gerenciar perfis de usuário e autenticação

class User:
    def __init__(self, username, password, role):
        self.username = username
        self.password = password
        self.role = role

class AccessControl:
    def __init__(self):
        self.users = []
        self.permissions = {
            'admin': ['add_user', 'remove_user', 'view_logs', 'manage_permissions'],
            'user': ['encrypt', 'decrypt'],
            'guest': []
        }

    def add_user(self, username, password, role):
        user = User(username, password, role)
        self.users.append(user)

    def authenticate(self, username, password):
        for user in self.users:
            if user.username == username and user.password == password:
                return user
        return None

    def authorize(self, user, action):
        return action in self.permissions.get(user.role, []) 
