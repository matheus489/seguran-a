# Arquivo para gerenciar perfis de usuário e autenticação

import json
from encryption import SymmetricEncryption
import logging

class User:
    def __init__(self, username, password, role, permissions=None):
        self.username = username
        self.password = password
        self.role = role
        self.permissions = permissions if permissions is not None else []

class AccessControl:
    def __init__(self):
        self.users = []
        self.permissions = {
            'admin': ['add_user', 'remove_user', 'view_logs', 'manage_permissions'],
            'user': ['encrypt', 'decrypt'],
            'guest': []
        }
        self.symmetric_encryption = SymmetricEncryption(key=b'Sixteen byte key')
        self.load_users()

    def add_user(self, username, password, role, permissions=None):
        # Verificar se o usuário já existe
        if any(user.username == username for user in self.users):
            logging.warning(f'Usuário {username} já existe. Não será adicionado novamente.')
            return
        user = User(username, password, role, permissions)
        self.users.append(user)
        self.save_users()

    def authenticate(self, username, password):
        for user in self.users:
            if user.username == username and user.password == password:
                return user
        return None

    def authorize(self, user, action):
        return action in user.permissions

    def save_users(self):
        with open('users.json', 'w') as file:
            json.dump([{
                'username': user.username,
                'password': user.password,
                'role': user.role,
                'permissions': user.permissions
            } for user in self.users], file)

    def load_users(self):
        try:
            with open('users.json', 'r') as file:
                users_data = json.load(file)
                if not isinstance(users_data, list):
                    users_data = []
                self.users = [User(**data) for data in users_data]
        except (FileNotFoundError, json.JSONDecodeError):
            self.users = []
            self.save_users() 