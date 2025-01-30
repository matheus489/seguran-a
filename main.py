# Arquivo principal para integrar o sistema
from access_control import AccessControl
from encryption import SymmetricEncryption, AsymmetricEncryption
from interface import App
import tkinter as tk

# Inicialização dos sistemas de controle de acesso e criptografia
access_control = AccessControl()
symmetric_encryption = SymmetricEncryption(key=b'Sixteen byte key')
asymmetric_encryption = AsymmetricEncryption()

# Adicionando usuários
access_control.add_user('admin', 'admin', 'admin')
access_control.add_user('user', 'user', 'user')
access_control.add_user('guest', 'guest', 'guest')

# Autenticação e autorização
user = access_control.authenticate('admin', 'admin')
if user and access_control.authorize(user, 'admin'):
    print(f"Usuário {user.username} autenticado como {user.role}.")

    # Criptografia simétrica
    data = b'Sensitive data'
    nonce, ciphertext, tag = symmetric_encryption.encrypt(data)
    print(f"Dados criptografados (simétrico): {ciphertext}")
    decrypted_data = symmetric_encryption.decrypt(nonce, ciphertext, tag)
    print(f"Dados descriptografados (simétrico): {decrypted_data}")

    # Criptografia assimétrica
    ciphertext = asymmetric_encryption.encrypt(data)
    print(f"Dados criptografados (assimétrico): {ciphertext}")
    decrypted_data = asymmetric_encryption.decrypt(ciphertext)
    print(f"Dados descriptografados (assimétrico): {decrypted_data}")
else:
    print("Acesso negado.")

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop() 
