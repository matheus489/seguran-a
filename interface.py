# Interface gráfica usando tkinter
import tkinter as tk
from tkinter import messagebox, filedialog
from access_control import AccessControl
from encryption import SymmetricEncryption, AsymmetricEncryption
import tkinter.ttk as ttk
import logging

# Configuração do logger
logging.basicConfig(filename='access.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Sistema de Segurança")

        self.access_control = AccessControl()
        self.symmetric_encryption = SymmetricEncryption(key=b'Sixteen byte key')
        self.asymmetric_encryption = AsymmetricEncryption()

        self.access_control.add_user('admin', 'admin', 'admin')
        self.access_control.add_user('user', 'user', 'user')
        self.access_control.add_user('guest', 'guest', 'guest')

        self.registration_requests = []  # Lista de pedidos de cadastro

        logging.info('Sistema iniciado')

        self.create_widgets()

    def create_widgets(self):
        self.label_username = tk.Label(self.root, text="Nome de Usuário:")
        self.label_username.pack()

        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack()

        self.label_password = tk.Label(self.root, text="Senha:")
        self.label_password.pack()

        self.password_entry = tk.Entry(self.root, show='*')
        self.password_entry.pack()

        self.login_button = tk.Button(self.root, text="Login", command=self.authenticate_user)
        self.login_button.pack()

        self.register_button = tk.Button(self.root, text="Registrar", command=self.register_user)
        self.register_button.pack()

    def register_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        self.registration_requests.append((username, password))
        messagebox.showinfo("Registro", "Pedido de registro enviado. Aguarde aprovação do administrador.")

    def open_admin_panel(self):
        self.admin_window = tk.Toplevel(self.root)
        self.admin_window.title("Painel do Administrador")

        self.requests_listbox = tk.Listbox(self.admin_window)
        self.requests_listbox.pack()

        for request in self.registration_requests:
            self.requests_listbox.insert(tk.END, f"Usuário: {request[0]}")

        self.approve_button = tk.Button(self.admin_window, text="Aprovar", command=self.approve_user)
        self.approve_button.pack()

        self.reject_button = tk.Button(self.admin_window, text="Rejeitar", command=self.reject_user)
        self.reject_button.pack()

        self.manage_permissions_button = tk.Button(self.admin_window, text="Gerenciar Permissões", command=self.manage_permissions)
        self.manage_permissions_button.pack()

    def approve_user(self):
        selected_index = self.requests_listbox.curselection()
        if selected_index:
            username, password = self.registration_requests.pop(selected_index[0])
            self.access_control.add_user(username, password, 'user')
            self.requests_listbox.delete(selected_index)
            logging.info(f'Usuário {username} aprovado')
            messagebox.showinfo("Aprovação", f"Usuário {username} aprovado.")

    def reject_user(self):
        selected_index = self.requests_listbox.curselection()
        if selected_index:
            username, _ = self.registration_requests.pop(selected_index[0])
            self.requests_listbox.delete(selected_index)
            logging.info(f'Usuário {username} rejeitado')
            messagebox.showinfo("Rejeição", f"Usuário {username} rejeitado.")

    def manage_permissions(self):
        self.permissions_window = tk.Toplevel(self.admin_window)
        self.permissions_window.title("Gerenciar Permissões")

        self.permissions_label = tk.Label(self.permissions_window, text="Configurações de Permissões")
        self.permissions_label.pack()

        # Exemplo de configuração de permissões
        self.permissions_text = tk.Text(self.permissions_window, height=10, width=50)
        self.permissions_text.insert(tk.END, "admin: add_user, remove_user, view_logs, manage_permissions\n")
        self.permissions_text.insert(tk.END, "user: encrypt, decrypt\n")
        self.permissions_text.insert(tk.END, "guest: \n")
        self.permissions_text.pack()

        self.save_permissions_button = tk.Button(self.permissions_window, text="Salvar", command=self.save_permissions)
        self.save_permissions_button.pack()

    def save_permissions(self):
        # Lógica para salvar as permissões configuradas
        messagebox.showinfo("Sucesso", "Permissões salvas com sucesso.")

    def authenticate_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        user = self.access_control.authenticate(username, password)
        if user:
            logging.info(f'Usuário {username} autenticado com sucesso como {user.role}')
            messagebox.showinfo("Sucesso", f"Usuário {user.username} autenticado como {user.role}.")
            self.current_user = user
            self.root.withdraw()  # Fechar a tela de login
            if user.role == 'admin':
                self.open_admin_panel()
            self.open_encryption_window()
        else:
            logging.warning(f'Tentativa de login falhou para o usuário {username}')
            messagebox.showerror("Erro", "Usuário ou senha incorretos.")

    def open_encryption_window(self):
        self.encryption_window = tk.Toplevel(self.root)
        self.encryption_window.title("Criptografia e Descriptografia")

        notebook = ttk.Notebook(self.encryption_window)
        notebook.pack(expand=True, fill='both')

        # Aba de Operações
        operations_frame = ttk.Frame(notebook)
        notebook.add(operations_frame, text='Operações')

        self.label_text = tk.Label(operations_frame, text="Texto:")
        self.label_text.pack()

        self.text_entry = tk.Entry(operations_frame, width=50)
        self.text_entry.pack()

        self.encrypt_aes_button = tk.Button(operations_frame, text="Criptografar com AES", command=self.encrypt_data_aes)
        self.encrypt_aes_button.pack()

        self.decrypt_aes_button = tk.Button(operations_frame, text="Descriptografar com AES", command=self.decrypt_data_aes)
        self.decrypt_aes_button.pack()

        self.encrypt_rsa_button = tk.Button(operations_frame, text="Criptografar com RSA", command=self.encrypt_data_rsa)
        self.encrypt_rsa_button.pack()

        self.decrypt_rsa_button = tk.Button(operations_frame, text="Descriptografar com RSA", command=self.decrypt_data_rsa)
        self.decrypt_rsa_button.pack()

        # Aba de Histórico
        history_frame = ttk.Frame(notebook)
        notebook.add(history_frame, text='Histórico')

        self.history_text = tk.Text(history_frame, height=10, width=50)
        self.history_text.pack()

        # Aba de Upload de Arquivo
        file_upload_frame = ttk.Frame(notebook)
        notebook.add(file_upload_frame, text='Upload de Arquivo')

        self.upload_label = tk.Label(file_upload_frame, text="Selecione um arquivo .txt:")
        self.upload_label.pack()

        self.file_path_entry = tk.Entry(file_upload_frame, width=50)
        self.file_path_entry.pack()

        self.browse_button = tk.Button(file_upload_frame, text="Procurar", command=self.browse_file)
        self.browse_button.pack()

        self.encrypt_file_aes_button = tk.Button(file_upload_frame, text="Criptografar Arquivo com AES", command=self.encrypt_file_aes)
        self.encrypt_file_aes_button.pack_forget()

        self.decrypt_file_aes_button = tk.Button(file_upload_frame, text="Descriptografar Arquivo com AES", command=self.decrypt_file_aes)
        self.decrypt_file_aes_button.pack_forget()

        self.encrypt_file_rsa_button = tk.Button(file_upload_frame, text="Criptografar Arquivo com RSA", command=self.encrypt_file_rsa)
        self.encrypt_file_rsa_button.pack()

        self.decrypt_file_rsa_button = tk.Button(file_upload_frame, text="Descriptografar Arquivo com RSA", command=self.decrypt_file_rsa)
        self.decrypt_file_rsa_button.pack()

        self.file_paths = []

        self.browse_multiple_button = tk.Button(file_upload_frame, text="Procurar Múltiplos", command=self.browse_multiple_files)
        self.browse_multiple_button.pack()

        self.encrypt_files_rsa_button = tk.Button(file_upload_frame, text="Criptografar Arquivos com RSA", command=self.encrypt_files_rsa)
        self.encrypt_files_rsa_button.pack()

        self.decrypt_files_rsa_button = tk.Button(file_upload_frame, text="Descriptografar Arquivos com RSA", command=self.decrypt_files_rsa)
        self.decrypt_files_rsa_button.pack()

        self.back_to_login_button = tk.Button(self.encryption_window, text="Voltar para Login", command=self.back_to_login)
        self.back_to_login_button.pack(pady=10)

    def encrypt_data_aes(self):
        if hasattr(self, 'current_user'):
            text = self.text_entry.get().encode()
            symmetric_encryption = SymmetricEncryption(key=b'Sixteen byte key')
            self.nonce, self.ciphertext, self.tag = symmetric_encryption.encrypt(text)
            self.history_text.insert(tk.END, f"AES Criptografado: {self.ciphertext}\n")
            messagebox.showinfo("Criptografia Simétrica", f"AES Criptografado: {self.ciphertext}")
        else:
            messagebox.showwarning("Acesso Negado", "Você precisa estar logado para criptografar dados.")

    def decrypt_data_aes(self):
        if hasattr(self, 'current_user'):
            symmetric_encryption = SymmetricEncryption(key=b'Sixteen byte key')
            decrypted_data = symmetric_encryption.decrypt(self.nonce, self.ciphertext, self.tag)
            self.history_text.insert(tk.END, f"AES Descriptografado: {decrypted_data}\n")
            messagebox.showinfo("Descriptografia Simétrica", f"AES Descriptografado: {decrypted_data}")
        else:
            messagebox.showwarning("Acesso Negado", "Você precisa estar logado para descriptografar dados.")

    def encrypt_data_rsa(self):
        if hasattr(self, 'current_user'):
            text = self.text_entry.get().encode()
            self.ciphertext_rsa = self.asymmetric_encryption.encrypt(text)
            self.history_text.insert(tk.END, f"RSA Criptografado: {self.ciphertext_rsa}\n")
            messagebox.showinfo("Criptografia Assimétrica", f"RSA Criptografado: {self.ciphertext_rsa}")
        else:
            messagebox.showwarning("Acesso Negado", "Você precisa estar logado para criptografar dados.")

    def decrypt_data_rsa(self):
        if hasattr(self, 'current_user'):
            decrypted_data = self.asymmetric_encryption.decrypt(self.ciphertext_rsa)
            self.history_text.insert(tk.END, f"RSA Descriptografado: {decrypted_data}\n")
            messagebox.showinfo("Descriptografia Assimétrica", f"RSA Descriptografado: {decrypted_data}")
        else:
            messagebox.showwarning("Acesso Negado", "Você precisa estar logado para descriptografar dados.")

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, file_path)

    def encrypt_file_aes(self):
        pass

    def decrypt_file_aes(self):
        pass

    def encrypt_file_rsa(self):
        file_path = self.file_path_entry.get()
        if file_path:
            with open(file_path, 'rb') as file:
                data = file.read()
            ciphertext = self.asymmetric_encryption.encrypt(data)
            with open(file_path + ".rsa.txt", 'wb') as file:
                file.write(ciphertext)
            messagebox.showinfo("Sucesso", "Arquivo criptografado com RSA com sucesso.")

    def decrypt_file_rsa(self):
        file_path = self.file_path_entry.get()
        if file_path and file_path.endswith('.rsa.txt'):
            with open(file_path, 'rb') as file:
                ciphertext = file.read()
            decrypted_data = self.asymmetric_encryption.decrypt(ciphertext)
            with open(file_path[:-8] + ".txt", 'wb') as file:
                file.write(decrypted_data)
            messagebox.showinfo("Sucesso", "Arquivo descriptografado com RSA com sucesso.")

    def browse_multiple_files(self):
        self.file_paths = filedialog.askopenfilenames(filetypes=[("Text files", "*.txt")])
        if self.file_paths:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, "; ".join(self.file_paths))

    def encrypt_files_rsa(self):
        for file_path in self.file_paths:
            with open(file_path, 'rb') as file:
                data = file.read()
            ciphertext = self.asymmetric_encryption.encrypt(data)
            with open(file_path + ".rsa.txt", 'wb') as file:
                file.write(ciphertext)
        messagebox.showinfo("Sucesso", "Arquivos criptografados com RSA com sucesso.")

    def decrypt_files_rsa(self):
        for file_path in self.file_paths:
            if file_path.endswith('.rsa.txt'):
                with open(file_path, 'rb') as file:
                    ciphertext = file.read()
                decrypted_data = self.asymmetric_encryption.decrypt(ciphertext)
                with open(file_path[:-8] + ".txt", 'wb') as file:
                    file.write(decrypted_data)
        messagebox.showinfo("Sucesso", "Arquivos descriptografados com RSA com sucesso.")

    def back_to_login(self):
        self.encryption_window.destroy()
        self.root.deiconify()

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop() 
