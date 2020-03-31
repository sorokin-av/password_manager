import hashlib
import secrets
import string
import tkinter as tk
from tkinter import messagebox as mb
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet

import sql_injections as sql


class MasterPasswordManager:
    def __init__(self, master):
        self.master = master
        self.master.geometry("400x220")
        self.master.title('Password Manager')
        self.frame = tk.Frame(self.master)

        self.sql = sql.Credentials()
        self.sql.create_master_pass_table()
        self.master_password_label = tk.Label(self.frame, text="Set master password:")
        self.master_password = tk.Entry(self.frame, width=20)
        self.insert_button = tk.Button(self.frame, text="Ok", command=self.insert_master_pass_into_db)

        self.master_password_label.grid(row=0, column=0, sticky="w")
        self.master_password.grid(row=0, column=1, padx=5, pady=5)
        self.insert_button.grid(row=1, column=0, padx=15, pady=5, sticky="e")

        self.frame.pack()

    def insert_master_pass_into_db(self):
        master_password_hash = hashlib.md5(self.master_password.get().encode()).hexdigest()
        self.sql.set_master_password(master_password_hash)
        mb.showinfo(title='SQL', message='Success!')
        self.master.destroy()


class PasswordManager:
    def __init__(self, master):
        self.master = master
        self.master.geometry("400x220")
        self.master.title('Password Manager')
        self.frame = tk.Frame(self.master)
        self.generate_button = self.new_button(text='Generate Password', button_class=GeneratePassword)
        self.set_button = self.new_button(text="Set Credentials", button_class=SetPassword)
        self.get_button = self.new_button(text="Get Credentials", button_class=GetPassword)
        self.delete_button = self.new_button(text="Delete Credentials", button_class=DeletePassword)
        self.update_button = self.new_button(text="Update Credentials", button_class=UpdatePassword)
        self.apply_grid_settings()
        self.frame.pack()

    def new_button(self, text, button_class):
        return tk.Button(self.frame, text=text, command=lambda: self.new_window(button_class))

    def new_window(self, button_class):
        self.new = tk.Toplevel(self.master)
        button_class(self.new)

    def apply_grid_settings(self):
        self.generate_button.grid(row=0, column=0, padx=5, pady=5)
        self.set_button.grid(row=1, column=0, padx=5, pady=5)
        self.get_button.grid(row=2, column=0, padx=5, pady=5)
        self.delete_button.grid(row=3, column=0, padx=5, pady=5)
        self.update_button.grid(row=4, column=0, padx=5, pady=5)


class BaseFormMixin:
    def __init__(self, master):
        self.master = master
        self.master.geometry("400x200")
        self.frame = tk.Frame(self.master)
        self.sql = sql.Credentials()
        self.sql.create_credentials_table()

        self.website_label = tk.Label(self.frame, text="Enter website name:")
        self.website = tk.Entry(self.frame, width=20)

        self.login_label = tk.Label(self.frame, text="Enter login:")
        self.login = tk.Entry(self.frame, width=20)

        self.master_password_label = tk.Label(self.frame, text="Enter master password:")
        self.master_password = tk.Entry(self.frame, width=20)

    def apply_grid_settings(self):
        self.website_label.grid(row=0, column=0, sticky="w")
        self.website.grid(row=0, column=1, padx=5, pady=5)

        self.login_label.grid(row=1, column=0, sticky="w")
        self.login.grid(row=1, column=1, padx=5, pady=5)

        self.master_password_label.grid(row=2, column=0, sticky="w")
        self.master_password.grid(row=2, column=1, padx=5, pady=5)

    @staticmethod
    def password_encrypt_decrypt(password: str, master_pass_hash: str, crypto_mode) -> str:
        key = urlsafe_b64encode(master_pass_hash.encode())
        f = Fernet(key)
        if crypto_mode == 'encrypt':
            password = password.encode()
            result = f.encrypt(password)
        elif crypto_mode == 'decrypt':
            password = password[0].encode()
            result = f.decrypt(password)
        else:
            raise ValueError('Wrong crypto mode: encrypt or decrypt')
        return result.decode()


class GeneratePassword:
    def __init__(self, master):
        self.master = master
        self.master.geometry("400x100")
        self.frame = tk.Frame(self.master)

        self.password_label = tk.Label(self.frame, text="Generated password:")
        self.password = tk.Entry(self.frame, width=20)

        self.generate_and_insert_password()
        self.apply_grid_settings()
        self.frame.pack()

    def apply_grid_settings(self):
        self.password_label.grid(row=0, column=0, sticky="w")
        self.password.grid(row=0, column=1, padx=5, pady=5)

    def generate_and_insert_password(self):
        alphabet = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(alphabet) for _ in range(15))
        self.password.insert(0, password)


class SetPassword(BaseFormMixin):
    def __init__(self, master):
        super().__init__(master)
        self.password_label = tk.Label(self.frame, text="Enter password:")
        self.password = tk.Entry(self.frame, width=20)
        self.insert_button = tk.Button(self.frame, text="Insert Into Database", command=self.insert_into_db)
        self.apply_grid_settings()
        self.frame.pack()

    def insert_into_db(self):
        expected_master_password_hash = hashlib.md5(self.master_password.get().encode()).hexdigest()
        if expected_master_password_hash == self.sql.get_master_password():
            if self.sql.get_credentials(website=self.website.get(), login=self.login.get()):
                mb.showerror(title='Error', message='Password is already set')
            else:
                encrypted_pass = self.password_encrypt_decrypt(password=self.password.get(),
                                                               master_pass_hash=expected_master_password_hash,
                                                               crypto_mode='encrypt')
                self.sql.set_credentials(website=self.website.get(), login=self.login.get(), password=encrypted_pass)
                mb.showinfo(title='SQL', message='Success!')
                self.master.destroy()
        else:
            mb.showerror(title='Error', message='Wrong Master Password')

    def apply_grid_settings(self):
        super().apply_grid_settings()
        self.password_label.grid(row=3, column=0, sticky="w")
        self.password.grid(row=3, column=1, padx=5, pady=5)
        self.insert_button.grid(row=4, column=0, padx=5, pady=5, sticky="e")


class GetPassword(BaseFormMixin):
    def __init__(self, master):
        super().__init__(master)
        self.select_button = tk.Button(self.frame, text="Select From Database", command=self.select_from_db)
        self.apply_grid_settings()
        self.frame.pack()

    def select_from_db(self):
        expected_master_password_hash = hashlib.md5(self.master_password.get().encode()).hexdigest()
        if expected_master_password_hash == self.sql.get_master_password():
            result = self.sql.get_credentials(website=self.website.get(), login=self.login.get())
            if result:
                password = self.password_encrypt_decrypt(password=result, master_pass_hash=expected_master_password_hash,
                                                         crypto_mode='decrypt')
                mb.showinfo(title='Password', message=password)
                self.master.destroy()
            else:
                mb.showinfo(title='Password', message='No such credentials')
        else:
            mb.showerror(title='Error', message='Wrong Master Password')

    def apply_grid_settings(self):
        super().apply_grid_settings()
        self.select_button.grid(row=4, column=0, padx=5, pady=5, sticky="e")


class DeletePassword(BaseFormMixin):
    def __init__(self, master):
        super().__init__(master)
        self.delete_button = tk.Button(self.frame, text="Delete From Database", command=self.delete_from_db)
        self.apply_grid_settings()
        self.frame.pack()

    def delete_from_db(self):
        expected_master_password_hash = hashlib.md5(self.master_password.get().encode()).hexdigest()
        if expected_master_password_hash == self.sql.get_master_password():
            self.sql.delete_credentials(website=self.website.get(), login=self.login.get())
            mb.showinfo(title='Info', message='Credentials have been deleted')
            self.master.destroy()
        else:
            mb.showerror(title='Error', message='Wrong Master Password')

    def apply_grid_settings(self):
        super().apply_grid_settings()
        self.delete_button.grid(row=4, column=0, padx=5, pady=5, sticky="e")


class UpdatePassword(BaseFormMixin):
    def __init__(self, master):
        super().__init__(master)
        self.new_password_label = tk.Label(self.frame, text="Enter new password:")
        self.new_password = tk.Entry(self.frame, width=20)
        self.update_button = tk.Button(self.frame, text="Update Database", command=self.update_db)
        self.apply_grid_settings()
        self.frame.pack()

    def update_db(self):
        expected_master_password_hash = hashlib.md5(self.master_password.get().encode()).hexdigest()
        if expected_master_password_hash == self.sql.get_master_password():
            encrypted_pass = self.password_encrypt_decrypt(password=self.new_password.get(),
                                                           master_pass_hash=expected_master_password_hash,
                                                           crypto_mode='encrypt')
            self.sql.update_credentials(website=self.website.get(), login=self.login.get(), password=encrypted_pass)
            mb.showinfo(title='Info', message='Credentials have been updated')
            self.master.destroy()
        else:
            mb.showerror(title='Error', message='Wrong Master Password')

    def apply_grid_settings(self):
        super().apply_grid_settings()
        self.new_password_label.grid(row=3, column=0, sticky="w")
        self.new_password.grid(row=3, column=1, padx=5, pady=5)
        self.update_button.grid(row=4, column=0, padx=5, pady=5, sticky="e")
