import tkinter as tk
from tkinter import messagebox, simpledialog
import base91
from argon2.low_level import hash_secret_raw, Type
from cryptography.fernet import Fernet, InvalidToken
import os
import pyperclip
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

MASTER_KEY_FILE = "master.key"
PASSWORD_STORE_FILE = "passwords.enc"
FONT_NAME = "Quantico"
theme_mode = {"dark": True}

colors = {
    "dark": {
        "bg": "#1e1e1e",
        "fg": "#ffffff",
        "entry_bg": "#2e2e2e",
        "entry_fg": "#ffffff",
        "button_bg": "#3e3e3e",
        "button_fg": "#ffffff",
        "text_bg": "#1e1e1e",
        "text_fg": "#ffffff"
    },
    "light": {
        "bg": "#ffffff",
        "fg": "#000000",
        "entry_bg": "#f0f0f0",
        "entry_fg": "#000000",
        "button_bg": "#e0e0e0",
        "button_fg": "#000000",
        "text_bg": "#ffffff",
        "text_fg": "#000000"
    }
}

def apply_theme():
    theme = "dark" if theme_mode["dark"] else "light"
    color = colors[theme]
    root.config(bg=color["bg"])
    for widget in root.winfo_children():
        if isinstance(widget, (tk.Label, tk.Button, tk.Text)):
            widget.config(bg=color["bg"], fg=color["fg"], font=(FONT_NAME, 10))
        elif isinstance(widget, tk.Entry):
            widget.config(bg=color["entry_bg"], fg=color["entry_fg"], insertbackground=color["fg"], font=(FONT_NAME, 10))
        elif isinstance(widget, tk.Frame):
            widget.config(bg=color["bg"])
            for child in widget.winfo_children():
                if isinstance(child, (tk.Label, tk.Button)):
                    child.config(bg=color["bg"], fg=color["fg"], font=(FONT_NAME, 10))
                elif isinstance(child, tk.Entry):
                    child.config(bg=color["entry_bg"], fg=color["entry_fg"], insertbackground=color["fg"], font=(FONT_NAME, 10))



def derive_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data, password):
    salt = os.urandom(16)
    key = derive_aes_key(password, salt)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return salt + iv + ct  

def decrypt_data(encrypted, password):
    salt = encrypted[:16]
    iv = encrypted[16:32]
    ct = encrypted[32:]
    key = derive_aes_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

def save_master_password(password):
    encrypted = encrypt_data(password, password)
    with open(MASTER_KEY_FILE, "wb") as f:
        f.write(encrypted)

def verify_master_password(password):
    if not os.path.exists(MASTER_KEY_FILE):
        return False
    with open(MASTER_KEY_FILE, "rb") as f:
        encrypted = f.read()
    try:
        return decrypt_data(encrypted, password) == password
    except Exception:
        return False

def change_master_password():
    old_pass = simpledialog.askstring("Authentication", "ENTER CURRENT MASTER KEY:",show="*")
    if not verify_master_password(old_pass):
        messagebox.showerror("ERROR", "INCORRECT CURRENT MASTER KEY")
        return
    new_pass = simpledialog.askstring("NEW PASSWORD", "ENTER A NEW MASTER KEY:", show="*")
    if new_pass:
        save_master_password(new_pass)
        encrypt_existing_passwords(old_pass, new_pass)
        master_password_cache[0] = new_pass
        messagebox.showinfo("SUCCESS", "MASTER KEY UPDATED SUCCESSFULLY")

def encrypt_existing_passwords(old_password, new_password):
    if not os.path.exists(PASSWORD_STORE_FILE):
        return
    with open(PASSWORD_STORE_FILE, "rb") as f:
        try:
            old_data = decrypt_data(f.read(), old_password)
        except:
            old_data = ""
    with open(PASSWORD_STORE_FILE, "wb") as f:
        f.write(encrypt_data(old_data, new_password))

def store_password(word, salt, password, master_password):
    line = f"Word: {word} | Salt: {salt} | Password: {password}\n"
    if os.path.exists(PASSWORD_STORE_FILE):
        with open(PASSWORD_STORE_FILE, "rb") as f:
            try:
                decrypted = decrypt_data(f.read(), master_password)
            except:
                decrypted = ""
    else:
        decrypted = ""
    with open(PASSWORD_STORE_FILE, "wb") as f:
        f.write(encrypt_data(decrypted + line, master_password))

def access_stored_passwords():
    entered = simpledialog.askstring("AUTHENTICATE", "ENTER MASTER KEY TO ACCESS PASSWORDS:", show="*")
    if verify_master_password(entered):
        if os.path.exists(PASSWORD_STORE_FILE):
            with open(PASSWORD_STORE_FILE, "rb") as f:
                try:
                    content = decrypt_data(f.read(), entered)
                except Exception:
                    messagebox.showerror("ERROR", "FAILED TO DECRYPT PASSWORD FILE.")
                    return
            show_popup("STORED PASSWORDS", content)
        else:
            messagebox.showinfo("INFO", "NO PASSWORDS STORED YET.")
    else:
        messagebox.showerror("ERROR", "INVALID MASTER KEY")
        
def show_popup(title, content):
    top = tk.Toplevel(root)
    top.title(title)
    theme = "dark" 
    color = colors[theme]
    top.config(bg=color["bg"])
    text = tk.Text(top, wrap="word", font=(FONT_NAME, 10), bg=color["text_bg"], fg=color["text_fg"])
    text.insert("1.0", content)
    text.config(state='disabled')
    text.pack(expand=True, fill='both')


def delete_password():
    entered = simpledialog.askstring("AUTHENTICATE", "ENTER MASTER KEY TO DELETE A PASSWORD:", show="*")
    if verify_master_password(entered):
        if os.path.exists(PASSWORD_STORE_FILE):
            with open(PASSWORD_STORE_FILE, "rb") as f:
                try:
                    content = decrypt_data(f.read(), entered)
                except Exception:
                    messagebox.showerror("ERROR", "FAILED TO ENCRYPT PASSWORD FILE.")
                    return

            
            lines = content.split("\n")
            password_list = [line for line in lines if line.strip()]  

            if password_list:
                top = tk.Toplevel(root)
                top.title("STORED PASSWORDS(ENTER THE INDEX NUMBER)")
                theme = "dark"
                color = colors[theme]
                top.config(bg=color["bg"])

                
                
                
                password_display = "\n".join([f"{idx + 1}. {password}" for idx, password in enumerate(password_list)])
                text = tk.Text(top, wrap="word")
                text.insert("1.0", password_display)
                text.pack(expand=True, fill='both')
                theme = "dark"
                color = colors[theme]
                text.config(bg=color["bg"], fg="white",font=(FONT_NAME, 10))
                

                # index to delete password
                delete_index_entry = tk.Entry(top)
                delete_index_entry.pack(pady=10)
                delete_index_entry.insert(0, "")
                delete_index_entry.config(bg=color["bg"], fg="white",font=(FONT_NAME, 10))
                

                delete_button = tk.Button(top, text="DELETE SELECTED PASSWORD", command=lambda: delete_from_file(password_list, delete_index_entry.get(), entered))
                delete_button.pack(pady=10)
                theme = "dark"
                color = colors[theme]
                delete_button.config(bg=color["bg"], fg="white",font=(FONT_NAME))
                
            else:
                messagebox.showinfo("INFO", "NO PASSWORD STORED YET.")
        else:
            messagebox.showinfo("INFO", "NO PASSWORD STORED YET.")
    else:
        messagebox.showerror("ERROR", "INVALID MASTER KEY")

def delete_from_file(password_list, delete_index, password):
    try:
        delete_index = int(delete_index) - 1  
        if delete_index < 0 or delete_index >= len(password_list):
            raise ValueError("INVALID INDEX")

        # Remove selected password
        password_list.pop(delete_index)

        # saving
        updated_content = "\n".join(password_list)
        with open(PASSWORD_STORE_FILE, "wb") as f:
            f.write(encrypt_data(updated_content, password))
        messagebox.showinfo("SUCCESS", "PASSWORD DELETED SUCCESSFULLY")
    except ValueError as ve:
        messagebox.showerror("Error", str(ve))

def type_password(label, password):
    label.config(fg="lightblue")  
    def type_character(index=0):
        if index < len(password):
            label.config(text=password[:index + 1])  
            label.after(50, type_character, index + 1)  #delay for typing effect
    type_character()


def generate_password(word_entry, salt_entry, output_label):
    word = word_entry.get()
    salt = salt_entry.get()
    word_entry = tk.Entry(root, font=("Arial", 14), width=20, show="*")  
    word_entry.pack(pady=5)

    salt_entry = tk.Entry(root, font=("Arial", 14), width=20, show="*")  
    salt_entry.pack(pady=5)

    if not word or not salt:
        messagebox.showwarning("MISSING INPUT", "PLEASE ENTER BOTH WORD AND SALT.")
        return
    try: 
        word_bytes = word.encode()
        salt_bytes = salt.encode()
        hashed = hash_secret_raw(
            secret=word_bytes,
            salt=salt_bytes,
            time_cost=15,
            memory_cost=2**17,
            parallelism=4,
            hash_len=17,
            type=Type.I
        )
        hex_hash = hashed.hex()
        reversed_hex = hex_hash[::-1]
        b91_encoded = base91.encode(reversed_hex.encode())
        final_password = b91_encoded[::-1]
        type_password(output_label, final_password)
        store_password(word, salt, final_password, master_password_cache[0])
    except Exception as e:
        messagebox.showerror("ERROR", f"ERROR GENERATING PASSWORD: {str(e)}")

def clear_fields():
    word_entry.delete(0, tk.END)
    salt_entry.delete(0, tk.END)
    output_label.config(text="")

def copy_to_clipboard():
    password = output_label.cget("text")
    if password:
        pyperclip.copy(password)
        messagebox.showinfo("COPIED", "PASSWORD COPIED TO CLIPBOARD!")

def clear_database():
    master_pass = simpledialog.askstring("AUTHENTICATION", "ENTER MASTER KEY TO CLEAR DATABASE:\n\nWARNING: THIS WILL DELETE ALL STORED PASSWORDS.", show="*")
    if verify_master_password(master_pass):
        if os.path.exists(PASSWORD_STORE_FILE):
            os.remove(PASSWORD_STORE_FILE)
            messagebox.showinfo("SUCCESS", "ALL THE PASSWORDS ARE WIPED.")
        else:
            messagebox.showinfo("INFO", "DATABASE ALREADY EMPTY.")
    else:
        messagebox.showerror("ERROR", "INVALID MASTER KEY")

def initialize_master():
    if not os.path.exists(MASTER_KEY_FILE):
        if os.path.exists(PASSWORD_STORE_FILE):
            messagebox.showerror(
                                  "SECURITY WARNING",
                                  "THE MASTERKEY FILE SEEMS TO BE MISPLACED OR DELETED.\nPLEASE RESTORE THE MASTERKEY FILE TO CONTINUE.\n"
            )
            root.destroy()
            return



        pwd = simpledialog.askstring("SETUP", "SET A MASTER KEY:", show="*")
        if pwd:
            save_master_password(pwd)
            master_password_cache.append(pwd)
            messagebox.showinfo("SUCCESS", "MASTER KEY SET SUCCESSFULLY")
        else:
            root.destroy()
    else:
        pwd = simpledialog.askstring("LOGIN", "ENTER YOUR MASTER KEY:", show="*")
        if pwd and verify_master_password(pwd):
            master_password_cache.append(pwd)
        else:
            messagebox.showerror("ACCESS DENIED", "INVALID MASTER KEY")
            root.destroy()

def open_about_window():
    # Create a new top-level window
    about_window = tk.Toplevel(root)
    about_window.title("DOCUMENTATION")
    about_window.configure(bg=colors["dark"]["bg"])  

    # about windows frame
    about_content_frame = tk.Frame(about_window, bg=colors["dark"]["bg"])
    about_content_frame.pack(padx=10, pady=10, fill="both", expand=True)

    # scrollbar
    scrollbar = tk.Scrollbar(about_content_frame, orient="vertical")
    scrollbar.pack(side="right", fill="y")

    about_text = tk.Text(
        about_content_frame,
        font=(FONT_NAME, 16),
        fg=colors["dark"]["fg"],
        bg=colors["dark"]["bg"],
        wrap="word",  
        yscrollcommand=scrollbar.set,  
        padx=10,
        pady=10
    )
    about_text.pack(side="left", fill="both", expand=True)
    scrollbar.config(command=about_text.yview)  

    #text
    about_text.insert("1.0",'''
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠔⢚⡭⠗⠋⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⣠⢶⡝⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⢯⢀⡟⠉⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣞⢹⠊⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠻⣄⣴⠋⠀⣠⣰⣇⣴⠁⡀⣤⠀⠀⠀⢀⡠⠾⣅⠀⡏⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡞⠒⣤⣼⣥⣴⠋⠁⠙⢿⡷⠾⣿⣧⣴⠲⢮⡉⠲⡀⢘⡞⠤⠤⠤⣐⡶⠦⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡾⣽⡩⣏⡴⠈⠉⣢⠵⠒⠒⠛⢢⡞⠙⠆⠀⢱⠀⢱⢀⡵⠋⠀⢀⡴⠋⠁⠀⣀⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⠙⢋⢾⢇⢔⡁⣩⡞⠉⠁⣠⣶⣶⣢⠈⠻⡄⠉⠀⠈⣠⠴⠋⠀⠀⠀⠈⢁⣠⠽⠛⠋⠁⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣿⡹⠓⡹⠓⠣⡀⡼⢹⠁⠀⣸⣿⣧⢽⡎⠀⡀⠰⣤⣖⠟⠃⠀⠀⠀⠀⠀⢰⠋⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⠾⠃⠈⠳⡄⣠⠊⠀⡇⢠⣾⣁⣘⡻⠼⠷⠾⠛⢁⣀⡈⢢⡀⠀⠀⠀⠀⠀⠸⣦⣀⡀⠀⠀⠀⠀
⠀⢀⣤⠤⢤⣠⡞⢁⣀⣄⡀⠀⠈⠁⠀⠔⠓⠋⠉⠀⠀⠀⠀⠀⠀⠀⣨⡾⢺⡆⢻⡧⠀⠀⠀⠀⠀⠀⢠⠜⠋⠀⠀⠀
⠀⡟⠁⠣⠀⠉⢒⡿⠃⠀⠪⣷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣾⢋⣿⡀⢣⠀⣷⣄⣤⣤⣤⣤⣤⣄⣙⠢⣀⠀⠀
⢀⣇⠀⠀⠀⠐⠁⠀⢀⣦⣢⠈⠁⠉⠂⠄⠀⠀⠀⠀⠀⣠⠞⢋⡽⠃⠸⢸⡇⠀⠃⠹⡆⠀⠀⣿⡉⠉⠈⠉⠙⠚⢷⡀
⢸⢹⠀⠀⠒⠃⠀⡇⡾⠟⠈⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣯⣶⡿⠁⠀⢁⠞⠁⠀⠀⢀⡷⡤⣤⣤⣭⣓⠢⣄⠀⠀⠀⠉
⣿⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⣶⣿⠻⣿⣿⡯⡿⣿⡿⠋⠀⠀⠐⠁⠀⠀⠀⢀⡾⢷⣤⡀⠈⡟⠛⠛⠲⢽⣆⠀⠀
⠈⢷⣤⣀⡀⠀⠀⠀⣀⣴⡿⢽⡍⠃⠀⠓⠇⢈⣠⣾⡜⠁⠀⢀⡴⠊⠁⠀⣠⡴⡿⡄⠀⠈⠛⢷⣜⢦⡀⠀⠀⠉⠃⠀
⠀⠈⠯⠙⠛⠷⠶⠚⠉⢠⣇⠀⠀⠀⢀⣠⣴⣾⣿⠎⠀⣠⠾⢋⣀⣤⣴⠺⠙⠋⠀⠸⡄⠀⠀⠀⢹⣷⣷⡄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣀⠀⢀⣞⣾⡄⠀⢠⣿⣿⣷⠟⠁⣠⣾⠥⠚⠋⠉⢳⣌⠳⡉⠀⣀⠔⢣⠀⠀⠀⠈⣧⠘⢿⡄⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢻⣦⣿⣯⡼⣙⣶⣯⡿⠟⠁⣠⠞⠋⠀⠀⠀⠀⠀⠀⢻⠉⢫⠉⠀⠀⢸⠀⠀⠀⠀⣿⣇⠀⢻⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⣷⠯⠿⠿⠿⠛⡉⠀⣠⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⢸⡄⢸⠀⠀⠀⣸⢀⠀⠀⠀⣿⠹⡄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣿⢷⣦⣠⣾⣴⣧⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠳⢼⠠⠴⠚⡝⠀⠀⠀⢀⣿⡆⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠘⢮⡇⡿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠏⢠⠃⠀⠀⡰⠁⠀⠀⠀⢸⠀⠇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⢫⡠⠃⠀⢀⡜⠁⠀⠀⠀⢀⡏⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⠞⢁⡜⠉⠉⣩⠋⠀⠀⠀⠀⠀⡞⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣈⡿⠛⠉⢹⡠⠊⠀⣠⠞⠁⠀⠀⠀⠀⢀⠞⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠤⠔⠚⠉⠀⠀⠀⠀⠀⣑⠖⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀           
                            GODFREY KEYGEN

This project is open source under the "Do whatever, but please give me credits" license.

Disclaimer: This tool is solely built on purpose of education.IF YOUR INTENT IS BAD,YOUR FBI AGENT IS GOING TO RAID
YOUR HOUSE TONIGHT.But I definitely recommend you to collaborate and contribute to become a hero for this society.

This tool was made by a hacker, to protect you from hackers.
Built By DISHANT alias RETZ. So don't try to claim or steal it or else the First Elden lord will make
you cower in fear.
Just like you, even I never remembered my passwords.
But I never trusted myself with a password manager.
You ever trusted a cloud-based password manager, a thing that is literally CONNECTED to the internet???
Bro your entire digital vault is sitting on someone else's server, and you can't even peek under the hood to see
what's really going on.
I know you can't sniff networks, but I can; that's what forces me to stay offline.
I agree we will be going passwordless in just few years,the quantum computing is gonna break our encryption systems,
and hashing algorithms but till then we cannot just let the hackers to harvest our data for tomorrow.

Let's cut the crap and go to main documentation.

Godfrey Keygen is a secure and offline Python-based password manager built with Tkinter.
It focuses on extremely secure password generation, functionality and a friendly user experience.
THE BASIC IDEA OF THIS TOOL IS FOR THE USER TO REMEMBER ONLY THE USERNAME AND A SINGLE SALT PHRASE,
AND YOU SHALL BECOME THE ALMIGHTY OF ALL PASSWORDS.

Technologies used:

1)Python
2)Tkinter for GUI
3)Argon2(argon2-cffi library)
4)Cryptography module
5)Base encoding libraries.

AUTHENTICATION:

A new user is prompted with a dialog box to set up a 'Master Key'.
User can set the 'Master Key' as per their will
The 'Master Key' is stored in a KEY file encrypted with AES-256 CBC Encryption.
The tool and author expects user to keep master key as unique and simple.
And next time user returns, the tool will ask user to authenticate with the master key
as set previously.
Master key can also be changed, by entering the current master key.
The master key will be used for following purposes:
1)Authentication
2)Accessing stored passwords
3)Deleting stored passwords
4)Deleting entire database that includes all stored passwords.
5)Update the master key with new.

WORKING AND FUNCTIONALITY:

This tool relies on the core concept of cryptography i.e hashing.
A secure password is generated via accepting a word from the user and hashing it with a
custom salt that user chooses.

The flowchart towards the secure password generation is as follows:-
➤ A "WORD" and "SALT" is accepted from user.
➤ Argon2-cffi algorithm hashes the word along with its salt.
➤ The generated "Binary Hash" is converted to "Hexadecimal Hash"
➤ The "Hexadecimal Hash" is then reversed.
➤ The reversed Hex Hash is encoded with Base-91 encoding.
➤ The Base-91 encoding is entropic as it contains numbers,both uppercase, lowercase and special characters.
➤ And the reverse Base-91 string becomes our password.
➤ To this password generation, endless possibilities exist, just so you know sky is the limit.
➤ You are free to try your own mind bending techniques to generate strongest possible password.

TOOL SETTINGS:-
1)Memory-cost=2^17(128MB)
The tool uses 128 megabytes of RAM per hash.
Attacker's GPUs struggle to crack due to this setting.
The melting heat of their GPUs will definitely cause global warming.

2)Parallelism= 4 threads in parallel.
Makes it difficult to attack in parallel.
I don't fight solo, 4 blades, all single handedly.

3)hash-len=17bytes(136bits)
This will give us 2^136 possible combinations, meaning hacker has to try
87 OCTILLION OCTILLION possibilities.HAHA!!!
Prevents the possibility of two different inputs giving out same hash input i.e Collision 

4)Time-cost=15 iterations.
Each 'WORD' goes through 15 cycles of being hashed.
I'll make you feel the pain, each cycle.


STANDARD FORMAT:

There is no standard format to choose your 'WORD' and 'SALT'.
For those who did not understand what does 'WORD' and 'SALT' mean,
Here is entire explaination for them.
Consider 'WORD' as a normal word,
which is to be processed to form a hash.
(HASH:- Hash is a one way mathematical function, that is widely used in world of internet,
especially for storing confidential stuff like passwords)
'SALT' is a random string,or say a key which we add in process of forming HASH to make it
difficult to be broken by hackers.
The more random is 'SALT' the more entropy is generated and generated hash becomes almost crack-proof.

Say if it is a password for email, your email username becomes your password itself, but slightly changed.
Example:- Lets say there is an email of a person, peterparker123@gmail.com
So making it simplest, our 'WORD' becomes peterparker.
You can keep anything as 'WORD' whatever you feel secure.
That's it.
Talking about salt, you must keep it a VERY SECRET.
MOST IMPORTANTLY, IT HAS TO BE MINIMUM '8 CHARACTERS'
Now it is upto you what efficient salt standard you choose.
But make sure to include BOTH LOWER AND UPPERCASE CHARACTERS,SPECIAL CHARACTERS AND NUMBERS.
You worried huh?
Don't be.
You just have to remember that one single phrase or lyrics or any line, that only you must know.
It has to be so secret that not even GOD could guess it.
That could be a childhood joke or whatever you can think of.
Use that one single phrase of your life as a 'Salt' in every password.
And you will be good in every possible way.
This is optional yet safest way.
If you have big brain, keep different salt for every different password.
Because the motive of this tool is to make you remember only your username and a single salt phrase.
And you are done, you have every single password in your fist.

HOW SECURE YOU ARE:-
You will be immune to these attacks:-

1)Rainbow Table Attacks
➤ In this attack, attacker uses a precomputed list of hashes for common passwords, which if matched,
the password is compromised.
Since our tool uses unique username everytime, and a very secret salt phrase(complex than nuclear codes),
a very unique hash is generated each time, which is impossible to be precomputed.
It will take THOUSAND TO MILLION years to get that hash to be guessed.

2)Brute Force Attack:-
➤ This attack is nothing but a joke for our tool, the time it will take to guess the password will be
around extinction of universe.

3)Reverse Engineering:-
➤ If your system gets stolen along with this tool and saved passwords, not an issue.
The tool is completely offline.
The password is encrypted with master key, which the User only knows.
So there's no way attacker is going to waste his time on salvaging the encrypted unreadable gibberish.
If the system is gone permanently, you get another system, download this tool
and re-generate your passwords with same 'WORD' and 'SALT'.
DAMNN!!! SUCH A SUPER POWER. ISN'T IT
And no attacker could actually break it using normal systems,
even a supercomputer would cry doing it.
Just quantum computers are yet to take that challenge.

THINGS YOU NEED TO REMEMBER:-

➤Nothing in the world exist is hack-proof.
➤You own your security, you are responsible for your actions,
so always be cautious in the world of internet.
➤Always keep an eye on emails and login alerts of different platforms.
➤Never login your primary email on unknown computers.
➤Remove email access from the apps or services which were not used for a long time.


This isn't just a password tool.It's a fortress built with logic, layered in encryption.
I didn't make it only to generate password, but also manage the passwords and store it securely.

REMEMBER THE RECIPE, SALT IT AS PER YOUR TASTE, ENJOY THE DISH.

''')
    about_text.config(state="disabled")

#  the main window
root = tk.Tk()
root.title("GODFREY KEYGEN")

# screen dimensions
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

# Calculate window size (80% of screen size)
window_width = int(screen_width * 0.8)
window_height = int(screen_height * 0.8)

# centre of wimdow
x_position = (screen_width - window_width) // 2
y_position = (screen_height - window_height) // 2

#window size and position
root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
root.minsize(int(screen_width * 0.5), int(screen_height * 0.5))  # Minimum size


root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

master_password_cache = []
initialize_master()

#ASCII ART Section 
ascii_art = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⡴⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣶⣿⣿⣿⡅⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣤⣤⣤⣴⣿⣿⣿⣿⣯⣤⣶⣶⣾⣿⣶⣶⣿⣿⣿⣿⣿⡿⠿⠟⠛⠉⠉⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠉⠁⠈⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣶⠶⠶⠦⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⡿⠟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣟⣡⣤⣾⣿⣿⣿⣿⣿⣿⢏⠉⠛⣿⣿⣿⣿⣿⣿⣿⣿⣿⡻⢿⣿⣿⣦⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣀⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠈⠻⡄⠁⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠈⠙⢧⠀⠀⠀
⠀⠀⠀⠀⢰⣿⣿⣿⣿⡿⠛⠉⠉⠉⠛⠛⠛⠛⠋⠁⠀⠀⠀⠁⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠁⠀⠀
⠀⠀⠀⠀⠀⠙⠿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠙⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⢹⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠋⠁⠀⠀⠀⠀⠈⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠛⢋⣩⡿⠿⠿⠟⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀
⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⣄⣀⡀⠀⠀⠀⠀⠀⠐⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣾⣿⣿⣿⣿⣿⣿⣿⠻⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⢿⣶⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢰⣿⣿⣿⣿⣿⣿⣿⣿⡄⠙⢿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠠⣤⣀⠀⠀⠀⠠⣄⣀⣀⡉⢻⣿⣿⣿⣶⣄⡀⠀⠀⠀⠀⠀⠀⠀
⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣦⣤⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡀⠀⠀⠀⠀
⠀⢻⡟⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠛⠋⠉⠀⠀⢀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀
⠀⠀⠃⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣶⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠈⠉⠻⢿⣿⣿⣿⣷⡄
⠀⠀⠀⠀⢸⣿⣿⡟⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠛⠛⣿⣿⣿⣿⣿⣧⣀⣀⡄⠀⠀⠀⠀⠀⠀⠈⣿⡿⣿⣿⣷⠀
⠀⠀⠀⠀⢸⣿⡿⠁⠀⠀⠀⠙⠻⠿⣟⠻⢿⣿⣿⣿⣷⣦⡀⠀⠈⠻⢿⣿⣿⣭⣉⡉⠀⠀⠀⠀⠀⠀⠀⠀⠘⠀⠸⣿⣿⡄
⠀⠀⠀⠀⣸⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⢿⣿⣿⣦⡀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠁
⠀⠀⠀⠠⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀   
"""

#Combined Center Container
center_container = tk.Frame(root, bg=colors["dark"]["bg"])
center_container.pack(pady=10, fill='both', expand=True)

center_container.grid_columnconfigure(0, weight=1)
center_container.grid_columnconfigure(1, weight=1)

# Left side:ASCII art 
ascii_frame = tk.Frame(center_container, bg=colors["dark"]["bg"])
ascii_frame.grid(row=0, column=0, sticky="nsew", padx=(20, 0))  

ascii_box = tk.Text(ascii_frame,
                    height=28,
                    font=(FONT_NAME, 10),
                    bg=colors["dark"]["bg"],
                    fg=colors["dark"]["fg"],
                    bd=0,
                    wrap="none")
ascii_box.insert("1.0", ascii_art)   
ascii_box.config(state="disabled")  #no edit  
ascii_box.pack(fill='both', expand=True)

#Right side:Fixed big text 
text_frame = tk.Frame(center_container, bg=colors["dark"]["bg"])
text_frame.grid(row=0, column=1, sticky="nsew", padx=(0, 20))  

big_text_label = tk.Label(text_frame,
                          text="GODFREY",
                          font=(FONT_NAME, int(window_height * 0.2)),  # Responsive font size
                          fg=colors["dark"]["fg"],
                          bg=colors["dark"]["bg"])
big_text_label.pack(expand=True)

# Main content frame
content_frame = tk.Frame(root, bg=colors["dark"]["bg"])
content_frame.pack(fill='both', expand=True, padx=20, pady=20)

# Labels and Entries 
tk.Label(content_frame, text="ENTER THE WORD", font=(FONT_NAME, int(window_height * 0.02)), bg=colors["dark"]["bg"], fg=colors["dark"]["fg"]).pack(pady=5)
word_entry = tk.Entry(content_frame, width=40, font=(FONT_NAME, int(window_height * 0.02)), show="*", bg=colors["dark"]["entry_bg"], fg=colors["dark"]["entry_fg"], insertbackground=colors["dark"]["fg"])
word_entry.pack(pady=5)

tk.Label(content_frame, text="ENTER THE SALT", font=(FONT_NAME, int(window_height * 0.02)), bg=colors["dark"]["bg"], fg=colors["dark"]["fg"]).pack(pady=5)
salt_entry = tk.Entry(content_frame, width=40, font=(FONT_NAME, int(window_height * 0.02)), show="*", bg=colors["dark"]["entry_bg"], fg=colors["dark"]["entry_fg"], insertbackground=colors["dark"]["fg"])
salt_entry.pack(pady=5)

# Generate Password button
generate_btn = tk.Button(content_frame, 
                        text="GENERATE PASSWORD", 
                        command=lambda: generate_password(word_entry, salt_entry, output_label),
                        font=(FONT_NAME, int(window_height * 0.02)),
                        bg=colors["dark"]["button_bg"],
                        fg=colors["dark"]["button_fg"])
generate_btn.pack(pady=10)

# Output Label Frame
output_frame = tk.Frame(root, bg=colors["dark"]["bg"])
output_frame.pack(fill='x', padx=20, pady=10)
tk.Label(output_frame, 
         text="GENERATED PASSWORD:", 
         font=(FONT_NAME, 10), 
         bg=colors["dark"]["bg"],
         fg=colors["dark"]["fg"]
).pack(side='left', padx=5)
output_label = tk.Label(output_frame, 
                       text="", 
                       fg="lightblue",
                       font=(FONT_NAME, 10),
                       bg=colors["dark"]["bg"])
output_label.pack(side='left', padx=5)

#First row-COPY and CLEAR buttons 
left_buttons_frame = tk.Frame(root, bg=colors["dark"]["bg"])
left_buttons_frame.pack(side='left', padx=20, pady=10)

copy_btn = tk.Button(left_buttons_frame, 
                     text="COPY", 
                     command=copy_to_clipboard, 
                     width=15, 
                     height=2,
                     font=(FONT_NAME, 50), 
                     bg=colors["dark"]["button_bg"], 
                     fg=colors["dark"]["button_fg"])
copy_btn.pack(pady=5)

clear_btn = tk.Button(left_buttons_frame, 
                      text="CLEAR", 
                      command=clear_fields, 
                      width=15, 
                      height=2,
                      font=(FONT_NAME, 50), 
                      bg=colors["dark"]["button_bg"], 
                      fg=colors["dark"]["button_fg"])
clear_btn.pack(pady=5)

#Center frame for middle and bottom buttons
center_buttons_frame = tk.Frame(root, bg=colors["dark"]["bg"])
center_buttons_frame.pack(expand=True, fill='both', padx=20, pady=10)

#Second row-ACCESS and CLEAR DATABASE centered
middle_row = tk.Frame(center_buttons_frame, bg=colors["dark"]["bg"])
middle_row.pack(fill='x', pady=10)

middle_row.grid_columnconfigure(0, weight=1)
middle_row.grid_columnconfigure(1, weight=1)
middle_row.grid_columnconfigure(2, weight=1)

access_btn = tk.Button(middle_row, 
                       text="ACCESS STORED PASSWORDS", 
                       width=25, 
                       height=1,
                       command=access_stored_passwords, 
                       font=(FONT_NAME, 20), 
                       bg=colors["dark"]["button_bg"], 
                       fg=colors["dark"]["button_fg"])
access_btn.grid(row=0, column=0, padx=5, sticky='ew')

#CHANGE MASTER KEY button
change_master_btn = tk.Button(middle_row, 
                              text="CHANGE MASTER KEY", 
                              width=25, 
                              height=1,
                              command=change_master_password, 
                              font=(FONT_NAME, 20), 
                              bg=colors["dark"]["button_bg"], 
                              fg=colors["dark"]["button_fg"])
change_master_btn.grid(row=0, column=1, padx=5, sticky='ew')

clear_db_btn = tk.Button(middle_row, 
                         text="CLEAR DATABASE", 
                         width=25, 
                         height=1,
                         command=clear_database, 
                         font=(FONT_NAME, 20), 
                         bg=colors["dark"]["button_bg"], 
                         fg=colors["dark"]["button_fg"])
clear_db_btn.grid(row=0, column=2, padx=5, sticky='ew')

# Third row 
bottom_row = tk.Frame(center_buttons_frame, bg=colors["dark"]["bg"])
bottom_row.pack(fill='x', pady=10)

# Left spacer
left_spacer = tk.Frame(bottom_row, bg=colors["dark"]["bg"])
left_spacer.pack(side='left', expand=True, fill='x')

delete_btn = tk.Button(bottom_row, 
                       text="DELETE STORED PASSWORD", 
                       width=25, 
                       height=1,
                       command=delete_password, 
                       font=(FONT_NAME, 20), 
                       bg=colors["dark"]["button_bg"], 
                       fg=colors["dark"]["button_fg"])
delete_btn.pack(side='left', padx=10)

docs_btn = tk.Button(bottom_row, 
                     text="DOCUMENTATION", 
                     width=25, 
                     height=1,
                     command=open_about_window, 
                     font=(FONT_NAME, 20), 
                     bg=colors["dark"]["button_bg"], 
                     fg=colors["dark"]["button_fg"])
docs_btn.pack(side='left', padx=10)

# Right spacer
right_spacer = tk.Frame(bottom_row, bg=colors["dark"]["bg"])
right_spacer.pack(side='left', expand=True, fill='x')

# resizable
root.resizable(True, True)

apply_theme()
root.mainloop()
