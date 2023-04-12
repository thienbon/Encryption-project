import binascii
import hashlib
import base64
import hashlib
import os
import tkinter as tk
import uuid
from base64 import b64encode
from tkinter import filedialog
from tkinter import messagebox
from tkinter import ttk
from tkinter.filedialog import askopenfile
from base64 import b64decode

import pymysql
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from cryptography.hazmat.backends import default_backend as crypto_default_backend, default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from dotenv import load_dotenv

load_dotenv()
# need to create database "encryption_project" from command line before running this program
db = pymysql.connect(host=os.getenv('HOST'), user=os.getenv('DATABASE_USER'), passwd=os.getenv('DATABASE_PASSWORD'),
                     db=os.getenv('DATABASE_NAME'))
cursor = db.cursor()

# set email variable to null
emailGlobal = None


def loadModel():
    # create user table if not exists
    cursor.execute("""CREATE TABLE IF NOT EXISTS user (
        id INT(11) NOT NULL AUTO_INCREMENT,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        address VARCHAR(255) NOT NULL,
        phone VARCHAR(255) NOT NULL,
        dob VARCHAR(255) NOT NULL,
        data VARCHAR(255) ,
        data_encrypt VARCHAR(255) ,
        key_public VARCHAR(2048) NOT NULL,
        key_private LONGTEXT NOT NULL,
        vector_iv VARCHAR(2048) ,
        PRIMARY KEY (id)
    )""")

frame_styles = {"relief": "groove",
                "bd": 3,
                "fg": "#073bb3", "font": ("Arial", 9, "bold")}


def EncryptAES(key, password):
    secret_key = password[0:16].encode('utf-8')
    cipher = AES.new(secret_key, AES.MODE_CBC)
    data_encrypt = cipher.encrypt(pad(key, AES.block_size))
    iv = cipher.iv
    iv = iv.hex()
    data_encrypt = data_encrypt.hex()
    return data_encrypt, iv


def DecryptAES(data_encrypt, password, iv):
    # convert hex to byte
    iv = bytes.fromhex(iv)
    data_encrypt = bytes.fromhex(data_encrypt)
    secret_key = password[0:16].encode('utf-8')
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    data_encrypt = unpad(cipher.decrypt(data_encrypt), AES.block_size)
    return data_encrypt

class LoginPage(tk.Tk):

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)

        main_frame = tk.Frame(self, bg="#708090", height=431, width=626)  # this is the background
        main_frame.pack(fill="both", expand="true")

        self.geometry("626x431")  # Sets window size to 626w x 431h pixels
        self.resizable(0, 0)  # This prevents any resizing of the screen
        title_styles = {"font": ("Trebuchet MS Bold", 16), "background": "white", "fg": "black"}

        text_styles = {"font": ("Verdana", 14)
            , "background": "white", "fg": "black"}

        frame_login = tk.Frame(main_frame, bg="white", relief="groove",
                               bd=2)  # this is the frame that holds all the login details and buttons
        frame_login.place(rely=0.30, relx=0.17, height=130, width=400)

        label_title = tk.Label(frame_login, title_styles, text="Login Page")
        label_title.grid(row=0, column=0, columnspan=1)

        label_email = tk.Label(frame_login, text_styles, text="Email:")
        label_email.grid(row=1, column=0)

        label_pw = tk.Label(frame_login, text_styles, text="Password:")
        label_pw.grid(row=2, column=0)

        entry_email = ttk.Entry(frame_login, width=45, cursor="xterm")
        entry_email.grid(row=1, column=1)

        entry_pw = ttk.Entry(frame_login, width=45, cursor="xterm", show="*")
        entry_pw.grid(row=2, column=1)

        button = ttk.Button(frame_login, text="Login", command=lambda: getLogin())
        button.place(rely=0.70, relx=0.50)

        signup_btn = ttk.Button(frame_login, text="Register", command=lambda: get_signup())
        signup_btn.place(rely=0.70, relx=0.75)

        def get_signup():
            SignupPage()

        def getLogin():
            email = entry_email.get()
            global emailGlobal  # this is used to set the email variable to the email entered in the login page
            emailGlobal = email
            password = entry_pw.get()

            if validate(email, password):
                tk.messagebox.showinfo("Login Successful", "Welcome {}".format(email))
                root.deiconify()
                top.destroy()
            else:
                tk.messagebox.showerror("Information", "The Username or Password you have entered are incorrect ")

        def validate(email, password):
            # check if username and password are in the database
            cursor.execute("SELECT * FROM user WHERE email = %s", (email,))
            user = cursor.fetchone()
            if user is None:
                return False
            else:
                if check_password(user[2], password):
                    # signFileSHA256()
                    # verifySignSHA256()
                    return True
                else:
                    return False


class SignupPage(tk.Tk):

    def __init__(self, *args, **kwargs):

        tk.Tk.__init__(self, *args, **kwargs)

        main_frame = tk.Frame(self, bg="#3F6BAA", height=150, width=250)
        # pack_propagate prevents the window resizing to match the widgets
        main_frame.pack_propagate(0)
        main_frame.pack(fill="both", expand="true")

        self.geometry("250x150")
        self.resizable(0, 0)

        self.title("Registration")

        text_styles = {"font": ("Verdana", 10),
                       "background": "#3F6BAA",
                       "foreground": "#E1FFFF"}

        label_email = tk.Label(main_frame, text_styles, text="New Email:")
        label_email.grid(row=1, column=0)

        label_pw = tk.Label(main_frame, text_styles, text="New Password:")
        label_pw.grid(row=2, column=0)

        label_name = tk.Label(main_frame, text_styles, text="Name:")
        label_name.grid(row=3, column=0)

        # date of birth
        label_dob = tk.Label(main_frame, text_styles, text="Date of Birth:")
        label_dob.grid(row=4, column=0)

        # phone
        label_phone = tk.Label(main_frame, text_styles, text="Phone:")
        label_phone.grid(row=5, column=0)

        # address
        label_address = tk.Label(main_frame, text_styles, text="Address:")
        label_address.grid(row=6, column=0)

        entry_email = ttk.Entry(main_frame, width=20, cursor="xterm")
        entry_email.grid(row=1, column=1)

        entry_pw = ttk.Entry(main_frame, width=20, cursor="xterm", show="*")
        entry_pw.grid(row=2, column=1)

        entry_name = ttk.Entry(main_frame, width=20, cursor="xterm")
        entry_name.grid(row=3, column=1)

        entry_dob = ttk.Entry(main_frame, width=20, cursor="xterm")
        entry_dob.grid(row=4, column=1)

        entry_phone = ttk.Entry(main_frame, width=20, cursor="xterm")
        entry_phone.grid(row=5, column=1)

        entry_address = ttk.Entry(main_frame, width=20, cursor="xterm")
        entry_address.grid(row=6, column=1)

        button = ttk.Button(main_frame, text="Register", command=lambda: signup())
        button.grid(row=7, column=1)

        def signup():
            # Creates a text file with the Username and password
            email = entry_email.get()
            pw = entry_pw.get()
            name = entry_name.get()
            dob = entry_dob.get()
            phone = entry_phone.get()
            address = entry_address.get()
            validation = validate_user(email)
            if not validation:
                tk.messagebox.showerror("Information", "That Username already exists")
            else:
                password = hash_password(pw)
                # log password console

                keypublic, keyprivate = generate_keypair()
                keyprivate, vector = EncryptAES(keyprivate, password)
                sql = "INSERT INTO user (email, password, name, dob, phone, address, key_public, key_private, vector_iv) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
                val = (email, password, name, dob, phone, address, keypublic, keyprivate, vector)
                cursor.execute(sql, val)
                db.commit()
                tk.messagebox.showinfo("Registration Successful", "Welcome {}".format(email))
                global emailGlobal
                emailGlobal = email
                root.deiconify()
                top.destroy()

        def validate_user(email):
            # check if the username is already in the database
            user = cursor.execute("SELECT * FROM user WHERE email = '%s'" % email)

            if user:
                return False
            else:
                return True

        def generate_keypair():
            key = rsa.generate_private_key(
                backend=crypto_default_backend(),
                public_exponent=65537,
                key_size=2048
            )
            private_key = key.private_bytes(
                crypto_serialization.Encoding.PEM,
                crypto_serialization.PrivateFormat.TraditionalOpenSSL,
                crypto_serialization.NoEncryption()
            )
            public_key = key.public_key().public_bytes(
                crypto_serialization.Encoding.OpenSSH,
                crypto_serialization.PublicFormat.OpenSSH
            ).decode('utf-8')
            return (public_key, private_key)




class UpdatePageRegular(tk.Tk):

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        main_frame = tk.Frame(self, bg="#3F6BAA")
        # pack_propagate prevents the window resizing to match the widgets
        main_frame.pack_propagate(0)
        main_frame.pack(fill="both", expand="true")

        self.geometry("250x150")
        self.resizable(0, 0)

        self.title("Update information")

        text_styles = {"font": ("Verdana", 10),
                       "background": "#3F6BAA",
                       "foreground": "#E1FFFF"}
        label_name = tk.Label(main_frame, text_styles, text="Name:")
        label_name.grid(row=3, column=0)

        # date of birth
        label_dob = tk.Label(main_frame, text_styles, text="Date of Birth:")
        label_dob.grid(row=4, column=0)

        # phone
        label_phone = tk.Label(main_frame, text_styles, text="Phone:")
        label_phone.grid(row=5, column=0)

        # address
        label_address = tk.Label(main_frame, text_styles, text="Address:")
        label_address.grid(row=6, column=0)

        cursor.execute("SELECT * FROM user WHERE email = '%s'" % emailGlobal)
        user = cursor.fetchone()
        # set default values for the fields
        entry_name = ttk.Entry(main_frame, width=20, cursor="xterm")
        entry_name.insert(0, user[3])
        entry_name.grid(row=3, column=1)

        entry_dob = ttk.Entry(main_frame, width=20, cursor="xterm")
        entry_dob.insert(0, user[6])
        entry_dob.grid(row=4, column=1)

        entry_phone = ttk.Entry(main_frame, width=20, cursor="xterm")
        entry_phone.insert(0, user[5])
        entry_phone.grid(row=5, column=1)

        entry_address = ttk.Entry(main_frame, width=20, cursor="xterm")
        entry_address.insert(0, user[4])
        entry_address.grid(row=6, column=1)

        button = ttk.Button(main_frame, text="Update regular", command=lambda: update())
        button.grid(row=7, column=1)

        def update():
            # Creates a text file with the Username and password
            name = entry_name.get()
            dob = entry_dob.get()
            phone = entry_phone.get()
            address = entry_address.get()
            # log password console
            sql = "UPDATE user SET name = %s, dob = %s, phone = %s, address = %s WHERE email = %s"
            val = (name, dob, phone, address, emailGlobal)
            cursor.execute(sql, val)
            db.commit()
            tk.messagebox.showinfo("Update Successfully", "You updated your information {}".format(emailGlobal))
            root.deiconify()


class UpdatePagePassword(tk.Tk):

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)

        main_frame = tk.Frame(self, bg="#3F6BAA")
        # pack_propagate prevents the window resizing to match the widgets
        main_frame.pack_propagate(0)
        main_frame.pack(fill="both", expand="true")

        self.geometry("250x150")
        self.resizable(0, 0)

        self.title("Update information")

        text_styles = {"font": ("Verdana", 10),
                       "background": "#3F6BAA",
                       "foreground": "#E1FFFF"}

        label_pw = tk.Label(main_frame, text_styles, text="New Password:")
        label_pw.grid(row=2, column=0)

        entry_pw = ttk.Entry(main_frame, width=20, cursor="xterm", show="*")
        entry_pw.grid(row=2, column=1)

        button = ttk.Button(main_frame, text="Update password", command=lambda: update())
        button.grid(row=7, column=1)

        def update():
            cursor.execute("SELECT * FROM user WHERE email = '%s'" % emailGlobal)
            user = cursor.fetchone()
            password = entry_pw.get()
            new_password = hash_password(password)
            keyprivateBeforeEncrypt = DecryptAES(user[10], user[2], user[11])
            keyprivate, vector = EncryptAES(keyprivateBeforeEncrypt, password)
            cursor.execute("UPDATE user SET password = %s, key_private = %s, vector_iv = %s WHERE email = %s",
                           (new_password, keyprivate, vector, emailGlobal))
            db.commit()
            tk.messagebox.showinfo("Update Successfully", "You updated your password {}".format(emailGlobal))
            root.deiconify()
            # Trường hợp đổi passphase cần đảm bảo cặp khoá Kprivate, Kpublic không bị thay đổi. Tức
            # là khoá Kprivate được mã hoá ở bước 2.2 với passphase cũ, cần được mã hoá lại với
            # passphase mới


class MenuBar(tk.Menu):
    def __init__(self, parent):
        tk.Menu.__init__(self, parent)

        menu_file = tk.Menu(self, tearoff=0)
        self.add_cascade(label="Home", menu=menu_file)
        menu_file.add_command(label="Features", command=lambda: parent.show_frame(Some_Widgets))
        menu_file.add_separator()
        menu_file.add_command(label="Exit Application", command=lambda: parent.Quit_application())

        menu_help = tk.Menu(self, tearoff=0)
        self.add_cascade(label="Update information", menu=menu_help)
        menu_help.add_command(label="Change information regular", command=lambda: parent.ChangeInformationRegular())
        menu_help.add_command(label="Change information password", command=lambda: parent.ChangeInformationPassword())


def hash_password(text):
    """
        Basic hashing function for a text using random unique salt.
    """
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + text.encode()).hexdigest() + ':' + salt


def check_password(hashedText, providedText):
    """
        Check for the text in the hashed text
    """
    _hashedText, salt = hashedText.split(':')
    return _hashedText == hashlib.sha256(salt.encode() + providedText.encode()).hexdigest()


class MyApp(tk.Tk):

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        main_frame = tk.Frame(self, bg="#84CEEB", height=600, width=1024)
        main_frame.pack_propagate(0)
        main_frame.pack(fill="both", expand="true")
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        # self.resizable(0, 0) prevents the app from being resized
        # self.geometry("1024x600") fixes the applications size
        self.frames = {}
        pages = (Some_Widgets, PageOne, PageTwo, PageThree, PageFour)
        for F in pages:
            frame = F(main_frame, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame(Some_Widgets)
        menubar = MenuBar(self)
        tk.Tk.config(self, menu=menubar)

    def show_frame(self, name):
        frame = self.frames[name]
        frame.tkraise()

    def ChangeInformationRegular(self):
        UpdatePageRegular()

    def ChangeInformationPassword(self):
        UpdatePagePassword()

    def Quit_application(self):
        self.destroy()


class GUI(tk.Frame):
    def __init__(self, parent):
        tk.Frame.__init__(self, parent)
        self.main_frame = tk.Frame(self, bg="#BEB2A7", height=600, width=1024)
        # self.main_frame.pack_propagate(0)
        self.main_frame.pack(fill="both", expand="true")
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)


class Some_Widgets(GUI):  # inherits from the GUI class

    def __init__(self, parent, controller):
        def Encryptfile():
            key_session = get_random_bytes(16)
            cipher = AES.new(key_session, AES.MODE_CBC)
            iv = cipher.iv
            messagebox.showinfo("", "select file to encrypt")
            filepath = filedialog.askopenfilenames()
            for x in filepath:
                with open(x, "rb") as file:
                    original = file.read()
                    data_encrypt = cipher.encrypt(pad(original, AES.block_size))
                with open(x, "wb") as encrypted_file:
                    encrypted_file.write(key_session)
                    encrypted_file.write(iv)
                    encrypted_file.write(data_encrypt)

            if not filepath:
                messagebox.showerror("Error", "no file was selected, try again")
            else:
                messagebox.showinfo("", "files encrypted successfully!")

        def Decryptfile():
            messagebox.showinfo("", "select one or more files to decrypt")
            filepath = filedialog.askopenfilenames()
            for x in filepath:
                with open(x, "rb") as file:
                    key_session = file.read(16)
                    iv = file.read(16)
                    content = file.read()
            cipher = AES.new(key_session, AES.MODE_CBC, iv)
            for x in filepath:
                with open(x, "rb") as file:
                    data_decrypt = unpad(cipher.decrypt(content), AES.block_size)
                with open(x, "wb") as encrypted_file:
                    encrypted_file.write(data_decrypt)
            if not filepath:
                messagebox.showerror("Error", "no file was selected, try again")
            else:
                messagebox.showinfo("", "files decrypted successfully!")

        def SignFile():
            messagebox.showinfo("", "select one or more files to sign")
            filepath = filedialog.askopenfilenames()
            for x in filepath:
                cursor.execute("SELECT * FROM user WHERE email = %s", (emailGlobal,))
                user = cursor.fetchone()
                print('DecryptAES(user[10], user[2], user[11]): ', DecryptAES(user[10], user[2], user[11]))
                # convert hex to ascii
                private_key_after_decrypt = DecryptAES(user[10], user[2], user[11])
                # convert private_key_after_decrypt to ascii
                private_key = serialization.load_pem_private_key(
                    private_key_after_decrypt,
                    password=None,
                    backend=default_backend(),
                )

                # Create new sign file and write the data to it
                with open(x, "rb") as fileOrigin:
                    payload = fileOrigin.read()
                    print(payload)

                # Sign the payload file.
                signature = base64.b64encode(
                    private_key.sign(
                        payload,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )
                )

                with open(x + ".sign", 'wb') as sign_file:
                    sign_file.write(signature)
            if not filepath:
                messagebox.showerror("Error", "no file was selected, try again")
            else:
                messagebox.showinfo("", "files sign successfully!")
            return True

        def VerifySignSHA256():
            messagebox.showinfo("", "select one or more files to sign")
            filepath = filedialog.askopenfilenames()
            # Load the public key.
            cursor.execute("SELECT * FROM user WHERE email = %s", (emailGlobal,))
            user = cursor.fetchone()
            print('filepath: ', filepath)
            for x in filepath:
                public_key = load_pem_public_key(user[9].encode('ascii'), default_backend())
                # Load the payload contents and the signature.
                with open(x, 'rb') as f:
                    payload_contents = f.read()
                with open('signature.sig', 'rb') as f:
                    signature = base64.b64decode(f.read())

                    # Perform the verification.
                    public_key.verify(
                        signature,
                        payload_contents,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )

        GUI.__init__(self, parent)

        frame2 = tk.LabelFrame(self, frame_styles, text="Features")
        frame2.place(rely=0.05, relx=0.02, height=400, width=400)
        button1 = tk.Button(frame2, text="Upload to encrypt file", command=lambda: Encryptfile())
        button1.pack()
        button2 = ttk.Button(frame2, text="Decrypt file", command=lambda: Decryptfile())
        button2.pack()
        button4 = ttk.Button(frame2, text="upload file to sign", command=lambda: SignFile())
        button4.pack()
        button3 = ttk.Button(frame2, text="upload file to verify", command=lambda: VerifySignSHA256())
        button3.pack()


class PageOne(GUI):
    def __init__(self, parent, controller):
        GUI.__init__(self, parent)

        label1 = tk.Label(self.main_frame, font=("Verdana", 20), text="Page One")
        label1.pack(side="top")


class PageThree(GUI):
    def __init__(self, parent, controller):
        GUI.__init__(self, parent)

        label1 = tk.Label(self.main_frame, font=("Verdana", 20), text="Page Three")
        label1.pack(side="top")


class PageFour(GUI):
    def __init__(self, parent, controller):
        GUI.__init__(self, parent)

        label1 = tk.Label(self.main_frame, font=("Verdana", 20), text="Page Four")
        label1.pack(side="top")


class PageTwo(GUI):
    def __init__(self, parent, controller):
        GUI.__init__(self, parent)

        label1 = tk.Label(self.main_frame, font=("Verdana", 20), text="Page Two")
        label1.pack(side="top")

    def open_file():
        file_path = askopenfile(mode='r', filetypes=[('Files to encrypt', '*doc')])
        if file_path is not None:
            pass


class OpenNewWindow(tk.Tk):

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)

        main_frame = tk.Frame(self)
        main_frame.pack_propagate(0)
        main_frame.pack(fill="both", expand="true")
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        self.title("Here is the Title of the Window")
        self.geometry("500x500")
        self.resizable(0, 0)


loadModel()

top = LoginPage()
top.title("Tkinter App Template - Login Page")
root = MyApp()
root.withdraw()
root.title("Tkinter App Template")

root.mainloop()
# disconnect from server
db.close()
