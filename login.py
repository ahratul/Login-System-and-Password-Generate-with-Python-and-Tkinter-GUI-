from tkinter import *
import random, string
import pyperclip


def main_menu():
    global main_window
    main_window = Tk()
    main_window.geometry("300x300")
    main_window.title("Login System")
    Label1 = Label(main_window, text="Choose an option", bg="gray", fg="blue")
    Label1.pack(fill=X, pady=20)
    login_btn = Button(main_window, text="Login", width="30", height="2", command=login)
    login_btn.pack(pady=20)
    new_user_btn = Button(main_window, text="New User", width="30", height="2", command=new_user)
    new_user_btn.pack(pady=20)
    main_window.mainloop()


def login_verify():
    login = False
    user = username_verify.get()
    pwrd = password_verify.get()
    username_verify_entry.delete(0, END)
    password_verify_entry.delete(0, END)
    for line in open("credentials.txt", "r").readlines():
        login_info = line.split()
        if user == login_info[1] and pwrd == login_info[3]:
            login = True
    if login:
        print("Successfull")
    else:
        failed_login_window = Toplevel(login_window)
        failed_login_window.geometry("200x200")
        failed_login_window.title("Warning!")
        Label(failed_login_window, text="Try Again!", bg="gray", fg="blue").pack(fill=X, pady=20)
        ok_btn = Button(failed_login_window, text="OK", width="20", command=lambda: failed_login_window.destroy())
        ok_btn.pack(pady=20)


def login():
    global username_verify
    global password_verify
    global username_verify_entry
    global password_verify_entry
    global login_window

    login_window = Toplevel(main_window)
    login_window.geometry("300x300")
    login_window.title("login")
    label2 = Label(login_window, text="please enter your credintials below", bg="gray", fg="blue")
    label2.pack(fill=X, pady=20)
    credntials_panel = Frame(login_window)
    credntials_panel.pack(pady=20)

    username_verify = StringVar()
    password_verify = StringVar()

    username_label = Label(credntials_panel, text="Username: ")
    username_label.grid(row=0, column=0)
    username_verify_entry = Entry(credntials_panel, textvariable=username_verify)
    username_verify_entry.grid(row=0, column=1)

    Label(credntials_panel, text="").grid(row=1)

    password_label = Label(credntials_panel, text="Password: ")
    password_label.grid(row=2, column=0)
    password_verify_entry = Entry(credntials_panel, textvariable=password_verify, show="*")
    password_verify_entry.grid(row=2, column=1)

    login_btn = Button(login_window, text="Login", command=login_verify)
    login_btn.pack(pady=20)


def register():
    registered = False
    username_text = username.get()
    password_text = password.get()
    name_text = name.get()
    file = open("credentials.txt", "a")
    for line in open("credentials.txt", "r").readlines():
        login_info = line.split()
        if username_text == login_info[1]:
            registered = True
    if registered:
        file.close()
        username_entry.delete(0, END)
        password_entry.delete(0, END)
        name_entry.delete(0, END)
        failed_register_window = Toplevel(new_user_window)
        failed_register_window.geometry("200x200")
        failed_register_window.title("Failure!")
        Label(failed_register_window, text="The Username Already Exists", bg="gray", fg="blue").pack(fill=X, pady=20)
        ok_btn = Button(failed_register_window, text="Try Again", width="20",
                        command=lambda: failed_register_window.destroy())
        ok_btn.pack(pady=20)
    else:
        file.write("Username: " + username_text + " Password: " + password_text + " Name: " + name_text + "\n")
        file.close()
        username_entry.delete(0, END)
        password_entry.delete(0, END)
        name_entry.delete(0, END)
        successfull_register_window = Toplevel(new_user_window)
        successfull_register_window.geometry("200x200")
        successfull_register_window.title("Sucess!")
        Label(successfull_register_window, text="Successfull Register!", bg="gray", fg="blue").pack(fill=X, pady=20)
        ok_btn = Button(successfull_register_window, text="OK", width="20",
                        command=lambda: successfull_register_window.destroy())
        ok_btn.pack(pady=20)


def new_user():
    global new_user_window
    global username
    global password
    global username_entry
    global password_entry
    global name_entry
    global name

    new_user_window = Toplevel(main_window)
    new_user_window.geometry("500x500")
    new_user_window.title("New User")

    username = StringVar()
    password = StringVar()
    name = StringVar()

    label2 = Label(new_user_window, text="Please fill in the info below", bg="gray", fg="blue")
    label2.pack(fill=X, pady=20)

    user_info_panel = Frame(new_user_window)
    user_info_panel.pack(pady=20)

    username_label = Label(user_info_panel, text="Username: ")
    username_label.grid(row=0, column=0)
    username_entry = Entry(user_info_panel, textvariable=username)
    username_entry.grid(row=0, column=1)

    Label(user_info_panel, text="").grid(row=1)

    password_label = Label(user_info_panel, text="Password: ")
    password_label.grid(row=2, column=0)
    password_entry = Entry(user_info_panel, textvariable=password)
    password_entry.grid(row=2, column=1)

    Label(user_info_panel, text="").grid(row=3)

    name_label = Label(user_info_panel, text="Full name: ")
    name_label.grid(row=4, column=0)
    name_entry = Entry(user_info_panel, textvariable=name)
    name_entry.grid(row=4, column=1)

    pass_str = StringVar()

    def Generator():
        password = ''
        for n in range(8):
            password = password + random.choice(
                string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation)
        pass_str.set(password)

    def Copy_password():
        pyperclip.copy(pass_str.get())

    Generate = Button(new_user_window, text="GENERATE PASSWORD", command=Generator, padx=5, pady=5)
    Generate.configure(background="blue", foreground='white', font=('ariel', 10, 'bold'))
    Generate.pack(side=TOP, pady=20)
    Entry(new_user_window, textvariable=pass_str).pack()
    copy = Button(new_user_window, text='Copy The Password to Clipboard', command=Copy_password)
    copy.configure(background="blue", foreground='white', font=('ariel', 10, 'bold'))
    copy.pack(side=TOP, pady=20)

    register_btn = Button(new_user_window, text="Register", command=register)
    register_btn.pack()


main_menu()
