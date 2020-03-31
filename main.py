import tkinter as tk
from os import listdir, getcwd
from os.path import isfile, join

from manager import MasterPasswordManager, PasswordManager


if __name__ == '__main__':
    files_at_current_path = [file for file in listdir(getcwd()) if isfile(join(getcwd(), file))]

    if 'credentials.db' not in files_at_current_path:
        root = tk.Tk()
        mpm = MasterPasswordManager(root)
        mpm.master.mainloop()

    root = tk.Tk()
    pm = PasswordManager(root)
    pm.master.mainloop()
