import tkinter as tk
import customtkinter as ctk
import serial


class Locker:
    def __init__(self, locker_number):
        self.locker_number = locker_number
        self.password = ""
        self.locked = False
        self.master_password = "88888888"

    def lock(self, password=""):
        if password and 4 <= len(password) <= 8:
            self.password = password
            self.locked = True
            return f"Casier {self.locker_number} est verrouillé."
        else:
            return "Mot de passe invalide. Le casier n'a pas été verrouillé."

    def unlock(self, password=""):
        if not self.locked:
            return f"Le casier {self.locker_number} est déjà déverrouillé."
        elif password == self.password or password == self.master_password:
            self.locked = False
            return f"Casier {self.locker_number} est déverrouillé."
        else:
            return "Mot de passe incorrect."

    def is_locked(self):
        return self.locked


class LockerManager:
    def __init__(self, numb_lockers):
        self.lockers = {}
        for i in range(1, numb_lockers + 1):
            self.lockers[i] = Locker(i)

    def lock_locker(self, locker_number, password):
        if locker_number in self.lockers:
            message = self.lockers[locker_number].lock(password)
            return message
        else:
            return "Ce casier n'existe pas."

    def unlock_locker(self, locker_number, password):
        if locker_number in self.lockers:
            message = self.lockers[locker_number].unlock(password)
            return message
        else:
            return "Ce casier n'existe pas."

    def is_locked(self, locker_number):
        if locker_number in self.lockers:
            return self.lockers[locker_number].is_locked()
        else:
            return "Ce casier n'existe pas."


class LockerManagerGUI:
    def __init__(self, master, numb_lockers):
        self.master = master
        self.num_lockers = numb_lockers
        self.locker_manager = LockerManager(numb_lockers)
        self.current_password = ctk.StringVar()

        self.locker_buttons = []
        for i in range(1, numb_lockers + 1):
            button = ctk.CTkButton(master, text=f"Casier {i}", width=120, height=50,
                                   font=("Arial", 20),
                                   corner_radius=5,
                                   border_width=5,
                                   hover_color="grey",
                                   fg_color="grey",
                                   command=lambda num=i: self.toggle_locker(num))
            button.grid(row=(i - 1) // 8, column=(i - 1) % 8, padx=5, pady=5)
            self.locker_buttons.append(button)

        self.password_label = ctk.CTkLabel(master, text="Entrer un mot de passe de 4 à 8 chiffres, "
                                                         "\n et sélectionner un casier:", font=("Arial", 24))
        self.password_label.grid(row=(numb_lockers - 1) // 5 + 2, column=0, columnspan=5, pady=5)

        self.password_entry = ctk.CTkEntry(master, show="*", textvariable=self.current_password, width=200, height=40)
        self.password_entry.grid(row=(numb_lockers - 1) // 5 + 3, column=0, columnspan=5, pady=5)
        self.password_entry.focus()
        self.password_entry.icursor(ctk.END)

        self.status_label = ctk.CTkLabel(master, text="", width=400, height=64, font=("Arial", 24))
        self.status_label.grid(row=(numb_lockers - 1) // 5 + 4, columnspan=5, pady=5)

    def toggle_locker(self, locker_number):
        if self.locker_manager.is_locked(locker_number):
            message = self.locker_manager.unlock_locker(locker_number, self.current_password.get())
        else:
            message = self.locker_manager.lock_locker(locker_number, self.current_password.get())
            self.current_password.set("")
        self.update_status(message)
        self.master.after(30000, self.clear_status)

    def update_status(self, message):
        self.status_label.configure(text=message)

    def clear_status(self):
        self.status_label.configure(text="Bienvenue Empire47.")


# Exemple d'utilisation
num_lockers = 48

root = tk.Tk()
root.title("Gestion des Casiers")
root.configure(background="white")

app = LockerManagerGUI(root, num_lockers)

root.mainloop()
