import tkinter as tk


class Locker:
    def __init__(self, locker_number):
        self.locker_number = locker_number
        self.password = ""
        self.locked = False  # Initialiser tous les casiers comme déverrouillés.

    def lock(self, password=""):
        if password and 4 <= len(password) <= 8:  # Vérifier si un mot de passe est fourni et s'il est valide.
            self.password = password
            self.locked = True
            return f"Locker {self.locker_number} verrouillé."
        else:
            return "Mot de passe invalide. Le casier n'a pas été verrouillé."

    def unlock(self, password=""):
        if not self.locked:  # Vérifier si le casier est déjà déverrouillé.
            return f"Le casier {self.locker_number} est déjà déverrouillé."
        elif password == self.password:  # Vérifier si le mot de passe est correct.
            self.locked = False
            return f"Locker {self.locker_number} déverrouillé."
        else:
            return "Mot de passe incorrect."

    def is_locked(self):
        return self.locked


class LockerManager:
    def __init__(self, num_lockers):
        self.lockers = {}
        for i in range(1, num_lockers + 1):
            self.lockers[i] = Locker(i)

    def lock_locker(self, locker_number, password):
        if locker_number in self.lockers:
            return self.lockers[locker_number].lock(password)
        else:
            return "Ce casier n'existe pas."

    def unlock_locker(self, locker_number, password):
        if locker_number in self.lockers:
            return self.lockers[locker_number].unlock(password)
        else:
            return "Ce casier n'existe pas."

    def is_locked(self, locker_number):
        if locker_number in self.lockers:
            return self.lockers[locker_number].is_locked()
        else:
            return "Ce casier n'existe pas."


class LockerManagerGUI:
    def __init__(self, master, num_lockers):
        self.master = master
        self.num_lockers = num_lockers
        self.locker_manager = LockerManager(num_lockers)
        self.current_password = tk.StringVar()

        self.locker_buttons = []

        for i in range(1, num_lockers + 1):
            button = tk.Button(master, text=f"Casier {i}", width=8, command=lambda num=i: self.toggle_locker(num))
            button.grid(row=(i - 1) // 5, column=(i - 1) % 5, padx=5, pady=5)
            self.locker_buttons.append(button)
            self.update_locker_button(i)

        self.password_label = tk.Label(master, text="Entrer un mot de passe de 4 à 8 caractères \n et sélectionner un "
                                                    "casier:", background="white")
        self.password_label.grid(row=(num_lockers - 1) // 5 + 2, column=0, columnspan=5, pady=5)

        self.password_entry = tk.Entry(master, textvariable=self.current_password, show="*",
                                       width=10, background="white")
        self.password_entry.grid(row=(num_lockers - 1) // 5 + 3, column=0, columnspan=5, pady=5)
        self.password_entry.icursor(tk.END)  # Place le curseur à la fin du champ de mot de passe

        self.status_label = tk.Label(master, text="", wraplength=200, background="white")
        self.status_label.grid(row=(num_lockers - 1) // 5 + 4, columnspan=5, pady=5)

        self.keypad_frame = tk.Frame(master)
        self.keypad_frame.grid(row=(num_lockers - 1) // 5 + 5, column=0, columnspan=5, pady=5)

        self.create_keypad()

    def toggle_locker(self, locker_number):
        if self.locker_manager.is_locked(locker_number):
            message = self.locker_manager.unlock_locker(locker_number, self.current_password.get())
        else:
            message = self.locker_manager.lock_locker(locker_number, self.current_password.get())
            # Réinitialiser le champ de mot de passe si le casier est cliqué
            self.current_password.set("")
        self.update_locker_button(locker_number)
        self.update_status(message)
        # Effacer le message et le champ mot de passe après 10 secondes.
        self.master.after(10000, self.clear_status)

    def update_locker_button(self, locker_number):
        if self.locker_manager.is_locked(locker_number):
            self.locker_buttons[locker_number - 1].config(bg="red")
        else:
            self.locker_buttons[locker_number - 1].config(bg="green")

    def create_keypad(self):
        buttons = [
            ("1", 0, 0), ("2", 0, 1), ("3", 0, 2),
            ("4", 1, 0), ("5", 1, 1), ("6", 1, 2),
            ("7", 2, 0), ("8", 2, 1), ("9", 2, 2),
            ("0", 3, 0), ("<< Effacer", 3, 1)
        ]
        for (text, row, column) in buttons:
            button = tk.Button(self.keypad_frame, text=text, background="white", width=12,
                               command=lambda t=text: self.keypad_input(t))
            button.grid(row=row, column=column, padx=5, pady=5)

    def keypad_input(self, value):
        current_password = self.current_password.get()
        if value == "<< Effacer":
            current_password = current_password[:-1]  # Supprimer le dernier caractère.
        else:
            current_password += value
        self.current_password.set(current_password)
        self.password_entry.icursor(tk.END)  # Place le curseur à la fin du champ de mot de passe.
        self.password_entry.focus()  # Place le curseur dans le champ de mot de passe.

    def update_status(self, message):
        self.status_label.config(text=message)

    def clear_status(self):
        self.status_label.config(text="Bienvenue Empire47.")
        self.current_password.set("")  # Efface le champ mot de passe.
        self.password_entry.icursor(tk.END)  # Place le curseur à la fin du champ de mot de passe


# Exemple d'utilisation
num_lockers = 20

root = tk.Tk()
root.title("Gestion des Casiers")
root.configure(background="white")  # couleur de fond
app = LockerManagerGUI(root, num_lockers)
root.mainloop()
