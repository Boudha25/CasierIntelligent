import time
import tkinter as tk
import customtkinter as ctk  # Importer customTkinter au lieu de tkinter
import serial


class Locker:
    def __init__(self, locker_number):
        self.locker_number = locker_number
        self.password = ""  # Mot de passe des usagers.
        self.locked = False  # Initialiser tous les casiers comme déverrouillés.
        self.master_password = "88888888"  # Définir le mot de passe maître

    def lock(self, password=""):
        # Vérifier si un mot de passe de 4 à 8 chiffres est fourni et s'il est valide.
        if password and 4 <= len(password) <= 8:
            self.password = password
            self.locked = True
            return f"Casier {self.locker_number} est verrouillé."
        else:
            return "Mot de passe invalide. Le casier n'a pas été verrouillé."

    def unlock(self, password=""):
        if not self.locked:  # Vérifier si le casier est déjà déverrouillé.
            return f"Le casier {self.locker_number} est déjà déverrouillé."
        # Vérifier si le mot de passe est correct ou le mot de passe maître est saisi.
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


class CU48Communication:
    def __init__(self, port, baudrate=19200, status_label=None):
        self.ser = serial.Serial(port, baudrate, timeout=1)
        self.locker_states = {}  # Dictionnaire pour stocker l'état de chaque casier.
        self.status_label = status_label  # Ajouter le status_label comme attribut.

    def send_command(self, addr, locker, cmd):
        command = bytearray([0x02, addr, locker, cmd, 0x03])
        checksum = sum(command) & 0xFF
        command.append(checksum)
        self.ser.write(command)

    def receive_response(self):
        response = self.ser.read(12)
        return response

    def get_locker_status(self):
        if self.status_label:
            self.update_status("Interrogation de l'état des casiers...")
        else:
            print("Interrogation de l'état des casiers...")

        self.send_command(0x0A, 0x30, 0x50)  # Envoyer la commande pour obtenir l'état de tous les casiers
        time.sleep(0.1)  # Attendre un court instant pour la réponse
        response = self.receive_response()

        # Vérifier si la réponse est valide
        if len(response) == 12 and response[0] == 0x02 and response[11] == 0x03:
            # Analyser la réponse pour mettre à jour l'état de chaque casier
            for i in range(1, 49):
                byte_index = (i - 1) // 8 + 1
                bit_index = (i - 1) % 8
                locker_num = byte_index * 8 - bit_index
                locker_state = (response[byte_index] >> bit_index) & 1
                if locker_num not in self.locker_states:
                    self.locker_states[locker_num] = locker_state
                else:
                    # Mettre à jour l'état du casier seulement s'il a changé
                    if self.locker_states[locker_num] != locker_state:
                        status_message = f"Changement d'état pour le casier {locker_num}. " \
                                         f"Nouvel état : {'Verrouillé' if locker_state else 'Déverrouillé'}"
                        if self.status_label:
                            self.update_status(status_message)
                        else:
                            print(status_message)
                        self.locker_states[locker_num] = locker_state
        else:
            if self.status_label:
                self.update_status("Réponse invalide.")
            else:
                print("Réponse invalide.")

    def update_status(self, message):  # Affiche-les prints dans le status_label.
        if self.status_label:
            self.status_label.configure(text=message)
        else:
            print(message)

    def close(self):
        self.ser.close()


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
                                   corner_radius=5,  # Rayon des coins pour un effet arrondi
                                   border_width=5,  # Largeur de la bordure pour un effet de relief
                                   hover_color="grey",
                                   fg_color="grey",  # Couleur de fond par défaut
                                   command=lambda num=i: self.toggle_locker(num))
            button.grid(row=(i - 1) // 5, column=(i - 1) % 5, padx=5, pady=5)
            self.locker_buttons.append(button)
            self.update_locker_button(i)

        self.password_label = ctk.CTkLabel(master, text="Entrer un mot de passe de 4 à 8 chiffres, "
                                                        "\n et sélectionner un casier:", font=("Arial", 24))
        self.password_label.grid(row=(numb_lockers - 1) // 5 + 2, column=0, columnspan=5, pady=5)

        self.password_entry = ctk.CTkEntry(master, show="*", textvariable=self.current_password, width=200, height=40)
        self.password_entry.grid(row=(numb_lockers - 1) // 5 + 3, column=0, columnspan=5, pady=5)
        self.password_entry.focus()  # Met le curseur dans le champ Entry.
        self.password_entry.icursor(ctk.END)  # Place le curseur à la fin du champ de mot de passe.

        self.status_label = ctk.CTkLabel(master, text="", width=400, height=64, font=("Arial", 24))
        self.status_label.grid(row=(numb_lockers - 1) // 5 + 4, columnspan=5, pady=5)

        self.keypad_frame = ctk.CTkFrame(master, fg_color="white")  # Couleur de fond par défaut
        self.keypad_frame.grid(row=(numb_lockers - 1) // 5 + 5, column=0, columnspan=5, pady=5)

        self.create_keypad()
        self.clear_status()  # Efface le champ status et écrit le mot de bienvenu.

    def toggle_locker(self, locker_number):
        if self.locker_manager.is_locked(locker_number):
            message = self.locker_manager.unlock_locker(locker_number, self.current_password.get())
        else:
            message = self.locker_manager.lock_locker(locker_number, self.current_password.get())
            # Réinitialiser le champ de mot de passe si le casier est cliqué.
            self.current_password.set("")
        self.update_locker_button(locker_number)
        self.update_status(message)
        # Effacer le champ mot de passe après avoir verrouillé ou déverrouillé un casier.
        self.clear_password()
        # Effacer le statut après 30 secondes
        self.master.after(30000, self.clear_status)

    def update_locker_button(self, locker_number):
        locker = self.locker_manager.lockers[locker_number]
        if locker.is_locked():
            # Rouge si le casier est verrouillé.
            self.locker_buttons[locker_number - 1].configure(fg_color="red")
        else:
            # Vert si le casier est déverrouillé.
            self.locker_buttons[locker_number - 1].configure(fg_color="green")
        # Mettre à jour le bouton pour refléter le changement de couleur.
        self.locker_buttons[locker_number - 1].update()

    def create_keypad(self):
        buttons = [
            ("1", 0, 0), ("2", 0, 1), ("3", 0, 2),
            ("4", 1, 0), ("5", 1, 1), ("6", 1, 2),
            ("7", 2, 0), ("8", 2, 1), ("9", 2, 2),
            ("0", 3, 1), ("<<", 3, 2)
        ]
        for (text, row, column) in buttons:
            button = ctk.CTkButton(self.keypad_frame, text=text,
                                   fg_color="grey",  # Couleur de fond par défaut
                                   font=("Arial", 24),
                                   height=50,
                                   width=100,
                                   command=lambda t=text: self.keypad_input(t))
            button.grid(row=row, column=column, padx=5, pady=5)

    def keypad_input(self, value):
        current_password = self.current_password.get()
        if value == "<<":
            current_password = current_password[:-1]  # Supprimer le dernier caractère.
        else:
            current_password += value
        self.current_password.set(current_password)
        self.password_entry.icursor(tk.END)  # Place le curseur à la fin du champ de mot de passe.
        self.master.after(30000, self.clear_password)

    def update_status(self, message):
        self.status_label.configure(text=message)

    def clear_password(self):
        self.current_password.set("")  # Efface le champ mot de passe.
        self.password_entry.icursor(tk.END)  # Place le curseur à la fin du champ de mot de passe

    def clear_status(self):
        self.status_label.configure(text="Bienvenue Empire47.")


# Exemple d'utilisation
num_lockers = 20

root = tk.Tk()
root.title("Gestion des Casiers")
root.configure(background="white")  # couleur de fond
app = LockerManagerGUI(root, num_lockers)

# Exemple d'utilisation
# cu48 = CU48Communication('/dev/ttyUSB0', status_label=app.status_label)
# cu48 = CU48Communication('com1', status_label=app.status_label)

root.mainloop()
