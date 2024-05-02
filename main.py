import hashlib
import sqlite3
import tkinter as tk
from tkinter import messagebox
from tkinter import Menu
import customtkinter as ctk  # Importer customTkinter au lieu de tkinter
import serial


class Locker:
    def __init__(self, locker_number, db_manager, password=""):
        self.locker_number = locker_number
        self.password = hashlib.sha256(password.encode()).hexdigest() if password else ""
        self.locked = False
        self.db_manager = db_manager

    def lock(self, password=""):
        if password and 4 <= len(password) <= 8:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            self.password = hashed_password
            self.locked = True
            # Mettre à jour le mot de passe dans la base de données
            self.db_manager.update_password(self.locker_number, password)
            # Mettre à jour l'état du casier dans la base de données
            self.db_manager.update_locker_state(self.locker_number, True)
            print(f"État de verrouillage du casier {self.locker_number} mis à jour dans la base de données")
            return f"Casier {self.locker_number} est verrouillé."
        else:
            return "Mot de passe invalide. Le casier n'a pas été verrouillé."

    def unlock(self, password=""):
        if not self.locked:
            return f"Le casier {self.locker_number} est déjà déverrouillé."
        elif hashlib.sha256(password.encode()).hexdigest() == self.db_manager.get_master_password():
            # Si le mot de passe est le mot de passe maître, déverrouiller le casier
            self.locked = False
            self.db_manager.update_locker_state(self.locker_number, False)
            return f"Casier {self.locker_number} est déverrouillé."
        elif hashlib.sha256(password.encode()).hexdigest() == self.password:
            # Si le mot de passe correspond au mot de passe stocké dans le casier, déverrouiller le casier
            self.locked = False
            self.db_manager.update_locker_state(self.locker_number, False)
            return f"Casier {self.locker_number} est déverrouillé."
        else:
            return "Mot de passe incorrect."

    def is_locked(self):
        return self.locked


class LockerManager:
    def __init__(self, numb_lockers, cu48_communication, db_file):
        self.lockers = {}
        self.cu48_communication = cu48_communication
        self.db_manager = DatabaseManager(db_file)  # Créez une instance de DatabaseManager
        self.initialize_lockers(numb_lockers)

    def initialize_lockers(self, numb_lockers):
        for i in range(1, numb_lockers + 1):
            # Récupérer l'état du casier depuis la base de données
            locker_locked = self.db_manager.get_locker_state(i)
            # Récupérer le mot de passe du casier depuis la base de données
            locker_password = self.db_manager.get_password(i)
            self.lockers[i] = Locker(i, self.db_manager)
            if locker_locked is not None:
                self.lockers[i].locked = locker_locked
            if locker_password is not None:  # Vérifier si un mot de passe a été récupéré
                self.lockers[i].password = locker_password  # Assigner le mot de passe au casier

    def lock_locker(self, locker_number, password):
        if locker_number in self.lockers:
            message = self.lockers[locker_number].lock(password)
            self.db_manager.update_locker_state(locker_number, True)
            return message
        else:
            return "Ce casier n'existe pas."

    def unlock_locker(self, locker_number, password):
        if locker_number in self.lockers:
            message = self.lockers[locker_number].unlock(password)
            self.db_manager.update_locker_state(locker_number, False)
            return message
        else:
            return "Ce casier n'existe pas."

    def is_locked(self, locker_number):
        if locker_number in self.lockers:
            return self.lockers[locker_number].is_locked()
        else:
            return "Ce casier n'existe pas."


class DatabaseManager:
    def __init__(self, db_file):
        try:
            self.conn = sqlite3.connect(db_file)
            self.cursor = self.conn.cursor()
            self.create_tables()
        except sqlite3.Error as e:
            print("Erreur lors de la connexion à la base de données:", e)

    def create_tables(self):
        try:
            # Créer les tables si elles n'existent pas déjà
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                                    locker_number INTEGER PRIMARY KEY,
                                    password TEXT UNIQUE
                                  )''')
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS lockers (
                                    locker_number INTEGER PRIMARY KEY,
                                    locked INTEGER
                                  )''')
            self.conn.commit()

            # Vérifier si le mot de passe maître par défaut existe déjà dans la base de données
            default_master_password = self.get_master_password()
            if default_master_password is None:
                # S'il n'existe pas, générer un hachage pour le mot de passe maître par défaut
                # et l'ajouter à la base de données.
                hashed_default_master_password = hashlib.sha256(b"88888888").hexdigest()
                self.cursor.execute('''INSERT INTO passwords (locker_number, password) VALUES (?, ?)''',
                                    (0, hashed_default_master_password))
                self.conn.commit()
        except sqlite3.Error as e:
            print("Erreur lors de la création des tables dans la base de données:", e)

    def update_password(self, locker_number, password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.cursor.execute('''INSERT OR REPLACE INTO passwords (locker_number, password)
                               VALUES (?, ?)''', (locker_number, hashed_password))
        self.conn.commit()

    def get_password(self, locker_number):
        self.cursor.execute('''SELECT password FROM passwords WHERE locker_number = ?''', (locker_number,))
        result = self.cursor.fetchone()
        if result:
            return result[0]
        return None

    def update_locker_state(self, locker_number, locked):
        self.cursor.execute('''INSERT OR REPLACE INTO lockers (locker_number, locked)
                               VALUES (?, ?)''', (locker_number, int(locked)))
        self.conn.commit()

    def get_master_password(self):
        # Récupérer le mot de passe maître par défaut à partir de la base de données
        self.cursor.execute('''SELECT password FROM passwords WHERE locker_number = 0''')
        result = self.cursor.fetchone()
        if result is None:
            return None
        else:
            return result[0]  # Retourner le hachage du mot de passe maître par défaut

    def get_locker_state(self, locker_number):
        self.cursor.execute('''SELECT locked FROM lockers WHERE locker_number = ?''', (locker_number,))
        result = self.cursor.fetchone()
        if result:
            return bool(result[0])
        return None


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
        print("Commande envoyée en hexadécimal:",
              command.hex())  # Ajouter cette ligne pour afficher la commande envoyée en hexadécimal.

    def update_status(self, message):  # Affiche-les prints dans le status_label.
        if self.status_label:
            self.status_label.configure(text=message)
        else:
            print(message)

    def close(self):
        self.ser.close()


class LockerManagerGUI:
    def __init__(self, master, numb_lockers, cu48_communication, db_file):
        self.master = master
        self.num_lockers = numb_lockers
        self.cu48_communication = cu48_communication
        self.locker_manager = LockerManager(numb_lockers, cu48_communication, db_file)  # Passer db_file ici
        self.current_password = ctk.StringVar()
        self.locker_buttons = []  # Initialiser la liste locker_buttons.

        # Créer les boutons des casiers et les ajouter à la liste locker_buttons
        for i in range(1, numb_lockers + 1):
            button = ctk.CTkButton(master, text=f"Casier {i}", width=120, height=50,
                                   font=("Arial", 20),
                                   corner_radius=5,
                                   border_width=5,
                                   hover_color="grey",
                                   fg_color="grey",
                                   command=lambda num=i: self.toggle_locker(num))
            button.grid(row=(i - 1) // 8, column=(i - 1) % 8, padx=5, pady=5)
            self.locker_buttons.append(button)  # Ajouter le bouton à la liste locker_buttons

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
        # Lancer une fonction pour interroger régulièrement les serrures

        # Créer la barre de menu
        menubar = Menu(master)

        # Créer un menu cascade pour les options
        options_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Options", menu=options_menu)

        # Ajouter les options de configuration au menu cascade
        options_menu.add_command(label="Configurer", command=self.open_config_window)

        # Associer la barre de menu à la fenêtre principale
        master.config(menu=menubar)

    def open_config_window(self):
        # Créer et afficher la fenêtre de configuration
        config_window = tk.Toplevel(self.master)
        config_window.title("Configuration")
        config_window.geometry("500x200")
        config_window.resizable(False, False)
        config_window.attributes("-topmost", True)  # Mettre la fenêtre au premier plan

        config_window.grab_set()  # Empêcher l'accès à la fenêtre principale

        # Passer l'instance de LockerManagerGUI à la fenêtre de configuration
        ConfigWindow(config_window, self)

    def update_config(self, new_com_port, new_master_password):
        # Mettre à jour la configuration avec le nouveau port COM et le nouveau mot de passe maître
        self.cu48_communication.ser.port = new_com_port
        self.locker_manager.master_password = new_master_password

    def toggle_locker(self, locker_number):
        is_locked = self.locker_manager.is_locked(locker_number)
        password = self.current_password.get()

        if isinstance(is_locked, bool):
            if is_locked:
                message = self.locker_manager.unlock_locker(locker_number, password)
                if message.startswith("Casier"):
                    self.update_locker_button(locker_number)
                    self.update_status(message)
                    # Envoyer la commande pour déverrouiller le casier
                    self.cu48_communication.send_command(0x00, locker_number - 1, 0x51)
                else:
                    self.update_status(message)
            else:
                message = self.locker_manager.lock_locker(locker_number, password)
                if message.startswith("Casier"):
                    self.update_locker_button(locker_number)
                    self.update_status(message)
                    # Envoyer la commande pour verrouiller le casier
                    self.cu48_communication.send_command(0x00, locker_number - 1, 0x51)
                else:
                    self.update_status(message)
        else:
            # Le casier n'existe pas ou une autre erreur s'est produite
            self.update_status(is_locked)

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

    def update_status(self, message):
        self.status_label.configure(text=message)

    def clear_password(self):
        self.current_password.set("")  # Efface le champ mot de passe.
        self.password_entry.icursor(tk.END)  # Place le curseur à la fin du champ de mot de passe

    def clear_status(self):
        self.status_label.configure(text="Bienvenue Empire47.")


class ConfigWindow:
    def __init__(self, master, locker_manager_gui):
        self.master = master
        self.locker_manager_gui = locker_manager_gui

        # Création des widgets pour la fenêtre de configuration
        self.password_label = tk.Label(master, text="Mot de passe:")
        self.password_entry = tk.Entry(master, show="*")
        self.com_port_label = tk.Label(master, text="Port COM:")
        self.com_port_entry = tk.Entry(master)
        self.new_master_password_label = tk.Label(master, text="Nouveau mot de passe maître:")
        self.new_master_password_entry = tk.Entry(master, show="*")
        self.save_button = tk.Button(master, text="Enregistrer", command=self.save_config)

        # Placement des widgets dans la fenêtre
        self.password_label.grid(row=0, column=0, padx=10, pady=5)
        self.password_entry.grid(row=0, column=1, padx=10, pady=5)
        self.com_port_label.grid(row=1, column=0, padx=10, pady=5)
        self.com_port_entry.grid(row=1, column=1, padx=10, pady=5)
        self.new_master_password_label.grid(row=2, column=0, padx=10, pady=5)
        self.new_master_password_entry.grid(row=2, column=1, padx=10, pady=5)
        self.save_button.grid(row=3, columnspan=2, padx=10, pady=5)

    def save_config(self):
        # Vérifier si le mot de passe est correct
        if self.password_entry.get() == "88888888":
            # Mettre à jour le port COM et le mot de passe maître
            new_com_port = self.com_port_entry.get()
            new_master_password = self.new_master_password_entry.get()

            # Mettre à jour la configuration dans l'application principale
            self.locker_manager_gui.update_config(new_com_port, new_master_password)

            # Fermer la fenêtre de configuration
            self.master.destroy()
        else:
            # Afficher un message d'erreur si le mot de passe est incorrect
            messagebox.showerror("Erreur", "Mot de passe incorrect")


# Exemple d'utilisation
num_lockers = 48

root = tk.Tk()
root.title("Gestion des Casiers")
root.configure(background="white")  # couleur de fond

# Créer une instance de CU48Communication avant de créer LockerManagerGUI
cu48 = CU48Communication('com3', status_label=None)  # Remplacer 'com3' par le port approprié

# Créer une instance de LockerManagerGUI en passant cu48 comme argument
app = LockerManagerGUI(root, num_lockers, cu48, 'data/database.db')

root.mainloop()
