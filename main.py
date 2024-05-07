import hashlib
import sqlite3
import tkinter as tk
from tkinter import Menu, messagebox
import customtkinter as ctk  # Importer customTkinter au lieu de tkinter
import serial


class Locker:
    def __init__(self, locker_number, database_manager, password=""):
        """Initialise un casier avec son numéro, son gestionnaire de base de données et un mot de passe facultatif."""
        self.locker_number = locker_number
        self.password = hashlib.sha256(password.encode()).hexdigest() if password else ""
        self.locked = False
        self.database_manager = database_manager

    def lock(self, password=""):
        """Verrouille le casier avec un mot de passe."""
        # Vérifier que le mot de passe contient uniquement des chiffres et a une longueur entre 4 et 8 caractères
        if password and password.isdigit() and 4 <= len(password) <= 8:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            self.password = hashed_password
            self.locked = True
            # Mettre à jour le mot de passe dans la base de données
            self.database_manager.update_password(self.locker_number, password)
            # Mettre à jour l'état du casier dans la base de données
            self.database_manager.update_locker_state(self.locker_number, True)
            print(f"État de verrouillage du casier {self.locker_number} mis à jour dans la base de données")
            return f"Casier {self.locker_number} est verrouillé."
        else:
            return "Mot de passe invalide. Le casier n'a pas été verrouillé."

    def unlock(self, password=""):
        """Déverrouille le casier avec un mot de passe."""
        if not self.locked:
            return f"Le casier {self.locker_number} est déjà déverrouillé."
        elif hashlib.sha256(password.encode()).hexdigest() == self.database_manager.get_master_password():
            # Si le mot de passe est le mot de passe maître, déverrouiller le casier
            print("déverrouillé par le mot de passe maitre.")
            self.locked = False
            self.database_manager.update_locker_state(self.locker_number, False)
            return f"Casier {self.locker_number} est déverrouillé."
        elif hashlib.sha256(password.encode()).hexdigest() == self.password:
            # Si le mot de passe correspond au mot de passe stocké dans le casier, déverrouiller le casier
            print("déverrouillé par le mot de passe régulier.")
            self.locked = False
            self.database_manager.update_locker_state(self.locker_number, False)
            return f"Casier {self.locker_number} est déverrouillé."
        else:
            return "Mot de passe incorrect."

    def is_locked(self):
        """Vérifie si le casier est verrouillé."""
        return self.locked


class LockerManager:
    def __init__(self, numb_lockers, cu48_communication):
        """Initialise le gestionnaire de casiers avec le nombre de casiers,
        la communication série CU48 et le gestionnaire de base de données."""
        self.locker_manager = None
        self.lockers = {}
        self.cu48_communication = cu48_communication
        self.db_manager = db_manager  # Créez une instance de DatabaseManager
        self.initialize_lockers(numb_lockers)

    def initialize_lockers(self, numb_lockers):
        """Initialise les casiers en récupérant leurs états et mots de passe depuis la base de données."""
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
        """Verrouille un casier avec le numéro spécifié et le mot de passe fourni."""
        if locker_number in self.lockers:
            message = self.lockers[locker_number].lock(password)
            self.db_manager.update_locker_state(locker_number, True)
            return message
        else:
            return "Ce casier n'existe pas."

    def unlock_locker(self, locker_number, password):
        """Déverrouille un casier avec le numéro spécifié et le mot de passe fourni."""
        if locker_number in self.lockers:
            message = self.lockers[locker_number].unlock(password)
            self.db_manager.update_locker_state(locker_number, False)
            return message
        else:
            return "Ce casier n'existe pas."

    def is_locked(self, locker_number):
        """Vérifie si un casier est verrouillé."""
        if locker_number in self.lockers:
            return self.lockers[locker_number].is_locked()
        else:
            return "Ce casier n'existe pas."

    def update_master_password(self, new_master_password_hash):
        """Met à jour le mot de passe maître dans le gestionnaire de base de données."""
        self.db_manager.update_master_password(new_master_password_hash)


class DatabaseManager:
    def __init__(self, db_file):
        """Initialise le gestionnaire de base de données avec le fichier de base de données spécifié."""
        try:
            self.conn = sqlite3.connect(db_file)
            self.cursor = self.conn.cursor()
            self.create_tables()
        except sqlite3.Error as e:
            print("Erreur lors de la connexion à la base de données:", e)

    def __del__(self):
        """Ferme la connexion à la base de données lors de la destruction de l'objet."""
        try:
            self.conn.close()  # Fermer la connexion à la base de données
        except Exception as e:
            print("Erreur lors de la fermeture de la connexion à la base de données:", e)

    def create_tables(self):
        """Crée les 2 tables de la base de données Password et Lockers."""
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
        """Met à jour les mots de passe dans le gestionnaire de base de données."""
        try:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            self.cursor.execute('''INSERT OR REPLACE INTO passwords (locker_number, password)
                                   VALUES (?, ?)''', (locker_number, hashed_password))
            self.conn.commit()
        except sqlite3.Error as e:
            print("Erreur lors de la mise à jour du mot de passe dans la base de données:", e)

    def get_password(self, locker_number):
        """Récupère le mot de passe dans le gestionnaire de base de données par casier."""
        try:
            self.cursor.execute('''SELECT password FROM passwords WHERE locker_number = ?''', (locker_number,))
            result = self.cursor.fetchone()
            if result:
                return result[0]
            return None
        except sqlite3.Error as e:
            print("Erreur de récupération du mot de passe dans la base de données:", e)

    def update_locker_state(self, locker_number, locked):
        """Met à jour l'état des casiers dans la base de donnée."""
        try:
            self.cursor.execute('''INSERT OR REPLACE INTO lockers (locker_number, locked)
                                   VALUES (?, ?)''', (locker_number, int(locked)))
            self.conn.commit()
        except sqlite3.Error as e:
            print("Erreur de mise à jour de l'état du casier dans la base de données:", e)

    def get_master_password(self):
        """Récupérer le mot de passe maître par défaut à partir de la base de données."""
        try:
            #  Le mot de passe maitre est enregistré dans le casier zéro.
            self.cursor.execute('''SELECT password FROM passwords WHERE locker_number = 0''')
            result = self.cursor.fetchone()
            if result is None:
                return None
            else:
                return result[0]  # Retourner le hachage du mot de passe maître par défaut
        except sqlite3.Error as e:
            print("Erreur de récupération du mot de passe maitre dans la base de données:", e)

    def update_master_password(self, new_master_password_hash):
        """Met à jour le mot de passe maître dans la base de données."""
        try:
            self.cursor.execute('''UPDATE passwords SET password = ? WHERE locker_number = 0''',
                                (new_master_password_hash,))
            self.conn.commit()
        except sqlite3.Error as e:
            print("Erreur lors de la mise à jour du mot de passe maître dans la base de données:", e)

    def get_locker_state(self, locker_number):
        """Récupérer l'état des casiers à partir de la base de données."""
        try:
            self.cursor.execute('''SELECT locked FROM lockers WHERE locker_number = ?''', (locker_number,))
            result = self.cursor.fetchone()
            if result:
                return bool(result[0])
            return None
        except sqlite3.Error as e:
            print("Erreur de de récupération de l'état du casier dans la base de données:", e)


class CU48Communication:
    def __init__(self, port='com1', baudrate=19200, status_label=None):
        """Initialise une communication série pour communiquer avec le CU48."""
        print("Port série utilisé:", port)  # Affiche la valeur du port série.
        try:
            if port is not None:
                self.ser = serial.Serial(port, baudrate, timeout=1)
                self.status_label = status_label  # Ajouter le status_label comme attribut.
            else:
                raise ValueError("Aucun port spécifié.")

        except (serial.SerialException, ValueError) as e:
            print("Erreur lors de l'initialisation de CU48Communication:", e)

    def __enter__(self):
        """Permet l'utilisation de la classe avec le mot-clé 'with'."""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Ferme la connexion série lors de la sortie d'un contexte 'with'."""
        try:
            self.ser.close()  # Fermer le port série
        except Exception as e:
            print("Erreur lors de la fermeture du port série:", e)

    def send_command(self, addr, locker, cmd):
        """Envoie une commande au CU48."""
        #  addr est l'adresse hexadécimale du CU48.
        try:
            command = bytearray([0x02, addr, locker, cmd, 0x03])
            checksum = sum(command) & 0xFF
            command.append(checksum)
            self.ser.write(command)
            print("addr:", addr, "locker:", locker + 1, "cmd:", cmd)
        except serial.SerialException as e:
            print("Erreur lors de l'envoi de la commande série:", e)

    def update_status(self, message):  # Affiche-les prints dans le status_label.
        """Met à jour l'état dans le status_label s'il est disponible, sinon affiche le message dans la console."""
        if self.status_label:
            try:
                self.status_label.configure(text=message)
            except Exception as e:
                print("Erreur lors de la mise à jour de l'état:", e)
        else:
            print(message)

    def close(self):
        """Ferme la connexion série."""
        try:
            self.ser.close()
        except Exception as e:
            print("Erreur lors de la fermeture du port série:", e)


class LockerManagerGUI:
    def __init__(self, master, numb_lockers, cu48_communication=None):
        """Initialise l'interface graphique du gestionnaire de casiers."""
        self.master = master
        self.num_lockers = numb_lockers
        self.cu48_communication = cu48_communication
        self.locker_manager = LockerManager(numb_lockers, cu48_communication)  # Passer db_file ici
        self.current_password = ctk.StringVar()
        self.locker_buttons = []  # Initialiser la liste locker_buttons.
        self.db_manager = db_manager
        self.cu48 = None

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
            self.locker_buttons.append(button)  # Ajouter le bouton à la liste locker_buttons.

            self.update_locker_button(i)

        # Crée les éléments de l'interface utilisateur
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

        # Créer la barre de menu.
        menubar = Menu(master)

        # Créer un menu cascade pour les options.
        options_menu = Menu(menubar, tearoff=0)
        aide_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Options", menu=options_menu)
        menubar.add_cascade(label="Aide", menu=aide_menu)

        # Ajouter les options de configuration au menu cascade.
        options_menu.add_command(label="Configurer", command=self.open_config_window, font=("Arial", 14))
        aide_menu.add_command(label="Instructions", command=self.open_help_window, font=("Arial", 14))

        # Associer la barre de menu à la fenêtre principale.
        master.config(menu=menubar)

    def open_config_window(self):
        """Ouvre la fenêtre de configuration."""
        try:
            # Vérifier le mot de passe maître avant d'ouvrir la fenêtre de configuration.
            master_password = self.locker_manager.db_manager.get_master_password()
            if master_password is not None:
                # Créer et afficher la fenêtre de configuration.
                config_window = ctk.CTkToplevel(self.master)
                config_window.title("Configuration")
                config_window.geometry("500x250")
                config_window.resizable(False, False)
                config_window.state('normal')  # Mettre la fenêtre au premier plan.

                config_window.grab_set()  # Empêcher l'accès à la fenêtre principale.

                # Passer l'instance de LockerManagerGUI à la fenêtre de configuration.
                ConfigWindow(config_window, self, master_password)
            else:
                messagebox.showerror("Erreur", "Impossible de récupérer le mot de passe maître.")
        except Exception as e:
            messagebox.showerror("Erreur", f"Une erreur est survenue "
                                           f"lors de l'ouverture de la fenêtre de configuration : {str(e)}")

    def open_help_window(self):
        """Ouvre une fenêtre d'aide affichant les instructions pour ouvrir et fermer un casier."""
        help_text = ("Pour ouvrir un casier : \n"
                     "1. À l'aide du pavé numérique, saisissez un mot de passe de 4 à 8 chiffres.\n"
                     "2. Sélectionnez le casier que vous souhaitez ouvrir.\n"
                     "3. Le casier s'ouvrira automatiquement.\n\n"
                     "Pour déverrouiller un casier : \n"
                     "4. Saisissez le mot de passe utilisateur que vous avez choisi à l'étape 1.\n"
                     "5. Cliquez sur le casier que vous avez verrouillé.\n")

        # Créer une nouvelle fenêtre pour afficher l'aide.
        help_window = ctk.CTkToplevel(self.master)
        help_window.title("Aide")
        help_window.geometry("700x300")
        help_window.state('normal')

        help_window.grab_set()  # Empêcher l'accès à la fenêtre principale.

        # Ajouter un label avec le texte d'aide.
        help_label = ctk.CTkLabel(help_window, text=help_text, justify="left")
        help_label.cget("font").configure(size=20)
        help_label.pack()

        # Ajouter un bouton "Fermer" pour fermer la fenêtre d'aide.
        close_button = ctk.CTkButton(help_window, text="Fermer", command=lambda: self.close_help_window(help_window))
        close_button.pack()

    @staticmethod
    def close_help_window(window):
        """Ferme la fenêtre d'aide."""
        window.destroy()

    def update_config(self, new_master_password):
        """Met à jour la configuration avec le nouveau mot de passe maître."""
        # Mettre à jour la configuration avec le nouveau mot de passe maître
        self.locker_manager.master_password = new_master_password

    def toggle_locker(self, locker_number):
        """Verrouille ou déverrouille un casier en fonction de son état actuel."""
        is_locked = self.locker_manager.is_locked(locker_number)
        password = self.current_password.get()

        if isinstance(is_locked, bool):
            """vérifie si is_locked est de type booléen."""
            if is_locked:
                # Déverrouille le casier.
                message = self.locker_manager.unlock_locker(locker_number, password)
                if message.startswith("Casier"):
                    self.update_locker_button(locker_number)
                    self.update_status(message)
                    # Envoyer la commande pour déverrouiller le casier.
                    # Envoyer la commande pour verrouiller ou déverrouiller le casier.
                    cu48_address, locker_index = self.get_cu48_address(locker_number)
                    self.cu48_communication.send_command(cu48_address, locker_index, 0x51)
                else:
                    self.update_status(message)
            else:
                # Verrouille le casier.
                message = self.locker_manager.lock_locker(locker_number, password)
                if message.startswith("Casier"):
                    self.update_locker_button(locker_number)
                    self.update_status(message)
                    # Envoyer la commande pour verrouiller ou déverrouiller le casier.
                    cu48_address, locker_index = self.get_cu48_address(locker_number)
                    self.cu48_communication.send_command(cu48_address, locker_index, 0x51)
                else:
                    self.update_status(message)
        else:
            # Le casier n'existe pas ou une autre erreur s'est produite.
            self.update_status(is_locked)

        # Effacer le champ mot de passe après avoir verrouillé ou déverrouillé un casier.
        self.clear_password()
        # Effacer le statut après 30 secondes.
        self.master.after(30000, self.clear_status)

    @staticmethod
    def get_cu48_address(locker_number):
        """Retourne l'adresse du CU48 et l'emplacement de branchement du casier en fonction de son numéro."""
        if 1 <= locker_number <= 24:
            return 0x00, locker_number -1
        elif 25 <= locker_number <= 48:
            return 0x01, locker_number - 25
        else:
            return 0x02, locker_number - 49

    def update_locker_button(self, locker_number):
        """Met à jour l'apparence du bouton du casier pour refléter son état."""
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
        """Crée le pavé numérique pour entrer le mot de passe."""
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
        """Gère l'entrée du pavé numérique."""
        current_password = self.current_password.get()
        if value == "<<":
            current_password = current_password[:-1]  # Supprimer le dernier caractère.
        else:
            current_password += value
        self.current_password.set(current_password)
        self.password_entry.icursor(tk.END)  # Place le curseur à la fin du champ de mot de passe.

    def update_status(self, message):
        """Met à jour le statut (message au-dessus du clavier)."""
        self.status_label.configure(text=message)

    def clear_password(self):
        """Efface le champ du mot de passe."""
        self.current_password.set("")  # Efface le champ mot de passe.
        self.password_entry.icursor(tk.END)  # Place le curseur à la fin du champ de mot de passe

    def clear_status(self):
        """Efface le statut."""
        self.status_label.configure(text="Bienvenue Empire47.")


class ConfigWindow:
    def __init__(self, master, locker_manager_gui, master_password_hash):
        """Initialise la fenêtre de configuration."""
        self.master = master
        self.locker_manager_gui = locker_manager_gui
        self.master_password_hash = master_password_hash

        # Création des widgets pour la fenêtre de configuration.
        self.master_password_label = tk.Label(master, text="Mot de passe maître:", font=("Arial", 14))
        self.master_password_entry = tk.Entry(master, show="*")
        self.confirm_new_master_password_label = tk.Label(master, text="Confirmer le nouveau mot de passe maître:",
                                                          font=("Arial", 14))
        self.confirm_new_master_password_entry = tk.Entry(master, show="*")
        self.new_master_password_label = tk.Label(master, text="Nouveau mot de passe maître:", font=("Arial", 14))
        self.new_master_password_entry = tk.Entry(master, show="*")
        self.save_button = tk.Button(master, text="Enregistrer", command=self.save_config, font=("Arial", 14))

        # Placement des widgets dans la fenêtre.
        self.master_password_label.grid(row=0, column=0, padx=10, pady=5)
        self.master_password_entry.grid(row=0, column=1, padx=10, pady=5)
        self.new_master_password_label.grid(row=1, column=0, padx=10, pady=5)
        self.new_master_password_entry.grid(row=1, column=1, padx=10, pady=5)
        self.confirm_new_master_password_label.grid(row=2, column=0, padx=10, pady=5)
        self.confirm_new_master_password_entry.grid(row=2, column=1, padx=10, pady=5)
        self.save_button.grid(row=4, columnspan=2, padx=10, pady=5)

    def save_config(self):
        """Enregistre la configuration de la fenêtre option."""
        # Récupérer le mot de passe maître entré par l'utilisateur
        entered_master_password = self.master_password_entry.get()

        # Vérifier si le mot de passe maître actuel est correct
        entered_master_password_hash = hashlib.sha256(entered_master_password.encode()).hexdigest()
        if entered_master_password_hash == self.master_password_hash:
            # Récupérer le nouveau mot de passe maître et sa confirmation
            new_master_password = self.new_master_password_entry.get()
            confirm_new_master_password = self.confirm_new_master_password_entry.get()
            # Vérifier si le nouveau mot de passe maître respecte les conditions (4 à 8 chiffres)
            if new_master_password.isdigit() and 4 <= len(new_master_password) <= 8:

                # Vérifier si les deux mots de passe correspondent
                if new_master_password == confirm_new_master_password:
                    # Hasher le nouveau mot de passe maître
                    new_master_password_hash = hashlib.sha256(new_master_password.encode()).hexdigest()

                    # Mettre à jour la configuration dans l'application principale
                    self.locker_manager_gui.update_config(new_master_password_hash)

                    # Mettre à jour le mot de passe maître dans la base de données
                    self.locker_manager_gui.db_manager.update_master_password(new_master_password_hash)

                    # Fermer la fenêtre de configuration
                    self.master.destroy()
                else:
                    messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas.")
            else:
                messagebox.showerror("Erreur", "Le nouveau mot de passe maître doit contenir entre 4 et 8 chiffres.")
        else:
            messagebox.showerror("Erreur", "Mot de passe maître incorrect")


# Donne le nombre de casiers à créer.
num_lockers = 48

# Crée une instance principale de l'interface graphique Tkinter.
root = ctk.CTk()
root.title("Gestion des Casiers")
root.configure(background="white")  # couleur de fond

# Crée une instance de DatabaseManager pour gérer la base de données.
db_manager = DatabaseManager('data/database.db')

# Crée une instance de CU48Communication pour gérer la communication avec le CU48.
# Remarque : status_label=None signifie que le label d'état n'est pas utilisé dans cet exemple
cu48 = CU48Communication(status_label=None)

# Crée une instance de LockerManagerGUI en passant les éléments nécessaires comme arguments.
# - root : la fenêtre principale Tkinter.
# - num_lockers : le nombre de casiers.
# - cu48 : l'instance de CU48Communication pour la communication avec le CU48.
app = LockerManagerGUI(root, num_lockers, cu48)

# Lance la boucle principale de l'interface graphique Tkinter, qui gère les événements et les interactions utilisateur.
root.mainloop()
