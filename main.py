from Database import DatabaseManager
import hashlib
import re
import tkinter as tk
from tkinter import Menu, messagebox
import customtkinter as ctk  # Importer customTkinter au lieu de tkinter
import serial
from twilio.rest import Client
import os
from dotenv import load_dotenv


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

        # Ajouter le checkbox pour envoyer le mot de passe par SMS
        self.send_sms_var = tk.IntVar()
        self.send_sms_checkbox = ctk.CTkCheckBox(master, text="Envoyer le mot de passe par SMS",
                                                 variable=self.send_sms_var, onvalue=True, offvalue=False,
                                                 font=("Arial", 16), command=self.show_phone_entry)
        self.send_sms_checkbox.grid(row=(numb_lockers - 1) // 5 + 1, column=3, columnspan=5, pady=5)

        # Ajouter le champ pour saisir le numéro de téléphone
        self.phone_number_label = ctk.CTkLabel(master, text="Numéro de téléphone:", font=("Arial", 14))
        self.phone_number_label.grid(row=(numb_lockers - 1) // 5 + 2, column=3, columnspan=5, pady=5)
        self.phone_number_var = tk.StringVar()
        self.phone_number_var.trace("w", lambda *args: self.format_phone_number())
        self.phone_number_entry = ctk.CTkEntry(master, width=100, height=40, textvariable=self.phone_number_var)
        self.phone_number_entry.grid(row=(numb_lockers - 1) // 5 + 3, column=3, columnspan=5, pady=5)
        self.phone_number_entry.icursor(ctk.END)  # Place le curseur à la fin du champ.

        # Masquer initialement le champ de numéro de téléphone
        self.phone_number_label.grid_remove()
        self.phone_number_entry.grid_remove()
        self.selected_entry = None

        # Créer les boutons des casiers et les ajouter à la liste locker_buttons
        for i in range(1, numb_lockers + 1):
            button = ctk.CTkButton(master, text=f"Casier {i}", width=120, height=45,
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
        self.password_entry.icursor(ctk.END)  # Place le curseur à la fin du champ de mot de passe.

        self.status_label = ctk.CTkLabel(master, text="", width=400, height=64, font=("Arial", 24))
        self.status_label.grid(row=(numb_lockers - 1) // 5 + 4, columnspan=5, pady=5)

        self.keypad_frame = ctk.CTkFrame(master, fg_color="white")  # Couleur de fond par défaut
        self.keypad_frame.grid(row=(numb_lockers - 1) // 5 + 5, column=0, columnspan=5, pady=5)

        self.create_keypad()
        self.clear_status()  # Efface le champ status et écrit le mot de bienvenu.

        self.selected_entry = "password"  # Définir par défaut que le mot de passe est sélectionné
        # Placer le curseur par défaut dans le champ d'entrée du mot de passe
        self.password_entry.focus_set()
        # Associer les événements de focus aux entrées pour mettre à jour selected_entry
        self.password_entry.bind("<FocusIn>", lambda event: self.set_selected_entry("password"))
        self.password_entry.bind("<FocusOut>", lambda event: self.clear_selected_entry("password"))
        self.phone_number_entry.bind("<FocusIn>", lambda event: self.set_selected_entry("phone_number"))
        self.phone_number_entry.bind("<FocusOut>", lambda event: self.clear_selected_entry("phone_number"))
        # Expression régulière pour valider le numéro de téléphone
        self.phone_regex = re.compile(r'^\d{10}$')  # Format : 10 chiffres sans espaces ni caractères spéciaux

        # Lier l'événement de saisie au champ d'entrée du numéro de téléphone
        self.phone_number_entry.bind("<KeyRelease>", self.validate_phone_number)

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
        master.configure(menu=menubar)

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
                    self.send_sms()  # Envoie un sms.
                    self.send_sms_checkbox.deselect()  # Décoche la case envoi par sms.
                    self.show_phone_entry()  # Relance la méthode pour effacer les widgets.
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
            return 0x00, locker_number - 1
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

    def set_selected_entry(self, entry_name):
        """Mettre à jour la variable selected_entry lorsqu'une entrée est sélectionnée."""
        self.selected_entry = entry_name

    def clear_selected_entry(self, entry_name):
        """Effacer la variable selected_entry lorsqu'une entrée n'est plus sélectionnée."""
        if self.selected_entry == entry_name:
            self.selected_entry = None

    def keypad_input(self, value):
        """Gère l'entrée du pavé numérique en fonction de l'entrée sélectionnée."""
        current_value = ""
        if self.selected_entry == "password":
            current_value = self.current_password.get()
        elif self.selected_entry == "phone_number":
            current_value = self.phone_number_entry.get()

        if value == "<<":
            current_value = ""
        else:
            current_value += value

        if self.selected_entry == "password":
            self.current_password.set(current_value)
            self.password_entry.icursor(tk.END)  # Place le curseur à la fin du champ de mot de passe.

        elif self.selected_entry == "phone_number":
            self.phone_number_entry.delete(0, tk.END)  # Effacer le contenu actuel de l'entrée
            self.phone_number_entry.insert(tk.END, current_value)  # Insérer le nouveau numéro de téléphone

    def update_status(self, message):
        """Met à jour le statut (message au-dessus du clavier)."""
        self.status_label.configure(text=message)

    def clear_password(self):
        """Efface le champ du mot de passe."""
        self.current_password.set("")  # Efface le champ mot de passe.
        self.password_entry.icursor(tk.END)  # Place le curseur à la fin du champ de mot de passe

    def clear_phone_number(self):
        """Efface le champ numéro de téléphone."""
        self.phone_number_entry.delete(0, tk.END)

    def clear_status(self):
        """Efface le statut."""
        self.status_label.configure(text="Bienvenue Empire47.")

    def show_phone_entry(self):
        """Affiche le champ de numéro de téléphone si la case à cocher est cochée."""
        if self.send_sms_var.get():
            self.phone_number_label.grid()
            self.phone_number_entry.grid()
            self.phone_number_entry.focus()
        else:
            self.phone_number_label.grid_remove()
            self.phone_number_entry.grid_remove()
            # Effacer le champ d'entrée du numéro de téléphone lorsque la case à cocher est décochée.
            self.phone_number_entry.delete(0, tk.END)
            # Réinitialiser la couleur de fond du champ d'entrée à sa couleur normale (noir)
            self.phone_number_entry.configure(fg_color="white")  # Couleur de fond normale

    def validate_phone_number(self, event):
        """Valide le numéro de téléphone lors de la saisie."""
        phone_number = self.phone_number_entry.get()

        # Vérifier si le numéro de téléphone correspond à l'expression régulière
        if re.match(r'^\(\d{3}\)\d{3}-\d{4}$', phone_number):
            self.phone_number_entry.configure(text_color="black")  # Réinitialiser la couleur du texte
            return True
        else:
            self.phone_number_entry.configure(fg_color="red")  # Afficher en rouge si le numéro est invalide
            return False

    def send_sms(self):
        """Fonction pour envoyer le mot de passe par SMS."""
        # Récupérer le mot de passe actuel
        current_password = self.current_password.get()

        # Vérifier si l'utilisateur a coché la case pour envoyer par SMS
        if self.send_sms_var.get() == 1:
            # Récupérer le numéro de téléphone saisi par l'utilisateur
            phone_number = self.phone_number_entry.get()

            try:
                # Valider le numéro de téléphone
                if self.validate_phone_number(phone_number):
                    # Ici, vous devriez implémenter la logique pour envoyer
                    # le SMS avec le mot de passe.
                    # Vous pouvez utiliser des bibliothèques Python comme
                    # Twilio pour envoyer des SMS
                    # Charger les variables d'environnement du fichier .env
                    load_dotenv(dotenv_path='secret.env')
                    # Utiliser les secrets du fichier secret.env.
                    account_sid = os.getenv('ACCOUNT_SID')
                    auth_token = os.getenv('AUTH_TOKEN')

                    client = Client(account_sid, auth_token)

                    if current_password.strip() != "":
                        message = client.messages.create(
                            from_='+15818905458',
                            to='+1' + phone_number,
                            body=f"Votre mot de passe est : {current_password}"
                        )
                        print(message.sid)

                        # Effacer le numéro de téléphone et revenir à la saisie du mot de passe
                        self.clear_phone_number()
                        self.password_entry.focus()

                        # Afficher une boîte de dialogue pour confirmer l'envoi du SMS
                        messagebox.showinfo("SMS envoyé", f"Le mot de passe a été envoyé à {phone_number} par SMS.")
                    else:
                        # Afficher un message d'erreur si le mot de passe est vide
                        messagebox.showerror("Erreur", "Le mot de passe est vide. Veuillez entrer un mot de passe.")
                else:
                    # Afficher un message d'erreur si le numéro de téléphone est invalide
                    messagebox.showerror("Erreur", "Veuillez saisir un numéro de téléphone valide.")
            except Exception as e:
                # Afficher un message d'erreur générique en cas d'erreur inattendue
                messagebox.showerror("Erreur", f"Une erreur est survenue lors de l'envoi du SMS : {str(e)}")

    def format_phone_number(self):
        """Formatte automatiquement le numéro de téléphone dans le format (123)123-1234."""
        # Récupérer le numéro de téléphone entré par l'utilisateur
        phone_number = self.phone_number_var.get()

        # Vérifier si le numéro de téléphone est vide

        # Supprimer tous les caractères non numériques du numéro de téléphone
        digits = re.sub(r"\D", "", phone_number)

        # Formater le numéro selon le format spécifié ((123)123-1234)
        formatted_number = "(" + digits[:3] + ")" + digits[3:6] + "-" + digits[6:10]

        # Mettre à jour le champ de saisie du numéro de téléphone avec le numéro formaté
        self.phone_number_entry.delete(0, tk.END)
        self.phone_number_entry.insert(0, formatted_number)


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
