from Database import DatabaseManager
from ConfigurationWindow import ConfigWindow
from Cu48Communication import CU48Communication
import hashlib
import re
import tkinter as tk
from tkinter import Menu, messagebox
import customtkinter as ctk  # Importer customTkinter au lieu de tkinter
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

        # Configuration des lignes de la grille. Ajustement automatique.
        for i in range(numb_lockers):
            master.grid_rowconfigure(i, weight=1)

        # Configuration des colonnes de la grille
        for j in range(8):  # ou tout autre nombre de colonnes que vous utilisez
            master.grid_columnconfigure(j, weight=1)

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
        self.password_label = ctk.CTkLabel(master, height=30, text="Entrer un mot de passe de 4 à 8 chiffres, "
                                                                   "\n et sélectionner un casier:", font=("Arial", 24))
        self.password_label.grid(row=(numb_lockers - 1) // 5 + 1, column=0, columnspan=4, pady=20)

        self.password_entry = ctk.CTkEntry(master, show="*", textvariable=self.current_password, width=200, height=40)
        self.password_entry.grid(row=(numb_lockers - 1) // 5 + 2, column=0, columnspan=4, pady=5)
        self.password_entry.icursor(ctk.END)  # Place le curseur à la fin du champ de mot de passe.

        self.status_label = ctk.CTkLabel(master, text="", width=40, height=30, font=("Arial", 24))
        self.status_label.grid(row=(numb_lockers - 1) // 5 + 3, columnspan=4, pady=5, sticky="n")

        self.keypad_frame = ctk.CTkFrame(master, fg_color="white")  # Couleur de fond par défaut
        self.keypad_frame.grid(row=(numb_lockers - 1) // 5 + 4, rowspan=2, column=0, columnspan=4, pady=5, sticky="n")

        # Ajouter le checkbox pour envoyer le mot de passe par SMS
        self.send_sms_var = tk.IntVar()
        self.send_sms_checkbox = ctk.CTkCheckBox(master, text="Envoyer le mot de passe par texto",
                                                 variable=self.send_sms_var, onvalue=True, offvalue=False,
                                                 font=("Arial", 24), command=self.show_phone_entry)
        self.send_sms_checkbox.grid(row=(numb_lockers - 1) // 5 + 1, rowspan=2, column=4, columnspan=5, pady=20,
                                    sticky="nw")

        # Ajouter le champ pour saisir le numéro de téléphone.
        self.phone_number_label = ctk.CTkLabel(master, text="Numéro de téléphone:", font=("Arial", 24))
        self.phone_number_label.grid(row=(numb_lockers - 1) // 5 + 1, column=4, columnspan=5, pady=0, sticky="sw")
        self.phone_number_var = tk.StringVar()
        self.phone_number_var.trace("w", lambda *args: self.format_phone_number())
        self.phone_number_entry = ctk.CTkEntry(master, width=110, height=40, textvariable=self.phone_number_var)
        self.phone_number_entry.grid(row=(numb_lockers - 1) // 5 + 2, column=4, columnspan=5, pady=5, sticky="nw")
        self.phone_number_entry.icursor(ctk.END)  # Place le curseur à la fin du champ.

        # Masquer initialement le champ de numéro de téléphone
        self.phone_number_label.grid_remove()
        self.phone_number_entry.grid_remove()
        self.selected_entry = None

        # Ajouter le champ pour afficher les instructions.
        self.instruction_label = ctk.CTkLabel(master, text="Instructions:\n", font=("Arial", 24))
        self.instruction_label.grid(row=(numb_lockers - 1) // 5 + 3, rowspan=2, column=4, columnspan=5,
                                    padx=0, pady=5, sticky="nw")
        self.instruction_line_label = ctk.CTkLabel(master, text="-Pour ouvrir un casier : \n"
                                                                "1. À l'aide du clavier, saisissez un mot de "
                                                                "passe de 4 à 8 chiffres.\n"
                                                                "2.(facultatif) Cochez la case (Envoyer le mot de "
                                                                "passe par texto).\n"
                                                                "3.(facultatif) Saisissez les 10 chiffres de votre "
                                                                "numéro de cellulaire.\n"
                                                                "4. Sélectionnez le casier que vous souhaitez ouvrir.\n"
                                                                "5. Le casier s'ouvrira automatiquement.\n\n"
                                                                "-Pour déverrouiller un casier : \n"
                                                                "1. Saisissez le mot de passe utilisateur que vous "
                                                                "avez choisi à l'étape 1.\n"
                                                                "2. Cliquez sur le casier que vous avez verrouillé.\n",
                                                   font=("Arial", 18), justify="left")
        self.instruction_line_label.grid(row=(numb_lockers - 1) // 5 + 4, column=4, columnspan=5, pady=0, sticky="nw")

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

        self.create_keypad()  # Création du clavier.
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
        help_text = ("-Pour ouvrir un casier : \n"
                     "1. À l'aide du pavé numérique, saisissez un mot de passe de 4 à 8 chiffres.\n"
                     "2. Cochez la case (Envoyer le mot de passe par texto), facultatif.\n"
                     "3. Saisissez les 10 chiffres de votre numéro de cellulaire, facultatif.\n"
                     "4. Sélectionnez le casier que vous souhaitez ouvrir.\n"
                     "5. Le casier s'ouvrira automatiquement.\n\n"
                     "-Pour déverrouiller un casier : \n"
                     "1. Saisissez le mot de passe utilisateur que vous avez choisi à l'étape 1.\n"
                     "2. Cliquez sur le casier que vous avez verrouillé.\n\n"
                     )

        # Créer une nouvelle fenêtre pour afficher l'aide.
        help_window = ctk.CTkToplevel(self.master)
        help_window.title("Aide")
        help_window.geometry("700x400")
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
            ("0", 3, 1), ("Efface", 3, 2)
        ]
        for (text, row, column) in buttons:
            button = ctk.CTkButton(self.keypad_frame, text=text,
                                   fg_color="grey",  # Couleur de fond par défaut
                                   font=("Arial", 24),
                                   height=40,
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

        if value == "Efface":
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

    def validate_phone_number(self, _event):
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
        """Ajuste automatiquement le numéro de téléphone dans le format (123)123-1234."""
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


# Fonction à exécuter pour quitter l'application
def quitter_application(_event=None):
    root.destroy()


# Donne le nombre de casiers à créer.
num_lockers = 48

# Crée une instance principale de l'interface graphique Tkinter.
root = ctk.CTk()
root.title("Gestion des Casiers")
root.configure(background="white")  # couleur de fond
# Définition de la résolution de l'écran
largeur_screen = root.winfo_screenwidth()
hauteur_screen = root.winfo_screenheight()
# Définition des dimensions de la fenêtre
root.geometry(f"{largeur_screen}x{hauteur_screen}")
print("Écran", largeur_screen, hauteur_screen)
# Affichage de la fenêtre en plein écran.
root.attributes("-fullscreen", True)  # Enlève le X pour pouvoir fermer la fenêtre.
# Lier la touche "<Echap>" pour quitter l'application.
root.bind("<Escape>", quitter_application)


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
