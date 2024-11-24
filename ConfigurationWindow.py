import hashlib
import json
from tkinter import messagebox
import tkinter as tk


def read_config_file(file_path):
    """Lit la configuration à partir d'un fichier JSON."""
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "cu48_ranges": [(1, 24), (25, 48), (49, 72)],
            "num_lockers": 48
        }


def write_config_file(file_path, config):
    """Écrit la configuration dans un fichier JSON."""
    with open(file_path, 'w') as file:
        json.dump(config, file, indent=4)


class ConfigWindow:
    def __init__(self, master, locker_manager_gui, master_password_hash, config_file_path):
        """Initialise la fenêtre de configuration."""
        self.master = master
        self.locker_manager_gui = locker_manager_gui
        self.master_password_hash = master_password_hash
        self.config_file_path = config_file_path

        # Lire la configuration actuelle
        self.config = read_config_file(config_file_path)
        self.cu48_ranges = self.config["cu48_ranges"]

        # Création des widgets pour la fenêtre de configuration.
        self.master_password_label = tk.Label(master, text="Mot de passe maître:", font=("Arial", 30))
        self.master_password_entry = tk.Entry(master, show="*", font=("Arial", 30))
        self.confirm_new_master_password_label = tk.Label(master, text="Confirmer le nouveau mot de passe maître:",
                                                          font=("Arial", 30))
        self.confirm_new_master_password_entry = tk.Entry(master, show="*", font=("Arial", 30))
        self.new_master_password_label = tk.Label(master, text="Nouveau mot de passe maître:", font=("Arial", 30))
        self.new_master_password_entry = tk.Entry(master, show="*", font=("Arial", 30))
        self.save_button = tk.Button(master, text="Enregistrer", command=self.save_config, font=("Arial", 30))

        # Création des widgets pour la configuration des adresses CU48.
        self.num_lockers_label = tk.Label(master, text="Nombre total de casiers:", font=("Arial", 30))
        self.num_lockers_entry = tk.Entry(master, font=("Arial", 30))
        self.num_lockers_entry.insert(0, str(self.config.get("num_lockers", 48)))  # Valeur par défaut à 48

        self.save_button = tk.Button(master, text="Enregistrer", command=self.save_config, font=("Arial", 30))

        self.cu48_label = tk.Label(master, text="Configuration des plages d'adresses par CU48:",
                                   font=("Arial", 30, 'bold'))
        self.address1_label = tk.Label(master, text="Adresse 0x00:", font=("Arial", 30))
        self.address1_start_entry = tk.Entry(master, font=("Arial", 30))
        self.address1_end_entry = tk.Entry(master, font=("Arial", 30))

        self.address2_label = tk.Label(master, text="Adresse 0x01:", font=("Arial", 30))
        self.address2_start_entry = tk.Entry(master, font=("Arial", 30))
        self.address2_end_entry = tk.Entry(master, font=("Arial", 30))

        self.address3_label = tk.Label(master, text="Adresse 0x02:", font=("Arial", 30))
        self.address3_start_entry = tk.Entry(master, font=("Arial", 30))
        self.address3_end_entry = tk.Entry(master, font=("Arial", 30))

        # Remplir les champs de saisie avec les plages actuelles
        self.address1_start_entry.insert(0, str(self.cu48_ranges[0][0]))
        self.address1_end_entry.insert(0, str(self.cu48_ranges[0][1]))
        self.address2_start_entry.insert(0, str(self.cu48_ranges[1][0]))
        self.address2_end_entry.insert(0, str(self.cu48_ranges[1][1]))
        self.address3_start_entry.insert(0, str(self.cu48_ranges[2][0]))
        self.address3_end_entry.insert(0, str(self.cu48_ranges[2][1]))

        # Placement des widgets dans la fenêtre.
        self.master_password_label.grid(row=0, column=0, padx=10, pady=5)
        self.master_password_entry.grid(row=0, column=1, padx=10, pady=5)
        self.new_master_password_label.grid(row=1, column=0, padx=10, pady=5)
        self.new_master_password_entry.grid(row=1, column=1, padx=10, pady=5)
        self.confirm_new_master_password_label.grid(row=2, column=0, padx=10, pady=5)
        self.confirm_new_master_password_entry.grid(row=2, column=1, padx=10, pady=5)

        self.cu48_label.grid(row=3, column=0, columnspan=2, padx=10, pady=10)
        self.num_lockers_label.grid(row=4, column=0, padx=10, pady=5)
        self.num_lockers_entry.grid(row=4, column=1, padx=10, pady=5)
        self.save_button.grid(row=5, columnspan=2, padx=10, pady=5)

        self.address1_label.grid(row=6, column=0, padx=10, pady=5)
        self.address1_start_entry.grid(row=6, column=1, padx=10, pady=5)
        self.address1_end_entry.grid(row=6, column=2, padx=10, pady=5)

        self.address2_label.grid(row=7, column=0, padx=10, pady=5)
        self.address2_start_entry.grid(row=7, column=1, padx=10, pady=5)
        self.address2_end_entry.grid(row=7, column=2, padx=10, pady=5)

        self.address3_label.grid(row=8, column=0, padx=10, pady=5)
        self.address3_start_entry.grid(row=8, column=1, padx=10, pady=5)
        self.address3_end_entry.grid(row=8, column=2, padx=10, pady=5)

        self.save_button.grid(row=9, columnspan=3, padx=10, pady=10)

        # Ajouter un bouton "Fermer" pour fermer la fenêtre de configuration.
        self.close_button = tk.Button(master, text="Fermer", command=self.close_config_window, font=("Arial", 30))
        self.close_button.grid(row=10, columnspan=3, padx=10, pady=10)

        # Bouton pour déverrouiller le casier 1
        self.unlock_locker1_button = tk.Button(master, text="Déverrouiller casier 1",
                                               command=self.unlock_locker1, font=("Arial", 30))
        self.unlock_locker1_button.grid(row=11, columnspan=3, padx=10, pady=10)

    def close_config_window(self):
        """Ferme la fenêtre de configuration."""
        self.master.destroy()

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

            # Vérifier si l'utilisateur souhaite changer le mot de passe maître
            if new_master_password or confirm_new_master_password:
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

                    else:
                        messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas.")
                        return
                else:
                    messagebox.showerror("Erreur",
                                         "Le nouveau mot de passe maître doit contenir entre 4 et 8 chiffres.")
                    return

            # Sauvegarder les adresses CU48
            try:
                address1_range = (int(self.address1_start_entry.get()), int(self.address1_end_entry.get()))
                address2_range = (int(self.address2_start_entry.get()), int(self.address2_end_entry.get()))
                address3_range = (int(self.address3_start_entry.get()), int(self.address3_end_entry.get()))

                # Vérifier que chaque plage CU48 ne dépasse pas 48 casiers
                if (address1_range[1] - address1_range[0] + 1) > 48:
                    messagebox.showerror("Erreur",
                                         "La plage d'adresse 0x00 ne doit pas contenir plus de 48 casiers.")
                    return
                if (address2_range[1] - address2_range[0] + 1) > 48:
                    messagebox.showerror("Erreur",
                                         "La plage d'adresse 0x01 ne doit pas contenir plus de 48 casiers.")
                    return
                if (address3_range[1] - address3_range[0] + 1) > 48:
                    messagebox.showerror("Erreur",
                                         "La plage d'adresse 0x02 ne doit pas contenir plus de 48 casiers.")
                    return

                self.locker_manager_gui.update_cu48_ranges(address1_range, address2_range, address3_range)

                # Récupérer la valeur du nombre total de casiers sous forme de chaîne
                num_lockers_str = self.num_lockers_entry.get()

                # Vérifier si la chaîne extraite contient uniquement des chiffres et qu'elle n'est pas vide
                if num_lockers_str.isdigit() and int(num_lockers_str) > 0:
                    # Convertir la chaîne en entier
                    num_lockers = int(num_lockers_str)
                else:
                    # Afficher une erreur si la valeur n'est pas un entier positif
                    messagebox.showerror("Erreur", "Le nombre total de casiers doit être un entier positif.")
                    return

                # Mettre à jour la configuration
                self.config["cu48_ranges"] = [address1_range, address2_range, address3_range]
                self.config["num_lockers"] = num_lockers
                write_config_file(self.config_file_path, self.config)

                # Mettre à jour le nombre de casiers dans l'application principale
                self.locker_manager_gui.update_num_lockers(num_lockers)

                # Fermer la fenêtre de configuration
                self.master.destroy()
            except ValueError:
                messagebox.showerror("Erreur", "Les valeurs des plages doivent être des entiers.")
        else:
            messagebox.showerror("Erreur", "Mot de passe maître incorrect")

    def unlock_locker1(self):
        """Déverrouille le casier numéro 1 après vérification du mot de passe maître."""
        entered_password = self.master_password_entry.get()
        entered_password_hash = hashlib.sha256(entered_password.encode()).hexdigest()

        # Vérification du mot de passe maître
        if entered_password_hash == self.master_password_hash:
            # Initialiser la communication avec CU48
            cu48 = self.locker_manager_gui.cu48_communication  # Supposons que la classe principale gère cette instance
            if cu48:
                cu48.send_command(addr=0x00, locker=0, cmd=0x51)  # Commande pour déverrouiller
                messagebox.showinfo("Succès", "Casier 1 déverrouillé avec succès !")
            else:
                messagebox.showerror("Erreur", "Communication CU48 non disponible.")
        else:
            messagebox.showerror("Erreur", "Mot de passe maître incorrect.")
