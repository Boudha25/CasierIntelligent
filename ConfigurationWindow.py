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
            "cu48_ranges": [(1, 24), (25, 48), (49, 72)]
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
        self.master_password_label = tk.Label(master, text="Mot de passe maître:", font=("Arial", 14))
        self.master_password_entry = tk.Entry(master, show="*")
        self.confirm_new_master_password_label = tk.Label(master, text="Confirmer le nouveau mot de passe maître:",
                                                          font=("Arial", 14))
        self.confirm_new_master_password_entry = tk.Entry(master, show="*")
        self.new_master_password_label = tk.Label(master, text="Nouveau mot de passe maître:", font=("Arial", 14))
        self.new_master_password_entry = tk.Entry(master, show="*")
        self.save_button = tk.Button(master, text="Enregistrer", command=self.save_config, font=("Arial", 14))

        # Création des widgets pour la configuration des adresses CU48.
        self.cu48_label = tk.Label(master, text="Configuration des adresses CU48:", font=("Arial", 14, 'bold'))
        self.address1_label = tk.Label(master, text="Adresse 0x00:", font=("Arial", 14))
        self.address1_start_entry = tk.Entry(master)
        self.address1_end_entry = tk.Entry(master)

        self.address2_label = tk.Label(master, text="Adresse 0x01:", font=("Arial", 14))
        self.address2_start_entry = tk.Entry(master)
        self.address2_end_entry = tk.Entry(master)

        self.address3_label = tk.Label(master, text="Adresse 0x02:", font=("Arial", 14))
        self.address3_start_entry = tk.Entry(master)
        self.address3_end_entry = tk.Entry(master)

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
        self.address1_label.grid(row=4, column=0, padx=10, pady=5)
        self.address1_start_entry.grid(row=4, column=1, padx=10, pady=5)
        self.address1_end_entry.grid(row=4, column=2, padx=10, pady=5)

        self.address2_label.grid(row=5, column=0, padx=10, pady=5)
        self.address2_start_entry.grid(row=5, column=1, padx=10, pady=5)
        self.address2_end_entry.grid(row=5, column=2, padx=10, pady=5)

        self.address3_label.grid(row=6, column=0, padx=10, pady=5)
        self.address3_start_entry.grid(row=6, column=1, padx=10, pady=5)
        self.address3_end_entry.grid(row=6, column=2, padx=10, pady=5)

        self.save_button.grid(row=7, columnspan=3, padx=10, pady=10)

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

                # Vérifier que le nombre total de casiers ne dépasse pas 48
                total_lockers = (address1_range[1] - address1_range[0] + 1) + \
                                (address2_range[1] - address2_range[0] + 1) + \
                                (address3_range[1] - address3_range[0] + 1)
                if total_lockers > 48:
                    messagebox.showerror("Erreur",
                                         "Les plages CU48 ne doivent pas contenir plus de 48 casiers au total.")
                    return

                self.locker_manager_gui.update_cu48_ranges(address1_range, address2_range, address3_range)

                # Mettre à jour la configuration
                self.config["cu48_ranges"] = [address1_range, address2_range, address3_range]
                write_config_file(self.config_file_path, self.config)

                # Fermer la fenêtre de configuration
                self.master.destroy()
            except ValueError:
                messagebox.showerror("Erreur", "Les valeurs des plages doivent être des entiers.")
        else:
            messagebox.showerror("Erreur", "Mot de passe maître incorrect")
