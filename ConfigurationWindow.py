import hashlib
from tkinter import messagebox
import tkinter as tk


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
