import hashlib
import sqlite3


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
            if result is not None:
                return bool(result[0])
            return False  # Si l'état est absent, considérer le casier comme "non verrouillé"

        except sqlite3.Error as e:
            print("Erreur de de récupération de l'état du casier dans la base de données:", e)
