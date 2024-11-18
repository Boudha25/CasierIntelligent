import serial


class CU48Communication:
    def __init__(self, port='com1', baudrate=19200, status_label=None):
        """Initialise une communication série pour communiquer avec le CU48."""
        print("Port série utilisé:", port)  # Affiche la valeur du port série.
        self.ser = None  # Initialiser self.ser à None par défaut
        self.status_label = status_label  # Ajouter le status_label comme attribut.
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
        if self.ser is None:
            print("Erreur: Port série non initialisé.")
            return
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
        if self.ser is not None:
            try:
                self.ser.close()
            except Exception as e:
                print("Erreur lors de la fermeture du port série:", e)
