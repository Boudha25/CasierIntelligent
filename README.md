Ce programme Python est une application de gestion de casiers utilisant une base de données SQLite et une communication série avec un appareil CU48. Il permet de verrouiller et déverrouiller les casiers à l'aide de mots de passe et de commander physiquement leur verrouillage/déverrouillage.

## Installation et Configuration

1. Assurez-vous d'avoir Python installé sur votre système.
2. Installez les dépendances en exécutant la commande suivante :

pip install customtkinter pyserial

3. Assurez-vous d'avoir le fichier `database.db` dans le dossier `data`.
4. Branchez le dispositif CU48 à votre ordinateur via le port série spécifié dans le code.
5. Exécutez le programme en exécutant le fichier Python `main.py`.

## Utilisation

Une fois le programme lancé, vous serez présenté avec une interface graphique contenant une liste de casiers numérotés. Vous pouvez cliquer sur un casier pour le verrouiller ou le déverrouiller en saisissant un mot de passe de 4 à 8 chiffres.

## Configuration

Pour configurer le programme, vous pouvez accéder au menu "Options" et sélectionner "Configurer". Vous devrez fournir le mot de passe maître actuel pour accéder à la configuration. Vous pouvez ensuite modifier le mot de passe maître et le sauvegarder.

**Note**: Assurez-vous de ne pas oublier le mot de passe maître, car il est nécessaire pour accéder à la configuration et modifier les paramètres du programme.

---

Pour toute question ou assistance supplémentaire, n'hésitez pas à me le faire savoir !
