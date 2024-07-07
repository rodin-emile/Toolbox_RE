Cybersecurity Toolbox RE

Ce script Python, développé par RODIN Emile, vise à fournir divers outils pour les tests de sécurité et l'exploitation dans un environnement informatique.
Nom de code : CyberWarrior

Fonctionnalités:

Découverte de Ports et Détection de Vulnérabilités
Utilise Nmap pour scanner les ports d'une adresse IP cible et détecter les vulnérabilités associées en utilisant des scripts comme Vulners.

Analyse de la Sécurité des Mots de Passe: Évalue la robustesse des mots de passe en utilisant l'algorithme zxcvbn et vérifie s'ils ont été compromis en interrogeant l'API pwnedpasswords.com.

Tests d'Authentification: Vérifie l'authentification SSH sur une machine distante en tentant de se connecter avec des identifiants préconfigurés.

Recherche d'Exploits: Utilise SearchSploit pour trouver des exploits correspondant à une requête spécifique, facilitant ainsi la recherche de failles exploitables.

Exploitation de Vulnérabilités avec Metasploit: Automatise l'exploitation de vulnérabilités en utilisant Metasploit Framework, permettant la sélection et la configuration de payloads pour les attaques.

Post-Exploitation: Effectue des commandes post-exploitation sur une machine compromise pour recueillir des informations supplémentaires ou exécuter des actions malveillantes.

Reporting: Génère un rapport PDF détaillant les résultats des tests d'intrusion, les vulnérabilités identifiées et des recommandations pour améliorer la sécurité.

Vérification de la Disponibilité de Payloads Metasploit

Vérifie si un payload spécifique est disponible dans Metasploit pour être utilisé lors de l'exploitation des vulnérabilités.

Prérequis
Avant d'utiliser cet outil, assurez-vous d'exécuter le script prerequis.sh pour installer toutes les dépendances nécessaires. Ce script installe les bibliothèques requises et configure l'environnement pour l'exécution correcte des fonctionnalités de la Boîte à Outils de Cybersécurité.
Assurez-vous également de ne pas avoir apache 2 déjà installé sur votre système, car cela pourrait entraîner des conflits de configuration avec certains composants de cet outil.
modifier les chemins pourqu'il correspond au chemin ou se trouve le dossier.

Installation
Clonez ce dépôt :
Copier le code
git clone https://github.com/rodin-emile/Toolbox_RE.git

Étapes d'utilisation
Lancez le script toolbox.py et suivez les instructions pour configurer l'adresse IP de la cible ainsi que d'autres informations nécessaires.
Génération du Fichier vulnerabilites.csv

Une fois la configuration terminée, le script effectue une analyse de la cible et génère un fichier vulnerabilites.csv qui contient les résultats des scans de vulnérabilités.
Analyse de la Sécurité des Mots de Passe

Utilisez l'option 3 dans le menu pour évaluer la robustesse des mots de passe présents sur la cible. Le système utilise zxcvbn pour évaluer la force des mots de passe et vérifier s'ils ont été compromis.
Tests d'Authentification

Utilisez l'option 4 pour tester des identifiants et des mots de passe récupérés ou pour effectuer des tests d'authentification sur la cible.
Recherche d'un Exploit avec SearchSploit

Utilisez l'option 5 pour rechercher un exploit correspondant aux vulnérabilités détectées. Sélectionnez également un payload adapté pour l'exploit.
Vérification de Disponibilité sur Metasploit

Utilisez l'option 6 pour vérifier si l'exploit et le payload sélectionnés sont disponibles dans Metasploit. Assurez-vous que votre machine Kali est configurée avec msfrpcd pour permettre une connexion client.
Lancement de l'Exploit avec Metasploit

Utilisez l'option 6 pour automatiser l'exploitation des vulnérabilités en utilisant Metasploit. Suivez les instructions pour sélectionner l'exploit et le payload, puis lancez l'exploit.
Obtention d'un Accès Shell Actif
Exemple :

=== MENU PRINCIPAL ===

Veuillez choisir une option :

1. Configuration
2. Découverte de ports, de services et Détection de vulnérabilités
3. Analyse de la sécurité des mots de passe
4. Tests d'authentification
5. Searchsploit
6. Exploitation de vulnérabilités
7. Post-exploitation
8. Générer le rapport des Tests d'Intrusion
9. Quitter

Votre choix : 6

Entrez l'adresse IP de la machine Metasploit : 192.168.2.129
Entrez le port de la machine Metasploit (par défaut : 55552) : 55552
Entrez le mot de passe Metasploit : 
Entrez le nom de l'exploit à utiliser : unix/ftp/vsftpd_234_backdoor

Liste des payloads disponibles pour l'exploit sélectionné :
1. cmd/unix/interact
Sélectionnez un payload (par numéro) : 1
Entrez le port cible : 21

ID du travail : {'job_id': 0, 'uuid': 'ewzymyty'}
ID de la session : 1

Une fois l'exploit réussi, vous obtiendrez un accès à un shell actif sur la cible compromise.
Post-Exploitation
Ce README inclut un exemple d'utilisation de l'exploit unix/ftp/vsftpd_234_backdoor avec Metasploit sur une machine metasploitable. 

Revenez au menu principal et utilisez l'option 7 pour exécuter des commandes post-exploitation sur la cible. Cela permet de récupérer des informations pertinentes sur la cible compromise.

Génération d'un Rapport

Utilisez l'option 8 pour générer un rapport PDF détaillant les résultats des tests d'intrusion, les vulnérabilités exploitées, les informations récupérées et les actions effectuées.


Liste de commande utile
Connexion au service msfrpcd de Metasploit :
msfrpcd -P <mot de passe> -p <port>
Remplacez <mot de passe> par le mot de passe configuré pour msfrpcd.
Remplacez <port> par le port sur lequel msfrpcd est configuré pour écouter.
Vérifier si un port est à l'écoute :
lsof -i :<port>
Remplacez <port> par le numéro de port que vous souhaitez vérifier.
Forcer l'arrêt d'un processus utilisant un port spécifique :
kill -9 $(lsof -t -i:<port>)
Cette commande utilise lsof pour trouver le PID du processus écoutant sur le port spécifié, puis utilise kill -9 pour forcer l'arrêt de ce processus.
Ces commandes seront utiles pour gérer la connexion à msfrpcd, vérifier les ports et arrêter les processus nécessaires lorsque vous travaillez avec Metasploit et d'autres outils de sécurité.

Notes
Sécurité : Faites preuve de prudence lors de l'utilisation d'outils qui interagissent avec des systèmes distants. Assurez-vous d'avoir les autorisations et les permissions nécessaires avant d'effectuer des actions intrusives.
Responsabilité : Respectez les limites légales et obtenez les permissions nécessaires avant de réaliser des évaluations de sécurité ou des tests sur des systèmes que vous ne possédez pas ou n'exploitez pas.

Avertissement
Ce script est fourni tel quel. Utilisez-le de manière responsable et uniquement sur des systèmes pour lesquels vous avez l'autorisation de tester. L'auteur n'assume aucune responsabilité pour une utilisation abusive ou un accès non autorisé.


Contributions
Les contributions sont les bienvenues! Si vous souhaitez contribuer à ce projet, veuillez ouvrir une issue pour discuter des modifications proposées.

Licence
Ce projet est sous licence MIT - voir le fichier LICENSE.md pour plus de détails.

Contact
Pour toute question ou suggestion, contactez RODIN Emile à l'adresse rodin-emile@hotmail.com.

