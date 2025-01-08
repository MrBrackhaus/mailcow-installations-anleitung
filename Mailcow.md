---
title: "Sichere Mailserver-Implementierung: Ein Leitfaden zur Installation und Konfiguration eines sicheren Mailcow Servers mit Proxmox VE und pfSense" 
author: Michael Kurz 
date: "14. Oktober 2024" 
subtitle: "Mail für Fortgeschrittene: Wie man mit Proxmox und pfSense einen Mailserver baut, der sogar deiner Schwiegermutter standhält." 
lang: de 
keywords: 
- Mailcow
- Proxmox
- pfSense
- Docker
output:
  pdf_document:
    latex_engine: xelatex
    keep_tex: true
    includes:
      in_header: header.tex

---

\begin{center} \includegraphics[width=1.0\textwidth]{S:/Dokumentationen/Titelbild.png} \end{center}

## Danksagung

Ich möchte mich herzlich bei meiner Servercrew bedanken, die maßgeblich zur Fertigstellung dieser Dokumentation beigetragen hat. Ohne eure wertvollen Hinweise, Unterstützung und den ständigen Austausch wäre dieses Werk nicht dasselbe geworden. Euer Engagement hat den Weg zu einer optimierten und sicheren E-Mail-Server-Architektur geebnet. Ein besonderes Dankeschön gilt auch der Open-Source-Community, die durch unermüdliche Arbeit die Software und Tools entwickelt hat, die diese Implementierung überhaupt erst möglich machen.

## Vorwort

Diese Dokumentation entstand aus dem Wunsch heraus, eine umfassende, zuverlässige und sichere Lösung für die E-Mail-Server-Administration zu schaffen. In der heutigen Zeit, in der Datenschutz und Sicherheit von größter Bedeutung sind, war es mein Ziel, eine detaillierte Anleitung zu entwickeln, die sowohl den aktuellen Standards entspricht als auch praktikable und zukunftssichere Lösungen bietet. Durch die Erfahrungen, die ich in diesem Projekt gesammelt habe, konnte ich mein technisches Verständnis und meine Fähigkeiten weiter ausbauen. Diese Dokumentation soll nicht nur ein Hilfsmittel für Administratoren und IT-Profis sein, sondern auch als Inspiration dienen, kontinuierlich nach besseren und sichereren Lösungen zu streben. Ich hoffe, dass diese Anleitung anderen als wertvolle Ressource dient und ihnen dabei hilft, ihre eigenen Projekte effizient und sicher umzusetzen.

\tableofcontents
\
\
\
\
\


## Kapitel 1: Einleitung und Zielsetzung

### 1.1 Einleitung

Diese Dokumentation beschreibt die detaillierte Installation und Konfiguration eines sicheren Mailcow-Servers auf Proxmox VE mit pfSense als Firewall. Mailcow, eine vollständige Mailserver-Lösung, wird in einer containerisierten Umgebung mittels Docker und Docker-Compose betrieben, um Skalierbarkeit und Sicherheit zu gewährleisten. Die Nutzung von Proxmox VE als Hypervisor ermöglicht die Virtualisierung des Mailservers und weiterer Services, während pfSense als Firewall-Lösung die Netzwerk- und Zugriffssicherheit sicherstellt.

Moderne Sicherheitsprotokolle wie TLS 1.2+, SPF, DKIM, DMARC, MTA-STS und DANE werden in dieser Anleitung detailliert beschrieben und implementiert, um eine sichere und verlässliche E-Mail-Kommunikation zu gewährleisten.

### 1.2 Zielsetzung

Das primäre Ziel dieser Dokumentation ist es, eine robuste und skalierbare E-Mail-Infrastruktur aufzubauen, die durch bewährte Sicherheitsprotokolle geschützt wird und gleichzeitig den Anforderungen der DSGVO entspricht. Es wird erläutert, wie der Mailserver in einer sicheren Umgebung betrieben werden kann, einschließlich der Konfiguration von SSL/TLS-Zertifikaten, Firewall-Regeln und fortschrittlichen Sicherheitsprotokollen.

### 1.3 Zielgruppe und Voraussetzungen

Diese Anleitung richtet sich an Systemadministratoren, Cloud-Architekten und IT-Experten, die bereits Kenntnisse in der Verwaltung von Proxmox, pfSense und Mailserver-Technologien haben. Grundkenntnisse in der Netzwerk- und Systemadministration werden vorausgesetzt, ebenso wie ein grundlegendes Verständnis für Virtualisierung und Container-Technologien.

\
**Voraussetzungen:**

- Erfahrung im Umgang mit Proxmox VE, pfSense und Docker.
- Grundlegendes Verständnis von Netzwerkprotokollen (IPv4, IPv6) und Mailserver-Konfiguration.
- Zugriff auf eine Proxmox VE-Instanz mit ausreichend Ressourcen (CPU, RAM, Speicher).
- Verfügbarkeit einer öffentlichen IP-Adresse sowie einer registrierten Domain zur Konfiguration des Mailservers.

---

## Kapitel 2: Systemanforderungen und Vorbereitung

### 2.1 Hardware- und Softwareanforderungen

Um einen sicheren und leistungsfähigen Mailcow-Server zu betreiben, müssen die folgenden Mindestanforderungen für die virtuelle Maschine (VM) erfüllt sein, auf der Mailcow betrieben wird:

**Mailcow-VM auf Proxmox VE:**

- CPU: 8 Kerne (Intel i9-13900k empfohlen)
- RAM: 16 GB (abhängig von der Anzahl der Nutzer und der E-Mail-Daten)
- Speicherplatz: 100 GB NVMe SSD (anpassbar je nach E-Mail-Aufkommen)
- Netzwerkschnittstellen:
  - LAN IPv4: 10.3.0.4/24
  - LAN IPv6: fd03::4/48

**pfSense-Firewall (auf separater VM oder physischer Appliance):**

- LAN IPv4: 10.3.0.1/24
- LAN IPv6: fd03::1/48
- DNS-Server: 10.3.0.1

\

**Öffentliche IP-Adressen für den Mailserver:**

- IPv4: 134.255.229.52
- IPv6: 2a05:bec0:27:fd03::4/48

### 2.2 Vorbereitung der Proxmox-VM

Die Proxmox-VM für Mailcow ist bereits eingerichtet und verfügt über die erforderlichen Ressourcen (8 CPU-Kerne, 16 GB RAM, 100 GB NVMe-Speicher). Folgende Vorbereitungen sollten getroffen werden, um die Umgebung optimal abzusichern und auf die Installation von Mailcow vorzubereiten:

1. **System-Updates ausführen:**

   - Vor der Installation von Docker und Mailcow sollte die VM auf den neuesten Stand gebracht werden.

   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Netzwerk- und DNS-Konfiguration überprüfen:**

   - Stelle sicher, dass die Mailcow-VM die richtigen IP-Adressen verwendet:
     - IPv4: 10.3.0.4/24
     - IPv6: fd03::4/48
     - DNS-Server: 10.3.0.1 (pfSense)
   - Verwende folgende Befehle, um die Konfiguration zu überprüfen:

   ```bash
   ip addr show
   ```

### 2.3 Sicherheitsoptimierung der Mailcow-VM

Um die Sicherheit der Mailcow-Instanz zu erhöhen, sollten zusätzliche Maßnahmen ergriffen werden:

1. **CrowdSec installieren:** CrowdSec schützt den Server vor böswilligen Angriffen und analysiert verdächtige Aktivitäten. Es bietet eine erweiterte Sicherheitsüberwachung.

   ```bash
   sudo apt install crowdsec
   sudo cscli hub update
   sudo cscli collections install crowdsecurity/sshd
   sudo systemctl restart crowdsec
   ```

2. **UFW (Uncomplicated Firewall) konfigurieren:**

   - Zur Absicherung der VM sollte UFW aktiviert und entsprechend konfiguriert werden, um unerwünschte Verbindungen zu blockieren:

   ```bash
   sudo apt install ufw
   sudo ufw allow ssh
   sudo ufw enable
   ```

3. **SSH-Härtung:**

   - Passwort-Authentifizierung deaktivieren und nur SSH-Schlüssel zulassen, um Brute-Force-Angriffe auf den SSH-Zugang zu verhindern:

   ```bash
   sudo nano /etc/ssh/sshd_config
   ```

   - Setze folgende Werte:

   ```text
   PasswordAuthentication no
   PermitRootLogin no
   ```
\
\
\

### 2.4 Sicherstellung der IPv6-Unterstützung

Die Konfiguration von IPv6 ist wichtig, um den Mailserver sowohl über IPv4 als auch IPv6 zugänglich zu machen. Stelle sicher, dass IPv6 korrekt eingerichtet ist und funktioniert:

1. **Überprüfe die IPv6-Adressen mit folgendem Befehl:**

   ```bash
   ip -6 addr show
   ```

2. **Teste die IPv6-Konnektivität:**

   ```bash
   ping6 google.com
   ```

### 2.5 Checkliste für Systemanforderungen und Vorbereitung

- \autocheckbox{} Proxmox-VM mit den richtigen Ressourcen konfiguriert (8 CPU-Kerne, 16 GB RAM, 100 GB SSD).
- \autocheckbox{} System-Updates auf der Mailcow-VM durchgeführt.
- \autocheckbox{} Netzwerkschnittstellen für IPv4 und IPv6 konfiguriert und überprüft.
- \autocheckbox{} CrowdSec installiert und aktiv.
- \autocheckbox{} UFW konfiguriert und aktiviert.
- \autocheckbox{} SSH-Härtung durchgeführt (Passwort-Authentifizierung deaktiviert).
- \autocheckbox{} IPv6-Konnektivität getestet.

---

## Kapitel 3: Installation von Docker und Docker-Compose

### 3.1 Einführung: Warum Docker und Docker-Compose für Mailcow genutzt werden

Docker und Docker-Compose sind die Kerntechnologien, auf denen Mailcow basiert. Docker ermöglicht die Containerisierung, wodurch die verschiedenen Dienste von Mailcow isoliert und unabhängig voneinander betrieben werden. Dies erhöht die Sicherheit und Skalierbarkeit. Docker-Compose vereinfacht das Management mehrerer Container, die zusammenarbeiten, indem es die Konfiguration und den Start der Container automatisiert.

### 3.2 Installation von Docker

Schritt-für-Schritt-Anleitung zur Docker-Installation:

1. **System-Update durchführen:** Aktualisiere das System, um sicherzustellen, dass alle Pakete auf dem neuesten Stand sind:

   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Erforderliche Abhängigkeiten installieren:** Installiere die nötigen Pakete für die Docker-Installation:

   ```bash
   sudo apt install apt-transport-https ca-certificates curl software-properties-common
   ```

3. **Docker GPG-Key und Repository hinzufügen:** Füge den Docker-GPG-Schlüssel hinzu und aktiviere das Docker-Repository:

   ```bash
   curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
   ```

4. **Docker installieren:** Aktualisiere die Paketliste und installiere Docker:

   ```bash
   sudo apt update
   sudo apt install docker-ce docker-ce-cli containerd.io
   ```
\

5. **Überprüfung der Docker-Installation:** Verifiziere, dass Docker korrekt installiert wurde, indem du den Status des Docker-Dienstes überprüfst:

   ```bash
   sudo systemctl status docker
   ```

6. **Docker in den Boot-Prozess einbinden:** Damit Docker nach einem Neustart automatisch startet:



### 3.3 Installation von Docker-Compose

1. **Docker-Compose herunterladen:** Lade die neueste Version von Docker-Compose herunter:

   ```bash
   sudo curl -L "https://github.com/docker/compose/releases/download/$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep -Po '(?<=tag_name": "v)[^"]*')" -o /usr/local/bin/docker-compose
   ```

2. **Ausführungsrechte erteilen:** Mache Docker-Compose ausführbar:

   ```bash
   sudo chmod +x /usr/local/bin/docker-compose
   ```

3. **Installation überprüfen:** Überprüfe die Installation, indem du die Version von Docker-Compose abfragst:

   ```bash
   docker-compose --version
   ```

### 3.4 Überprüfung und Absicherung der Docker-Installation

1. **Absicherung der Docker-API:** Die Docker-API sollte standardmäßig nur lokal verfügbar sein. Entferne die Möglichkeit, Docker über das Netzwerk zu steuern, um ungewollten Zugriff zu verhindern.

2. **Nutzung der Docker-Gruppe:** Um Root-Rechte zu vermeiden, füge den Benutzer, der Docker verwenden soll, der Docker-Gruppe hinzu:

   ```bash
   sudo usermod -aG docker $USER
   ```

3. **Docker-Installation testen:** Führe einen Test-Container aus, um zu überprüfen, ob Docker korrekt läuft:

   ```bash
   sudo docker run hello-world
   ```

### 3.5 Sicherheitsoptimierung von Docker-Containern

1. **Vermeidung privilegierter Container:** Vermeide die Nutzung von privilegierten Containern, um das Risiko einer Sicherheitslücke zu verringern. Prüfe stets, welche Rechte ein Container hat, bevor er gestartet wird.

2. **Namespace-Isolation:** Nutze die Namespace-Isolation, um sicherzustellen, dass Container keine direkten Zugriffsrechte auf den Host haben.

3. **Rootless Docker:** Es wird empfohlen, nach Möglichkeit Rootless Docker zu verwenden, um die Sicherheit weiter zu erhöhen. Informationen zur Einrichtung von Rootless Docker findest du in der offiziellen Docker-Dokumentation.

### 3.6 Verknüpfung zu Docker-Dokumentationen und Ressourcen

Für detaillierte Informationen zur Verwaltung von Docker und Docker-Containern kannst du auf die offizielle [Docker-Dokumentation](https://docs.docker.com/) sowie die [Docker-Compose-Dokumentation](https://docs.docker.com/compose/) zugreifen.

\
\
\
\
\

### 3.7 Checkliste für Docker-Installation und Sicherheitsmaßnahmen

- \autocheckbox{} Docker ist erfolgreich installiert und läuft ohne Fehler.
- \autocheckbox{} Docker-Compose wurde erfolgreich heruntergeladen und installiert.
- \autocheckbox{} Die Docker-API ist nur lokal verfügbar.
- \autocheckbox{} Benutzer wurden der Docker-Gruppe hinzugefügt, um Root-Rechte zu vermeiden.
- \autocheckbox{} Sicherheitsoptimierungen wie die Vermeidung privilegierter Container und Ressourceneinschränkungen wurden implementiert.
- \autocheckbox{} Die Docker-Installation wurde mit einem Test-Container überprüft:
  ```bash
  sudo docker run hello-world
  ```

---

## Kapitel 4: Mailcow-Installation und Grundkonfiguration

### 4.1 Download und Initialisierung von Mailcow

**Einführung:**

In diesem Abschnitt wird die Installation von Mailcow auf dem bereits eingerichteten Proxmox-Host beschrieben. Mailcow verwendet Docker-Container, die verschiedene Dienste wie Postfix, Dovecot, Rspamd und MariaDB bereitstellen, um einen voll funktionsfähigen Mailserver zu betreiben.

**Schritt-für-Schritt-Anleitung:**

1. **Download von Mailcow:** Lade das Mailcow-Dockerized-Paket herunter:

   ```bash
   git clone https://github.com/mailcow/mailcow-dockerized
   cd mailcow-dockerized
   ```

2. **Konfiguration generieren:** Erstelle die Konfigurationsdateien für Mailcow:

   ```bash
   ./generate_config.sh
   ```

   **Details:**

   - Du wirst aufgefordert, grundlegende Konfigurationsdaten wie den Hostname und die Domain einzugeben. Beispiel:
     - **FQDN:** mail.xd-cloud.de
     - **IP-Adresse (öffentlich):** 134.255.229.52
     - Wähle aus, ob du IPv6 aktivieren möchtest (dies sollte in deinem Fall geschehen).

3. **Mailcow-Docker-Container starten:** Nach der Generierung der Konfigurationsdateien kannst du die Docker-Container starten:

   ```bash
   docker-compose pull
   docker-compose up -d
   ```

   **Hinweis:**

   Dieser Befehl lädt die neuesten Docker-Images für Mailcow herunter und startet die Container im Hintergrund.

4. **Initialisierung der Weboberfläche:** Nachdem die Container erfolgreich gestartet wurden, ist die Mailcow-Verwaltungsoberfläche über deinen Webbrowser zugänglich:

   - **URL:** [https://mail.xd-cloud.de](https://mail.xd-cloud.de)

\

### 4.2 Konfiguration der mailcow\.conf (inkl. SSL/ACME)

**Einführung:**

Die `mailcow.conf` ist die Hauptkonfigurationsdatei, in der wichtige Einstellungen wie SSL/TLS, Zertifikate und Netzwerkschnittstellen definiert werden. Eine korrekte Konfiguration dieser Datei ist entscheidend für die Sicherheit und Funktionalität des Mailservers.

**Schritt-für-Schritt-Anleitung:**

1. **Bearbeiten der mailcow\.conf:** Öffne die `mailcow.conf` Datei, um Änderungen vorzunehmen:

   ```bash
   nano mailcow.conf
   ```

2. **Wichtige Parameter in der mailcow\.conf:**

   - **HTTP(S)-Ports und SSL-Konfiguration:**

     - Stelle sicher, dass Mailcow ausschließlich über HTTPS läuft.
     - Beispielkonfiguration:
       ```makefile
       HTTP_PORT=80
       HTTPS_PORT=443
       ```

   - **SSL-Zertifikate (ACME/Let's Encrypt):**

     - Mailcow kann SSL-Zertifikate automatisch über Let's Encrypt beziehen. Um dies zu aktivieren, füge in der `mailcow.conf` Folgendes hinzu:
       ```makefile
       USE_SSL=y
       ACME_DOMAIN=mail.xd-cloud.de
       ACME_MAIL=email@xd-cloud.de
       ```

   - **Netzwerkkonfiguration:** Stelle sicher, dass die Netzwerkschnittstellen korrekt konfiguriert sind:

     ```makefile
     MAILCOW_HOSTNAME=mail.xd-cloud.de
     IPV4_ADDRESS=10.3.0.4
     IPV6_ADDRESS=fd03::4
     ```

3. **Zertifikatsautomatisierung:**

   - Falls Let's Encrypt für die automatische Zertifikatsverwaltung aktiviert wurde, wird Mailcow die Zertifikate automatisch erneuern. Dies wird durch die Integration von ACME gehandhabt.
   - **Hinweis:** Die Erneuerung erfolgt regelmäßig und muss nicht manuell ausgeführt werden.

### 4.3 Automatisierung der SSL-Zertifikate mit Let's Encrypt/ACME

**Einführung:**

Die Nutzung von Let's Encrypt für die SSL-Zertifikate bietet den Vorteil, dass die Zertifikate automatisch alle 90 Tage erneuert werden, ohne manuelles Eingreifen. Dies sorgt für eine durchgängige Absicherung der Webschnittstellen von Mailcow.

**Schritt-für-Schritt-Anleitung:**

1. **Prüfen der ACME-Integration:** Mailcow unterstützt die automatische Verwaltung von SSL-Zertifikaten durch Let's Encrypt (ACME). Prüfe, ob die Konfiguration korrekt ist, indem du die `mailcow.conf` wie oben beschrieben überprüfst.

2. **Manuelles Erzwingen der Zertifikatsanforderung:** Falls du die Zertifikate sofort anfordern möchtest, kannst du den folgenden Befehl nutzen:

   ```bash
   docker-compose exec acme-mailcow certbot renew
   ```

3. **Überwachung der Zertifikatsaktualisierungen:** Überprüfe, ob die Zertifikate erfolgreich angefordert wurden:

   - Navigiere zu `/var/lib/acme/` und überprüfe, ob dort ein aktuelles Zertifikat vorhanden ist.
   - Du kannst auch die Weboberfläche von Mailcow besuchen, um sicherzustellen, dass das SSL-Zertifikat korrekt eingerichtet wurde.

### 4.4 Validierung und Test der Mailcow-Installation

**Tests für Mailversand und Empfang:**

1. **Mailversand testen:** Sende eine Testmail von einem externen E-Mail-Provider an die Mailcow-Adresse:

   - **Beispiel:** `test@xd-cloud.de`
   - Überprüfe, ob die E-Mail im Posteingang des Mailcow-Kontos erscheint.

2. **Mailversand von Mailcow aus:** Sende eine E-Mail von deinem Mailcow-Konto an ein externes E-Mail-Konto, um sicherzustellen, dass der Versand korrekt funktioniert.

3. **SSL-Validierung:** Nutze einen SSL-Checker, um zu überprüfen, ob das SSL-Zertifikat korrekt implementiert wurde:

   - Tools wie [ssllabs.com](https://www.ssllabs.com/) oder `sslyze` bieten detaillierte Einblicke in die SSL-Konfiguration.

### 4.5 Fehlerbehebung bei der Mailcow-Installation

**Log-Analyse:**

1. **Docker-Logs überprüfen:** Falls ein Dienst nicht wie erwartet funktioniert, überprüfe die Docker-Logs:

   ```bash
   docker-compose logs
   ```

2. **Mail-Protokolle überprüfen:** Die wichtigsten Logs befinden sich in:

   - `/var/log/mail.log` für Mail-Dienste wie Postfix und Dovecot.
   - `/var/log/nginx/` für die Webschnittstelle.

**Häufige Fehler:**

- **Probleme mit SSL:** Überprüfe die Zertifikate unter `/var/lib/acme/` und stelle sicher, dass sie gültig sind.
- **Mailversand schlägt fehl:** Überprüfe die DNS-Einträge (MX, SPF) und die Protokolle auf Fehlermeldungen.

### 4.6 Checkliste für die Mailcow-Installation

- \autocheckbox{} Mailcow-Docker-Container erfolgreich heruntergeladen und gestartet.
- \autocheckbox{} SSL/ACME-Konfiguration in der `mailcow.conf` korrekt eingerichtet.
- \autocheckbox{} Mailversand und -empfang erfolgreich getestet.
- \autocheckbox{} SSL-Zertifikate erfolgreich validiert und überprüft.
- \autocheckbox{} Docker-Logs überprüft und keine kritischen Fehler gefunden.

### 4.7 Verknüpfung zu Mailcow-Dokumentation und Ressourcen

- [Mailcow-Dokumentation](https://mailcow.github.io/mailcow-dockerized-docs/)
- [Docker-Dokumentation](https://docs.docker.com/)
- [Let's Encrypt/ACME-Dokumentation](https://letsencrypt.org/docs/)

---


## Kapitel 5: DNS-Einrichtung und Sicherheitsprotokolle (SPF, DKIM, DMARC)

### 5.1 DNS-Einrichtung (A-Record, MX, SPF)

Die DNS-Konfiguration ist entscheidend, damit der Mailserver korrekt mit anderen Mailservern kommunizieren kann. In diesem Schritt konfigurieren wir den A-Record, den MX-Record sowie den SPF-Eintrag für deine Domain `mail.xd-cloud.de`.

1. **A-Record (Adresseintrag):**

   - Der A-Record weist der Domain eine IP-Adresse zu, sodass die Domain mit dem Mailserver verbunden wird. Der A-Record sollte auf die öffentliche IP-Adresse des Mailservers zeigen (IPv4: `134.255.229.52` und IPv6: `fd03::1`).

   **Beispiel für einen A-Record:**

   ```yaml
   Name: mail
   Typ: A
   Ziel: 134.255.229.52
   TTL: 3600
   ```

   ```yaml
   Name: mail
   Typ: AAAA
   Ziel: fd03::1
   TTL: 3600
   ```

2. **MX-Record (Mail-Exchange-Eintrag):**

   - Der MX-Record gibt an, welcher Mailserver für die Domain zuständig ist. Für den Server `mail.xd-cloud.de` sollten die MX-Einträge so aussehen:

   ```yaml
   Name: mail.xd-cloud.de
   Typ: MX
   Priorität: 10
   Ziel: mail.xd-cloud.de
   TTL: 3600
   ```

3. **SPF-Eintrag (Sender Policy Framework):**

   - Der SPF-Eintrag dient dazu, Spam zu verhindern, indem er angibt, welche IP-Adressen E-Mails für die Domain versenden dürfen.

   **Beispiel für einen SPF-Eintrag:**

   ```yaml
   Name: mail.xd-cloud.de
   Typ: TXT
   Wert: "v=spf1 a mx ip4:134.255.229.52 -all"
   TTL: 3600
   ```

   - Dies erlaubt dem Server mit der IP-Adresse `134.255.229.52`, E-Mails für `mail.xd-cloud.de` zu versenden.

### 5.2 DKIM-Schlüssel generieren und konfigurieren

DKIM (DomainKeys Identified Mail) stellt sicher, dass E-Mails nicht unterwegs manipuliert wurden. DKIM verwendet einen privaten Schlüssel, um E-Mails digital zu signieren. Der öffentliche Schlüssel wird als TXT-Eintrag im DNS hinterlegt.

1. **DKIM-Schlüssel generieren:**

   - In der Mailcow-Verwaltungsoberfläche unter `Configuration → Mail Setup → DKIM` kannst du den DKIM-Schlüssel für deine Domain generieren. Dies erzeugt einen öffentlichen und einen privaten Schlüssel.

2. **DKIM-Eintrag im DNS hinterlegen:**

   - Du erhältst einen öffentlichen Schlüssel, der als TXT-Eintrag im DNS hinterlegt wird.

   **Beispiel:**

   ```yaml
   Name: dkim._domainkey.mail.xd-cloud.de
   Typ: TXT
   Wert: (DKIM-Schlüssel, der in der Mailcow-Admin-Oberfläche angezeigt wird)
   TTL: 3600
   ```

### 5.3 DMARC-Richtlinie einrichten und testen

DMARC (Domain-based Message Authentication, Reporting & Conformance) fügt eine weitere Schutzschicht hinzu, indem es sicherstellt, dass SPF und DKIM korrekt konfiguriert sind. Es definiert, wie Empfänger E-Mails behandeln sollen, die SPF und DKIM nicht bestehen.

1. **DMARC-Eintrag im DNS hinterlegen:**

   **Beispiel:**

   ```yaml
   Name: _dmarc.mail.xd-cloud.de
   Typ: TXT
   Wert: "v=DMARC1; p=none; rua=mailto:dmarc-reports@mail.xd-cloud.de"
   TTL: 3600
   ```

   - In diesem Beispiel ist die Richtlinie auf `none` gesetzt, um zu überwachen, wie E-Mails mit SPF/DKIM umgehen, ohne sie direkt abzulehnen. Du kannst später die Richtlinie auf `reject` ändern, um nicht authentifizierte E-Mails abzulehnen.

2. **DMARC-Berichte aktivieren:**

   - Stelle sicher, dass die E-Mail-Adresse für DMARC-Berichte regelmäßig überprüft wird.

### 5.4 Validierung der DNS-Einträge mit Tools

Um sicherzustellen, dass die DNS-Einträge korrekt konfiguriert sind, kannst du folgende Tools verwenden:

- **dig (für Linux):**

  ```bash
  dig mx mail.xd-cloud.de
  dig txt mail.xd-cloud.de
  dig dkim._domainkey.mail.xd-cloud.de
  ```

- **Online-Tools:**
  - [MXToolbox](https://mxtoolbox.com/) zur Überprüfung von DNS-Einträgen.
  - [DMARC Analyzer](https://dmarcian.com/) zur Analyse der DMARC-Richtlinien.

### 5.5 Testvalidierung der SPF-, DKIM- und DMARC-Einträge

Um die Konfigurationen zu testen, kannst du Tools wie [mail-tester.com](https://www.mail-tester.com/) oder [MXToolbox](https://mxtoolbox.com/) verwenden. Diese helfen dir, sicherzustellen, dass SPF, DKIM und DMARC korrekt arbeiten:

- **SPF-Test:** Überprüft, ob der Mailserver in der Lage ist, E-Mails zu versenden, die SPF-konform sind.
- **DKIM-Test:** Stellt sicher, dass E-Mails korrekt signiert und nicht unterwegs verändert wurden.
- **DMARC-Test:** Validiert, ob die DMARC-Richtlinie greift und Berichte über abgelehnte E-Mails gesendet werden.

### 5.6 Checkliste für die DNS-Einrichtung und Sicherheitsprotokolle

- A-Record zeigt korrekt auf die IP-Adressen des Mailcow-Servers.
- MX-Record ist richtig konfiguriert und zeigt auf `mail.xd-cloud.de`.
- SPF-Eintrag ist korrekt und erlaubt nur autorisierte IPs.
- DKIM-Schlüssel ist generiert und als DNS-TXT-Eintrag hinterlegt.
- DMARC-Richtlinie ist konfiguriert und auf `none` gesetzt (für Testzwecke).
- Alle DNS-Einträge wurden validiert und korrekt getestet.

### 5.7 Verknüpfung zu Mailcow-Dokumentation und Ressourcen

- [Mailcow-Dokumentation zur DKIM-Konfiguration](https://mailcow.github.io/mailcow-dockerized-docs/)
- [Mailcow-Dokumentation zu DNS](https://mailcow.github.io/mailcow-dockerized-docs/)

---

## Kapitel 6: SSL/TLS-Konfiguration

### 6.1 Einführung in SSL/TLS und Sicherheitsaspekte

SSL (Secure Sockets Layer) und sein Nachfolger TLS (Transport Layer Security) sind wesentliche Protokolle, um die Vertraulichkeit und Integrität der Kommunikation über das Internet zu gewährleisten. Mailserver sollten ausschließlich mit TLS 1.2 oder höher arbeiten, um Sicherheit zu gewährleisten. In diesem Kapitel werden die Grundlagen von SSL/TLS, die Konfiguration für Mailcow und die Integration von Let's Encrypt für automatisierte Zertifikate behandelt.

**Wichtige Sicherheitsaspekte:**

- **TLS 1.2+ verwenden:** Ältere Versionen wie SSLv3, TLS 1.0 und TLS 1.1 sind als unsicher eingestuft und sollten deaktiviert werden.
- **Automatisierte Zertifikatsverwaltung:** Die Nutzung von Let's Encrypt mit dem ACME-Protokoll bietet eine einfache Möglichkeit, SSL-Zertifikate zu erhalten und zu verwalten.
- **Strikte SSL-Überwachung:** Regelmäßige Überprüfung der Zertifikate und ihrer Gültigkeit, um Verfall oder Misskonfiguration zu verhindern.

### 6.2 Let's Encrypt und ACME-Integration in Mailcow

Um SSL-Zertifikate in Mailcow zu nutzen, kann Let's Encrypt mit dem ACME-Protokoll integriert werden. Mailcow bietet eine native Unterstützung, um SSL-Zertifikate automatisch zu verwalten und zu erneuern.

**Schritte zur Einrichtung:**

1. **Konfiguration der mailcow\.conf:** Öffne die Mailcow-Konfigurationsdatei und stelle sicher, dass Let's Encrypt aktiviert ist:

   ```bash
   nano /opt/mailcow-dockerized/mailcow.conf
   ```

   **Füge oder bearbeite die folgenden Zeilen:**

   ```bash
   # Domain für Let's Encrypt SSL-Zertifikate:
   MAILCOW_HOSTNAME=mail.xd-cloud.de

   # Let's Encrypt aktivieren
   SSL_TYPE=letsencrypt

   # E-Mail für Zertifikatserneuerungen
   ACME_MAIL=admin@xd-cloud.de
   ```

2. **ACME-Prozess starten:** Nachdem die Konfiguration angepasst wurde, kann der ACME-Prozess initialisiert werden, um das SSL-Zertifikat von Let's Encrypt zu beziehen:

   ```bash
   docker-compose exec acme-mailcow /acme.sh --issue --standalone -d mail.xd-cloud.de
   ```

3. **Zertifikat automatisch erneuern:** Let's Encrypt Zertifikate haben eine Gültigkeit von 90 Tagen. Mailcow übernimmt die automatische Erneuerung dieser Zertifikate. Du kannst den Status der Zertifikate regelmäßig überprüfen:

   ```bash
   docker-compose exec acme-mailcow /acme.sh --renew-all --force
   ```

4. **SSL/TLS Konfiguration testen:** Überprüfe die Konfiguration mit Tools wie SSL Labs:

   - **[SSL Labs Test](https://www.ssllabs.com/)** für eine vollständige Analyse deiner SSL-Konfiguration.

### 6.3 Anpassung der Postfix- und Dovecot-Konfiguration

Die SSL/TLS-Konfiguration muss auch in den Diensten Postfix (für den SMTP-Server) und Dovecot (für IMAP/POP3) angepasst werden. Standardmäßig sind TLS 1.0 und 1.1 deaktiviert, aber du solltest sicherstellen, dass nur TLS 1.2+ aktiv ist.

**Anpassung der Konfigurationsdatei extra.cf:**

```bash
nano /opt/mailcow-dockerized/data/conf/postfix/extra.cf
```

**TLS 1.2 und 1.3 erzwingen:**

Füge die folgenden Zeilen hinzu:

```bash
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
```

**Starte den Postfix-Dienst neu, damit die Änderungen wirksam werden:**

```bash
docker-compose restart postfix-mailcow
```

**Dovecot sollte ebenfalls sicher konfiguriert werden.** Die TLS-Einstellungen findest du in der Datei `dovecot.conf`:

```bash
nano /opt/mailcow-dockerized/data/conf/dovecot/dovecot.conf
```

**Sicherstellen, dass nur TLS 1.2+ aktiviert ist:**

```bash
ssl_protocols = !SSLv2 !SSLv3 !TLSv1 !TLSv1.1
```

### 6.4 Überprüfung und Validierung der SSL/TLS-Konfiguration

Nach der Konfiguration von SSL/TLS sollten Tests durchgeführt werden, um sicherzustellen, dass die Konfiguration korrekt ist und keine unsicheren Protokolle verwendet werden.

**Test der SSL-Konfiguration:**

1. **OpenSSL-Test für SMTP:**

   ```bash
   openssl s_client -connect mail.xd-cloud.de:25 -starttls smtp
   ```

   Stelle sicher, dass nur TLS 1.2 oder höher verwendet wird.

2. **SSL Labs Test:** Verwende SSL Labs zur externen Überprüfung der SSL/TLS-Konfiguration.

### 6.5 Checkliste zur SSL/TLS-Sicherheit

- Let's Encrypt in Mailcow aktiviert und korrekt konfiguriert.
- SSL-Zertifikate wurden erfolgreich bezogen und getestet.
- Postfix und Dovecot sind korrekt konfiguriert und verwenden nur TLS 1.2+.
- Die SSL-Konfiguration wurde extern überprüft (z.B. SSL Labs Test).
- Automatische Zertifikatsaktualisierung ist aktiviert und funktioniert korrekt.

### 6.6 Erweiterte SSL/TLS-Sicherheitsprotokolle

Für eine erweiterte Sicherheitsüberprüfung können zusätzliche Tools wie `sslyze` verwendet werden. Dieses Tool analysiert die Stärke der SSL-Konfiguration und stellt sicher, dass nur sichere Verschlüsselungsmethoden verwendet werden.

**Installiere sslyze:**

```bash
sudo apt install sslyze
```

**Führe die Überprüfung durch:**

```bash
sslyze --regular mail.xd-cloud.de
```

Überprüfe, ob alle Protokolle und Verschlüsselungsmethoden den modernen Sicherheitsstandards entsprechen.

### 6.7 Verknüpfung zu SSL/TLS-Ressourcen

- [SSL Labs](https://www.ssllabs.com/): Online-Tool zur Überprüfung von SSL/TLS-Konfigurationen.
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/): Detaillierte Dokumentation zu Let's Encrypt und ACME.
- [Postfix TLS Documentation](http://www.postfix.org/TLS_README.html): Offizielle Postfix-Dokumentation zu TLS.
- [Dovecot SSL Configuration](https://doc.dovecot.org/configuration_manual/ssl_configuration/): Offizielle Dovecot-Dokumentation zu SSL/TLS.

## Kapitel 7: Erweiterte Sicherheitsprotokolle: DKIM, DMARC, MTA-STS, DANE

### 7.1 Einführung in die erweiterten Mailprotokolle
E-Mails sind anfällig für verschiedene Bedrohungen, darunter Phishing, Spoofing und Man-in-the-Middle-Angriffe. Um diese Bedrohungen zu minimieren, wurden erweiterte Sicherheitsprotokolle wie DKIM, DMARC, MTA-STS und DANE entwickelt. Diese Protokolle verbessern die Authentifizierung von E-Mails und sorgen dafür, dass E-Mails auf ihrem Weg verschlüsselt und sicher zugestellt werden. In diesem Kapitel werden wir diese Protokolle einrichten und testen.

#### Übersicht der Protokolle
- **DKIM (DomainKeys Identified Mail)**: Stellt sicher, dass E-Mails von autorisierten Servern gesendet werden, indem Nachrichten mit einer digitalen Signatur versehen werden.
- **DMARC (Domain-based Message Authentication, Reporting & Conformance)**: Erweitert SPF und DKIM, um zu verhindern, dass nicht autorisierte E-Mails im Namen Ihrer Domain gesendet werden.
- **MTA-STS (Mail Transfer Agent Strict Transport Security)**: Erzwingt die Verschlüsselung von E-Mails zwischen Mailservern durch TLS.
- **DANE (DNS-based Authentication of Named Entities)**: Ermöglicht die Validierung von TLS-Zertifikaten für SMTP-Verbindungen durch DNSSEC.

### 7.2 DNS-Einträge und Aktivierung von MTA-STS und DANE
Damit diese Protokolle wirksam sind, müssen sie in Ihren DNS-Einträgen hinterlegt und korrekt konfiguriert werden. Die DNS-Einträge für DKIM, DMARC und SPF sollten bereits konfiguriert sein (siehe vorheriges Kapitel). Nun richten wir MTA-STS und DANE ein.

#### MTA-STS Konfiguration
1. **Erstellen eines MTA-STS-Eintrags im DNS**

   Fügen Sie folgende Einträge zu Ihrer Domain hinzu:

   - **Policy-Eintrag (TXT Record):**
     ```
     _mta-sts.mail.xd-cloud.de. IN TXT "v=STSv1; id=20240101000000"
     ```

   - **MTA-STS-Host**: Erstellen Sie einen HTTPS-Endpunkt unter `https://mta-sts.mail.xd-cloud.de/.well-known/mta-sts.txt`, der Ihre MTA-STS-Richtlinie hostet.

     Beispiel für eine MTA-STS-Richtlinie (`mta-sts.txt`):
     ```
     version: STSv1
     mode: enforce
     mx: mail.xd-cloud.de
     max_age: 86400
     ```

2. **Webserver-Konfiguration**
   
   Sie müssen sicherstellen, dass der HTTPS-Server korrekt eingerichtet ist, um die `mta-sts.txt`-Datei bereitzustellen. Verwenden Sie hierzu z. B. Nginx oder Apache mit SSL-Zertifikaten (Let's Encrypt).

#### DANE Konfiguration
**Voraussetzungen:**
- **DNSSEC** muss für Ihre Domain aktiviert sein. Dies ist eine Voraussetzung für die Implementierung von DANE.

1. **TLSA-Eintrag für DANE**

   Erstellen Sie im DNS einen TLSA-Eintrag für Ihren Mailserver. Dieser Eintrag gibt an, welche Zertifikate für TLS-Verbindungen vertrauenswürdig sind.

   Beispiel für einen DANE-Eintrag (TLSA):
   ```
   _25._tcp.mail.xd-cloud.de. IN TLSA 3 1 1 {SHA256_hash_of_certificate}
   ```
   - `3` steht für "PKIX-TA" (Zertifikat basierend auf einem vertrauenswürdigen CA-Stammzertifikat).
   - `1` für die Zertifikatnutzung (im Hash-Format).
   - Der SHA-256-Hash des Zertifikats kann mit folgendem Befehl generiert werden:
     ```
     openssl x509 -noout -fingerprint -sha256 -inform pem -in /path/to/cert.pem
     ```

2. **Überprüfen der DNSSEC- und TLSA-Konfiguration**
   
   Nach der Einrichtung sollten Sie die DNSSEC- und TLSA-Einträge mit Tools wie `dnssec-tools` und `dnsviz.net` überprüfen, um sicherzustellen, dass sie korrekt konfiguriert sind.

### 7.3 Validierung der Sicherheitsprotokolle (SPF, DKIM, DMARC, MTA-STS, DANE)
Nach der Einrichtung der Protokolle ist es wichtig, diese zu validieren und sicherzustellen, dass sie korrekt funktionieren.

1. **SPF, DKIM und DMARC-Validierung**
   - Nutzen Sie Online-Tools wie **MXToolbox** oder **mail-tester.com**, um die Konfiguration Ihrer SPF-, DKIM- und DMARC-Einträge zu überprüfen.
   - **SPF-Test**: Überprüfen Sie, ob nur die autorisierten Mailserver E-Mails versenden dürfen.
   - **DKIM-Test**: Stellen Sie sicher, dass Ihre E-Mails mit einer DKIM-Signatur versehen sind.
   - **DMARC-Berichte**: Analysieren Sie die Rückmeldungen von DMARC-Berichten, um zu sehen, ob unautorisierte E-Mails blockiert werden.

2. **MTA-STS Validierung**
   - Verwenden Sie Tools wie `starttls-everywhere.org`, um sicherzustellen, dass Ihre MTA-STS-Richtlinie korrekt implementiert wurde.

3. **DANE Validierung**
   - Verwenden Sie das Tool `tlsa-check`, um zu überprüfen, ob Ihre TLSA-Einträge und DNSSEC korrekt konfiguriert sind:
     ```
     tlsa-check mail.xd-cloud.de
     ```

### 7.4 Automatisierung der MTA-STS-Konfiguration
Es ist sinnvoll, die MTA-STS-Konfiguration zu automatisieren, insbesondere das regelmäßige Aktualisieren der MTA-STS-Richtlinie und den HTTPS-Zugang.

1. **Automatische Updates der MTA-STS-Datei**
   - Verwenden Sie Cronjobs oder ein Skript, das regelmäßig die MTA-STS-Datei erneuert und auf dem Server bereitstellt. Beispiel für einen Cronjob, der einmal täglich die Richtlinie aktualisiert:
     ```
     0 0 * * * /path/to/update-mta-sts.sh
     ```

2. **Zertifikatserneuerung für MTA-STS**
   - Integrieren Sie Let's Encrypt in Ihren Webserver, um sicherzustellen, dass das Zertifikat für die HTTPS-Verbindung automatisch erneuert wird. Dies sollte bereits durch den ACME-Client von Let's Encrypt (siehe Kapitel 6) abgedeckt sein.

### 7.5 Checkliste für die erweiterten Sicherheitsprotokolle
- **DKIM**: DKIM-Schlüssel wurde generiert und in den DNS-Einträgen hinterlegt.
- **DMARC**: DMARC-Richtlinie ist korrekt konfiguriert und validiert.
- **MTA-STS**: MTA-STS-Richtlinie wurde erstellt und auf dem HTTPS-Endpunkt veröffentlicht.
- **DANE**: TLSA-Einträge sind korrekt konfiguriert und DNSSEC ist aktiviert.
- **Validierung**: Alle Sicherheitsprotokolle wurden erfolgreich mit Tools wie **MXToolbox** und `tlsa-check` überprüft.
- **Automatisierung**: Die MTA-STS-Konfiguration und Zertifikatserneuerung sind automatisiert.

### 7.6 Ressourcen und weiterführende Links
Um das Thema der erweiterten Mailprotokolle zu vertiefen und weiterführende Informationen zu erhalten, sind folgende Links nützlich:

1. **DKIM**
   - [DKIM-Spezifikation](#): Offizielle Spezifikation des DomainKeys Identified Mail-Protokolls.
   - [Mailcow DKIM-Konfiguration](#): Anleitung zur Einrichtung von DKIM in Mailcow.

2. **DMARC**
   - [DMARC-Spezifikation](#): Die Spezifikation von DMARC zur Authentifizierung von E-Mails.
   - [DMARC-Anleitung und Tools](#): Liste von Tools und Ressourcen für DMARC.

3. **MTA-STS**
   - [MTA-STS RFC](#): Die offizielle Spezifikation für MTA-STS.
   - [Let's Encrypt MTA-STS Anleitung](#): Ein nützliches Tutorial zur Integration von MTA-STS in Mailcow.
   - [MTA-STS Validator](#): Tool zur Überprüfung der MTA-STS-Konfiguration.

4. **DANE**
   - [DANE RFC](#): Die Spezifikation von DANE und seine Anwendung für TLS.
   - [DANE-Validator](#): Tool zur Überprüfung der DANE-Implementierung und TLSA-Einträge.

5. **SPF**
   - [SPF-Spezifikation](#): Das SPF-Protokoll zur Überprüfung der autorisierten Mailserver.

6. **Allgemeine E-Mail-Sicherheitsprotokolle**
   - [MXToolbox](#): Ein umfassendes Tool zur Überprüfung von DNS-Einträgen und Sicherheitsprotokollen.
   - [Mailcow Dokumentation - Sicherheit](#): Offizielle Mailcow-Dokumentation zum Thema Sicherheit.

## Kapitel 8: Konfiguration von pfSense für den Mailcow-Server

In diesem Kapitel wird die pfSense-Firewall so konfiguriert, dass sie den Mailcow-Server schützt und den sicheren E-Mail-Verkehr ermöglicht. Dabei werden Firewall-Regeln, NAT und IPv6-Einstellungen behandelt. Außerdem wird die pfSense-Konfiguration mithilfe von Tools wie `tcpdump` überprüft und Logging- sowie Monitoring-Mechanismen eingerichtet.

### 8.1 Einrichtung der Firewall-Regeln für Mail und SSL/TLS-Verbindungen

**Ziel:** Erstellen von Firewall-Regeln, die den ein- und ausgehenden E-Mail-Verkehr (SMTP, IMAP, POP3) sowie SSL/TLS-Verbindungen absichern.

**Schritt-für-Schritt-Anleitung:**

1. **Zugriff auf die pfSense-Oberfläche:**
   - Melde dich in der pfSense-Weboberfläche an.
   - Navigiere zu **Firewall > Rules**.

2. **Erstellung einer Regel für SMTP (Port 25):**
   - Erstelle eine neue Regel für eingehenden Verkehr über Port 25 (SMTP):
     - **Action:** Pass
     - **Interface:** WAN
     - **Protocol:** TCP
     - **Destination Port:** SMTP (25)
     - **Source:** Any
     - **Destination:** IP-Adresse des Mailcow-Servers (z.B. 10.3.0.4)
     - **Description:** "Erlaube eingehenden SMTP-Verkehr für Mailcow"

3. **Regeln für SMTPS (Port 465) und Submission (Port 587):**
   - Erstelle ähnliche Regeln für die Ports 465 (SMTPS) und 587 (Submission), die ebenfalls für den gesicherten Mailversand genutzt werden.

4. **Regeln für IMAP (Port 143) und IMAPS (Port 993):**
   - Füge eine Regel für den Port 143 (IMAP) und eine für 993 (IMAPS) hinzu, um den Zugriff auf Mailboxen über ungesicherte und gesicherte Verbindungen zu ermöglichen.

5. **Regeln für POP3 (Port 110) und POP3S (Port 995):**
   - Erstelle ähnliche Regeln für 110 (POP3) und 995 (POP3S).

6. **Regeln für HTTPS (Port 443) für Webmail und Administration:**
   - Erstelle eine Regel für den eingehenden HTTPS-Verkehr (Port 443) für die Mailcow-Verwaltung und Webmail.

> **Hinweis:** Es ist wichtig, ausgehenden Traffic ebenfalls durch entsprechende Regeln zuzulassen, falls pfSense standardmäßig ausgehende Verbindungen blockiert.

### 8.2 NAT und Portweiterleitung für die Mailcow-VM

**Ziel:** Einrichtung von NAT-Regeln (Network Address Translation), um den E-Mail-Verkehr vom WAN an die interne Mailcow-VM weiterzuleiten.

**Schritt-für-Schritt-Anleitung:**

1. **Navigieren zu NAT-Einstellungen:**
   - Gehe zu **Firewall > NAT > Port Forward**.

2. **Erstellen der NAT-Regeln für die Mail-Ports:**
   - Erstelle eine NAT-Regel für jeden E-Mail-Port (SMTP, SMTPS, Submission, IMAP, IMAPS, POP3, POP3S):
     - **Interface:** WAN
     - **Protocol:** TCP
     - **Destination Port:** Der jeweilige Port (z.B. 25 für SMTP)
     - **Redirect Target IP:** Interne IP-Adresse des Mailcow-Servers (z.B. 10.3.0.4)
     - **Redirect Target Port:** Gleicher Port (z.B. 25 für SMTP)
     - **Description:** "NAT für SMTP-Verkehr an Mailcow"

3. **Regeln für HTTPS und Webmail:**
   - Füge eine Portweiterleitungsregel für Port 443 (HTTPS) hinzu, um den Webmail-Zugang und die Administration zu ermöglichen.

4. **Aktivieren von NAT Reflection:**
   - Stelle sicher, dass NAT Reflection für die Mailcow-VM aktiviert ist, um die Kommunikation auch innerhalb des internen Netzwerks zu ermöglichen.

### 8.3 Konfiguration von IPv6 für Mailcow

**Ziel:** Einrichtung der IPv6-Kommunikation für Mailcow, um den Server über IPv6 erreichbar zu machen.

**Schritt-für-Schritt-Anleitung:**

1. **Erstellen von Firewall-Regeln für IPv6:**
   - Gehe zu **Firewall > Rules** und erstelle eine Regel für IPv6-Verbindungen:
     - **Action:** Pass
     - **Interface:** WAN
     - **Protocol:** TCP
     - **Source:** Any
     - **Destination:** IPv6-Adresse der Mailcow-VM (fd03::4)
     - **Destination Port:** Die entsprechenden Mail-Ports (SMTP, SMTPS, IMAP, POP3, HTTPS)

2. **NAT für IPv6:**
   - Gehe zu **Firewall > NAT > Port Forward** und füge die IPv6-Adressen und -Ports hinzu, die auf die Mailcow-VM weitergeleitet werden sollen.

3. **Überprüfung der IPv6-Konnektivität:**
   - Verwende Tools wie `ping6` oder `traceroute6`, um sicherzustellen, dass die IPv6-Kommunikation zwischen der Mailcow-VM und dem Internet funktioniert.

### 8.4 Validierung der pfSense-Konfiguration

**Ziel:** Sicherstellen, dass die pfSense-Firewall korrekt konfiguriert ist und den Mailverkehr sicher und zuverlässig weiterleitet.

**Schritt-für-Schritt-Anleitung:**

1. **Verwendung von `tcpdump` für die Netzwerküberprüfung:**
   - Auf der pfSense-VM kannst du `tcpdump` nutzen, um den eingehenden und ausgehenden Mail-Verkehr zu überprüfen:
     ```bash
     tcpdump -i WAN interface port 25
     ```

2. **Überprüfung der pfSense-Logs:**
   - Navigiere zu **Status > System Logs** und überprüfe die Firewall-Logs, um sicherzustellen, dass alle relevanten Mail-Ports weitergeleitet werden und keine unerwarteten Verbindungen blockiert werden.

### 8.5 Einrichtung von pfSense-Logging und Monitoring

**Ziel:** Einrichtung von Logging und Monitoring auf pfSense, um potenzielle Probleme und Sicherheitsvorfälle frühzeitig zu erkennen.

**Schritt-für-Schritt-Anleitung:**

1. **Aktivierung von Logging für Firewall-Regeln:**
   - Gehe zu **Firewall > Rules** und aktiviere die Log-Option für jede erstellte Regel, um alle Zugriffe zu protokollieren.

2. **Installation von Monitoring-Tools (z.B. Zabbix, Prometheus):**
   - pfSense kann in Monitoring-Tools wie **Zabbix** oder **Prometheus** integriert werden. Diese Tools ermöglichen die Überwachung des Netzwerkverkehrs und der Systemressourcen in Echtzeit.

### 8.6 Checkliste für die pfSense-Konfiguration

- \autocheckbox{} Alle erforderlichen Firewall-Regeln für SMTP, IMAP, POP3, HTTPS wurden erstellt.
- \autocheckbox{} NAT-Regeln für die Weiterleitung der Mail-Ports an die Mailcow-VM eingerichtet.
- \autocheckbox{} IPv6-Unterstützung aktiviert und getestet.
- \autocheckbox{} Die pfSense-Konfiguration mit `tcpdump` und den pfSense-Logs überprüft.
- \autocheckbox{} Logging und Monitoring eingerichtet, um den Mail-Verkehr zu überwachen.

### 8.7 Verknüpfung zur pfSense-Dokumentation und Ressourcen

- [pfSense Documentation](https://docs.netgate.com/pfsense/en/latest/)
- [CrowdSec Documentation](https://doc.crowdsec.net/)
- [Zabbix Documentation](https://www.zabbix.com/documentation/current/manual)
- [Prometheus Documentation](https://prometheus.io/docs/)

## Kapitel 9: Zusammenfassung der Sicherheitskonfiguration

### 9.1 Gesamtüberblick über alle Sicherheitsmaßnahmen

In diesem Kapitel fassen wir die implementierten Sicherheitsmaßnahmen zusammen, die im gesamten Mailcow-Setup zum Einsatz gekommen sind. Diese Maßnahmen gewährleisten, dass der Server bestmöglich gegen Angriffe abgesichert ist und der E-Mail-Verkehr sicher und zuverlässig funktioniert.

**Hauptsicherheitsmaßnahmen:**

- **TLS 1.2+ und SSL-Zertifikate:** Durch den Einsatz von Let's Encrypt und der korrekten TLS-Konfiguration wird sichergestellt, dass der E-Mail-Verkehr über sichere Verbindungen abgewickelt wird. Veraltete Protokolle wie TLS 1.0 und 1.1 wurden deaktiviert.
- **SPF, DKIM und DMARC:** Diese DNS-basierten Sicherheitsprotokolle verhindern E-Mail-Spoofing und sorgen dafür, dass E-Mails nicht als Spam eingestuft werden.
- **MTA-STS und DANE:** Diese erweiterten Sicherheitsprotokolle sorgen für eine zusätzliche Absicherung des E-Mail-Verkehrs, indem sie erzwingen, dass E-Mails nur über verschlüsselte Verbindungen zugestellt werden.
- **pfSense-Firewall:** Die Firewall sichert den Netzwerkverkehr, indem sie nur autorisierten Datenverkehr zulässt. Durch die korrekt eingerichteten NAT- und Portweiterleitungsregeln sowie die IPv6-Unterstützung bleibt der Mailverkehr sicher und stabil.
- **CrowdSec und Fail2Ban:** Diese Tools schützen den Server vor Brute-Force-Angriffen und böswilligen IP-Adressen, indem sie verdächtigen Verkehr blockieren.
- **Zwei-Faktor-Authentifizierung (2FA):** Durch die Aktivierung von 2FA für die Mailcow-Benutzer wird die Anmeldesicherheit weiter erhöht.
- **Backup-Strategien:** Regelmäßige Backups stellen sicher, dass der Server im Falle eines Ausfalls schnell wiederhergestellt werden kann.

### 9.2 Checkliste zur Sicherheitsprüfung

**TLS und SSL-Konfiguration:**

- \autocheckbox{} TLS 1.2+ ist aktiv, veraltete Protokolle (TLS 1.0 und 1.1) sind deaktiviert.
- \autocheckbox{} SSL-Zertifikate werden durch Let's Encrypt automatisch erneuert.
- \autocheckbox{} Die SSL-Konfiguration wurde mit Tools wie `sslyze` und `openssl s_client` validiert.

**SPF, DKIM, DMARC:**

- \autocheckbox{} SPF ist korrekt im DNS konfiguriert und wird validiert.
- \autocheckbox{} DKIM-Schlüssel wurden generiert und erfolgreich im DNS eingetragen.
- \autocheckbox{} DMARC-Reports werden regelmäßig ausgewertet und die Richtlinie ist korrekt konfiguriert.

**MTA-STS und DANE:**

- \autocheckbox{} MTA-STS ist korrekt eingerichtet und wird durch regelmäßige Tests validiert.
- \autocheckbox{} DANE-Einträge sind korrekt im DNS hinterlegt und validiert.

**pfSense-Firewall:**

- \autocheckbox{} Die Firewall-Regeln für SMTP, IMAP, POP3 und HTTPS sind korrekt konfiguriert.
- \autocheckbox{} NAT- und Portweiterleitungsregeln funktionieren einwandfrei.
- \autocheckbox{} IPv6-Verbindungen wurden getestet und sind stabil.

**CrowdSec und Fail2Ban:**

- \autocheckbox{} CrowdSec schützt den Server gegen verdächtigen Netzwerkverkehr.
- \autocheckbox{} Fail2Ban ist für SSH und andere kritische Dienste aktiv und blockiert Brute-Force-Angriffe.

**2FA und Sicherheitsrichtlinien:**

- \autocheckbox{} Zwei-Faktor-Authentifizierung ist für alle Benutzer aktiviert.
- \autocheckbox{} Starke Passwortrichtlinien sind implementiert und durchgesetzt.

**Backups:**

- \autocheckbox{} Regelmäßige Backups werden durchgeführt und in der Cloud gespeichert.
- \autocheckbox{} Die Wiederherstellungsprozesse wurden erfolgreich getestet.

## Kapitel 10: Best Practices für Backups und Wiederherstellung

### 10.1 Automatisierung von Backups mit Proxmox: Proxmox Backup-Integration

Um den Mailcow-Server zuverlässig zu sichern, ist eine Automatisierung der Backups notwendig. Proxmox bietet eine integrierte Backup-Lösung, die regelmäßig automatisierte Snapshots der VMs erstellt. Die Integration in Proxmox ermöglicht es, vollständige Backups des gesamten Systems zu erstellen und bei Bedarf eine schnelle Wiederherstellung durchzuführen.

**Schritte zur Einrichtung von Proxmox-Backups:**

1. **Backup-Speicher definieren:**
   - Richten Sie in Proxmox einen Backup-Speicher ein, der lokal oder in einer Netzwerkspeicherlösung (NAS, SAN) eingebunden ist.
   - Navigieren Sie zu Datacenter > Storage > Add und wählen Sie das passende Backup-Speicherziel (z.B. NFS oder CIFS).

2. **Backup-Plan konfigurieren:**
   - Gehen Sie zu Datacenter > Backup und fügen Sie einen neuen Backup-Job hinzu.
   - Wählen Sie die Mailcow-VM, den Zeitplan (z.B. tägliche Backups) und den Backup-Typ (vollständig oder differenziell).

3. **Automatisierte Wiederherstellungstests:**
   - Planen Sie regelmäßige Testwiederherstellungen in einer separaten Umgebung, um sicherzustellen, dass die Backups im Notfall funktionieren.

### 10.2 Sichern der Docker-Volumes und Konfigurationen: Backup der Mailcow-Container

Neben der vollständigen Sicherung der Proxmox-VM sollten die Docker-Volumes und die Mailcow-Konfigurationen gesichert werden. Diese Sicherungen erlauben eine gezielte Wiederherstellung einzelner Komponenten, falls nur bestimmte Daten verloren gehen.

**Backup der Docker-Volumes:**

1. **Verwendung von docker-compose:**
   - Mit Docker Compose können die Mailcow-Dienste einfach gestoppt und die Volumes gesichert werden.
   - Führen Sie folgendes aus, um Mailcow-Dienste zu stoppen:
     ```bash
     docker-compose down
     ```

2. **Volumes sichern:**
   - Kopieren Sie die Docker-Volumes und Konfigurationsdateien an einen sicheren Ort.
   - Beispielsweise können Sie die Daten mit rsync auf eine externe Festplatte oder einen Netzwerkspeicher übertragen:
     ```bash
     rsync -av /opt/mailcow-dockerized /backup/mailcow-backup/
     ```

3. **Wiederherstellung der Volumes:**
   - Bei einem Systemausfall können die gesicherten Volumes in die Docker-Umgebung zurückgespielt und der Dienst wieder gestartet werden.

### 10.3 Wiederherstellungsstrategie und Tests

Es reicht nicht aus, nur Backups zu erstellen. Ebenso wichtig ist es, eine funktionierende Wiederherstellungsstrategie zu haben und regelmäßige Tests durchzuführen, um sicherzustellen, dass die Backups wie erwartet funktionieren.

**Best Practices zur Wiederherstellung:**

1. **Regelmäßige Testwiederherstellungen:**
   - Testen Sie mindestens einmal im Quartal die Wiederherstellung Ihrer Daten in einer isolierten Umgebung.
   - Stellen Sie sicher, dass alle Mailcow-Dienste, die Konfigurationen und die Benutzerdaten nach der Wiederherstellung korrekt funktionieren.

2. **Dokumentation der Wiederherstellungsprozesse:**
   - Erstellen Sie eine detaillierte Dokumentation, die den gesamten Wiederherstellungsprozess beschreibt, um im Notfall effizient reagieren zu können.

### 10.4 Speicherung von Backups in der Cloud: Nutzung von Cloud-Backup-Lösungen (S3, B2)

Um zusätzlichen Schutz zu bieten, können Backups in der Cloud gespeichert werden. Cloud-Lösungen wie Amazon S3 oder Backblaze B2 bieten kostengünstigen und skalierbaren Speicher für Backups.

**Schritte zur Cloud-Backup-Einrichtung:**

1. **Installation von rclone:**
   - Installieren Sie rclone, um Verbindungen zu Cloud-Speichern herzustellen:
     ```bash
     sudo apt install rclone
     ```

2. **Verbindung zu Cloud-Diensten konfigurieren:**
   - Konfigurieren Sie rclone mit den Zugangsdaten zu Ihrem Cloud-Speicher (z.B. S3 oder B2).

3. **Automatisierte Backups in die Cloud:**
   - Erstellen Sie ein Skript, das regelmäßig die Docker-Volumes und Konfigurationsdateien in die Cloud synchronisiert:
     ```bash
     rclone sync /backup/mailcow-backup/ remote:mailcow-backups
     ```

4. **Sicherstellung der Cloud-Datensicherheit:**
   - Verschlüsseln Sie die Backups, bevor sie in die Cloud hochgeladen werden, um den Schutz der Daten zu gewährleisten.

### 10.5 Checkliste für Backups und Wiederherstellung

- \autocheckbox{} Proxmox-Backup-Ziel ist konfiguriert und automatisierte Snapshots werden regelmäßig erstellt.
- \autocheckbox{} Docker-Volumes und Mailcow-Konfigurationen werden regelmäßig gesichert.
- \autocheckbox{} Testwiederherstellungen werden regelmäßig durchgeführt.
- \autocheckbox{} Cloud-Backups sind eingerichtet und verschlüsselt.
- \autocheckbox{} Die Wiederherstellungsprozesse sind dokumentiert und überprüft.
- \autocheckbox{} Alle Backup-Ziele sind sicher und redundant.

### 10.6 Verknüpfung zur Dokumentation und Ressourcen

- Proxmox Backup Guide
- Docker Volumes
- rclone Documentation

---

## Kapitel 11: Zwei-Faktor-Authentifizierung (2FA) und erweiterte Sicherheitsmaßnahmen

### 11.1 Aktivierung der 2FA für Mailcow-Benutzer

Die Zwei-Faktor-Authentifizierung (2FA) ist eine zusätzliche Sicherheitsschicht, die über den herkömmlichen Benutzernamen und Passwortschutz hinausgeht. Bei der Aktivierung von 2FA muss der Benutzer zusätzlich einen Einmalcode eingeben, der über eine App wie Google Authenticator oder Authy generiert wird. Die Implementierung in Mailcow läuft wie folgt:

1. **Mailcow Admin Interface öffnen:**
   - Melde dich als Admin im Mailcow-Admin-Dashboard an.

2. **2FA-Einstellungen aktivieren:**
   - Navigiere zu Configuration > User Management.
   - Wähle den gewünschten Benutzer aus und aktiviere 2FA unter Security Settings.

3. **QR-Code für die 2FA-App scannen:**
   - Der Benutzer erhält einen QR-Code, den er mit einer Authentifizierungs-App scannen kann. Dies verbindet das Konto mit der App.

4. **Überprüfung:**
   - Fordere den Benutzer auf, den ersten Einmalcode zur Verifizierung einzugeben, um die 2FA zu aktivieren.

### 11.2 Erstellung und Durchsetzung von Sicherheitsrichtlinien

Mailcow erlaubt die Festlegung von Sicherheitsrichtlinien, um das Benutzerverhalten zu steuern und den Zugang zu sichern:

1. **Passwort-Richtlinien:**
   - Im Mailcow-Admin-Panel kannst du Richtlinien für Passwortstärke und Passwortänderungen festlegen (z.B. Mindestlänge, Sonderzeichen).

2. **Sitzungs-Timeouts und Login-Versuche:**
   - Lege fest, nach wie vielen fehlgeschlagenen Login-Versuchen ein Konto gesperrt wird, sowie nach welchem Zeitraum eine Sitzung automatisch beendet wird.

3. **E-Mail-Benachrichtigungen bei Sicherheitsereignissen:**
   - Aktiviere E-Mail-Benachrichtigungen bei ungewöhnlichen Anmeldeaktivitten oder versuchten Zugriffen.

### 11.3 Integration von externen Authentifizierungsdiensten (z.B. Google Authenticator)

Für Benutzer, die externe Authentifizierungsdienste verwenden möchten, gibt es einfache Möglichkeiten zur Integration von 2FA:

1. **Google Authenticator:**
   - Google Authenticator kann durch das Scannen des QR-Codes direkt integriert werden. Alternativ gibt es Unterstützung für andere TOTP-basierte Dienste wie Authy.

2. **LDAP und SSO (Single Sign-On):**
   - Für größere Organisationen kann auch die Integration von LDAP oder anderen SSO-Diensten sinnvoll sein, um zentrale Benutzerverwaltung und Authentifizierung zu gewährleisten.

### 11.4 Checkliste für 2FA und Sicherheitsmaßnahmen

- \autocheckbox{} 2FA für alle Benutzer aktiviert und getestet.
- \autocheckbox{} Passwort-Richtlinien korrekt konfiguriert.
- \autocheckbox{} Sicherheitsbenachrichtigungen bei ungewöhnlichen Login-Versuchen eingerichtet.
- \autocheckbox{} Externe Authentifizierungsdienste (Google Authenticator, LDAP) konfiguriert und getestet.

### 11.5 Weiterführende Links und Ressourcen

- Mailcow 2FA Dokumentation: Mailcow Documentation -- Security
- Google Authenticator Setup: Google Authenticator
- TOTP (Time-based One-Time Password Algorithm): TOTP RFC 6238
- LDAP und SSO-Integration in Mailcow: Mailcow LDAP/SSO Integration Guide

## Kapitel 12: Monitoring, Protokollanalyse und Fehlerbehebung

### 12.1 Monitoring der Mailcow-Dienste und Proxmox

Eine durchgehende Überwachung der Mailcow-Dienste sowie der Proxmox-VM ist entscheidend für die frühzeitige Erkennung von Problemen und die Optimierung der Serverleistung. Hier sind einige empfohlene Monitoring-Tools und -Strategien:

- **Mailcow Dashboard**: Das native Dashboard von Mailcow bietet grundlegende Informationen über die Auslastung des Systems und den Status der E-Mail-Dienste. Es sollte regelmäßig genutzt werden, um Engpässe und Auffälligkeiten im Mailverkehr zu erkennen.
- **Prometheus**: Ein umfassendes Monitoring- und Alerting-System, das sich hervorragend für die Überwachung von Docker-Containern und Ressourcen eignet. Es sammelt Metriken über CPU-Auslastung, Speichernutzung und Netzwerklatenz.
- **Grafana**: Grafana fungiert als Visualisierungstool, das die von Prometheus gesammelten Daten auf übersichtlichen Dashboards darstellt. Alarmierungen und Benachrichtigungen können basierend auf vordefinierten Schwellenwerten eingerichtet werden.
- **Netdata**: Ein leichtgewichtiges Monitoring-Tool, das in Echtzeit tiefe Einblicke in die System- und Anwendungsleistung gibt. Es ist besonders nützlich für die Überwachung der Proxmox-VM und der Docker-Container.

**Best Practices für Monitoring:**

- Implementiere regelmäßige Berichte und Benachrichtigungen über kritische Systemmetriken wie CPU-Überlastung oder Speicherengpässe.
- Setze Schwellenwerte, bei deren Überschreitung Alarmmeldungen gesendet werden, um schnell auf Probleme reagieren zu können.

### 12.2 Protokollanalyse mit Grafana und Prometheus

Die Protokollanalyse ist ein essenzieller Bestandteil des Monitorings. Grafana und Prometheus bilden das Rückgrat einer modernen Infrastruktur zur Protokollanalyse:

- **Prometheus** speichert Metriken von Mailcow, Docker und Proxmox in einer Zeitreihendatenbank. Alle relevanten Metriken, wie z.B. E-Mail-Statistiken, Fehlerquoten und Speicherverhalten, können gesammelt und analysiert werden.
- **Grafana** bietet benutzerdefinierte Dashboards für eine visuelle Aufbereitung dieser Daten. Dashboards sollten so konfiguriert werden, dass sie Echtzeit-Daten zur Serverauslastung, Anzahl der verschickten E-Mails und Ressourcenverbrauch der Docker-Container anzeigen.

**Best Practices:**

- Richten Sie Dashboard-Ansichten ein, die auf die wichtigsten Dienste fokussiert sind, z.B. separate Dashboards für Docker, Proxmox und Mailcow.
- Füge Alarmierungen hinzu, die bei kritischen Schwellenwerten E-Mail-Benachrichtigungen auslösen.

### 12.3 Fehlerbehebung bei typischen Problemen (Docker, DNS, pfSense)

Fehler können in verschiedenen Bereichen auftreten. Hier sind häufige Probleme und Ansätze zur Lösung:

- **Docker-Probleme:**
  - Prüfe die Logs der Container:
    ```bash
    docker logs <container_name>
    ```
  - Typische Fehler umfassen Netzwerkprobleme, Ressourcenkonflikte und fehlgeschlagene Starts aufgrund von Portkonflikten. Verwende `docker inspect` zur weiteren Fehleranalyse:
    ```bash
    docker inspect <container_name>
    ```

- **DNS-Probleme:**
  - Bei E-Mail-Zustellproblemen sollte der Zustand der DNS-Einträge geprüft werden:
    ```bash
    dig mail.xd-cloud.de MX
    ```
  - Fehlerhafte Einträge in SPF, DKIM oder DMARC können zu einer schlechten E-Mail-Zustellrate führen. Nutze Tools wie MXToolbox oder mail-tester.com, um Fehler zu identifizieren.

- **pfSense-Netzwerkprobleme:**
  - Überprüfe, ob die Firewall-Regeln korrekt konfiguriert sind und ob alle benötigten Ports geöffnet sind (SMTP, IMAP, POP3, HTTPS):
    ```bash
    tcpdump -i eth0 host 10.3.0.1
    ```
  - Prüfe auch, ob die NAT- und Portweiterleitungsregeln in pfSense ordnungsgemäß funktionieren.

### 12.4 Fehlerbehebung bei SSL/TLS und Zertifikaten

SSL/TLS-Fehler können zu Problemen bei der sicheren Kommunikation führen. Hier sind die typischen Ursachen und Lösungen:

- **Zertifikate abgelaufen**: Überprüfe, ob die Zertifikate über Let's Encrypt ordnungsgemäß erneuert werden. Führe manuell eine Erneuerung durch:
  ```bash
  docker-compose exec acme-mailcow renew
  ```

- **Falsche TLS-Versionen**: Mailcow sollte standardmäßig TLS 1.2 und 1.3 nutzen. Überprüfe die eingesetzten Protokolle:
  ```bash
  openssl s_client -connect mail.xd-cloud.de:443
  ```

- **Zertifikatskette unvollständig**: Verifiziere mit `sslyze`, ob alle Zertifikate in der Kette korrekt sind. Fehlende Zwischenzertifikate führen zu SSL-Fehlern bei einigen Clients.

### 12.5 Netzwerkfehler und Troubleshooting bei Docker-Containern

Netzwerkprobleme können zu Verbindungsabbrüchen oder Performanceeinbußen führen. Hier sind einige Ansätze zur Fehlerbehebung:

- **Netzwerkprobleme isolieren**: Verwende `tcpdump` oder Wireshark, um den Netzwerkverkehr zu analysieren:
  ```bash
  tcpdump -i eth0 port 25
  ```
  Dies hilft, blockierte Ports oder fehlerhafte Weiterleitungen zu identifizieren.

- **Docker-Netzwerke überprüfen**: Wenn Docker-Container nicht miteinander kommunizieren können, prüfe die Netzwerkeinstellungen von Docker:
  ```bash
  docker network ls
  ```

- **Performance-Analyse**: Verifiziere, dass die Container ausreichende Ressourcen zugewiesen bekommen haben (CPU, RAM) und keine Engpässe auftreten.

### 12.6 Checkliste für Monitoring und Fehlerbehebung

- \autocheckbox{} Alle relevanten Monitoring-Tools (Prometheus, Grafana, Netdata) sind eingerichtet und überwachen die Dienste.
- \autocheckbox{} Regelmäßige Protokollauswertungen werden durchgeführt.
- \autocheckbox{} Docker-Logs wurden überprüft, und Container-Probleme wurden diagnostiziert und gelöst.
- \autocheckbox{} SSL/TLS-Zertifikate sind aktuell, und TLS 1.2+ wird verwendet.
- \autocheckbox{} Netzwerkverbindungen und DNS-Einträge wurden getestet und validiert.
- \autocheckbox{} Alle Netzwerkprobleme (Docker, pfSense) wurden gelöst, und die Verbindungen sind stabil.

### 12.7 Weiterführende Links und Ressourcen

- [Mailcow-Dokumentation](https://docs.mailcow.email)
- [Prometheus-Dokumentation](https://prometheus.io/docs/)
- [Grafana-Dokumentation](https://grafana.com/docs/)
- [Netdata-Dokumentation](https://learn.netdata.cloud/docs)
- [tcpdump-Dokumentation](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [Wireshark-Dokumentation](https://www.wireshark.org/docs/)
- [MXToolbox](https://mxtoolbox.com/)
- [Mail-Tester](https://www.mail-tester.com/)
- [sslyze-Dokumentation](https://github.com/nabla-c0d3/sslyze)
- [Docker-Dokumentation](https://docs.docker.com/)

## Kapitel 13: Erweiterte Funktionen: Skalierung, Hochverfügbarkeit und Integration

### 13.1 Skalierungsmöglichkeiten für Mailcow und Docker: Horizontal und vertikal skalieren

**Einleitung:**

Skalierung ist eine essenzielle Maßnahme, um die Leistung eines Mailservers wie Mailcow zu verbessern und sicherzustellen, dass er den Anforderungen wachsender Nutzerzahlen gerecht wird. Es gibt zwei Hauptmethoden der Skalierung: **vertikale Skalierung** (Erhöhung der Ressourcen wie CPU und RAM) und **horizontale Skalierung** (Hinzufügen weiterer Server, um die Last zu verteilen).

**Vertikale Skalierung:**

- **CPU und RAM erhöhen**: Passe die Ressourcen der Mailcow-VM an, um mehr Benutzeranfragen zu verarbeiten. Dies ist vor allem bei steigender E-Mail-Aktivität hilfreich.
- **Proxmox** bietet einfache Tools zur Anpassung der Ressourcen von VMs.
- Beispiel: Erhöhen der vCPU von 8 auf 12 oder des Arbeitsspeichers von 16 GB auf 32 GB.
- **Speicher erhöhen**: Erweiterung des Storage-Backends (z.B. NVMe-Disks oder SSDs). Hierbei kann ZFS verwendet werden, um den Speicher dynamisch zu erweitern.

**Horizontale Skalierung:**

- **Docker-Cluster**: Setze mehrere Mailcow-Instanzen in einem Docker-Swarm oder Kubernetes-Cluster auf. Docker-Compose selbst unterstützt keine horizontale Skalierung, aber durch den Einsatz von Docker-Swarm oder Kubernetes können zusätzliche Instanzen zur Lastverteilung genutzt werden.
- **Load-Balancing**: Der Mail-Verkehr kann durch pfSense oder andere Load-Balancer auf mehrere Mailcow-Instanzen verteilt werden.
- **Speicher-Skalierung mit NFS/GlusterFS**: Nutze verteilte Dateisysteme wie NFS oder GlusterFS, um den Speicherbedarf bei mehreren Instanzen zu decken. Dadurch wird der Speicher über mehrere Nodes verteilt und gemeinsam genutzt.

### 13.2 Hochverfügbarkeitsstrategien für Proxmox und Mailcow: Cluster-Setup für HA-Lösungen

**Einleitung:**

Hochverfügbarkeit (HA) ist essenziell, um sicherzustellen, dass der Mailserver auch im Falle eines Hardware- oder Softwarefehlers funktionsfähig bleibt. Proxmox VE bietet native Unterstützung für Hochverfügbarkeits-Cluster.

**Schritt-für-Schritt zur Einrichtung eines Proxmox HA-Clusters:**

1. **Proxmox-Cluster erstellen**: Verbinde mehrere Proxmox-Server zu einem Cluster, sodass VMs bei einem Serverausfall auf einen anderen Server migrieren können.
   ```bash
   pvecm add <IP-Adresse-des-Cluster-Nodes>
   ```

2. **HA-Ressourcen konfigurieren**: Weise der Mailcow-VM eine HA-Policy zu, sodass diese bei einem Serverausfall automatisch neu gestartet wird:
   ```bash
   ha-manager add vm:<VMID> --group <HA-Group>
   ```

3. **Ceph oder ZFS für verteilten Speicher**: Nutze Ceph oder ZFS für eine hochverfügbare, verteilte Speicherlösung. Ceph repliziert die Daten auf mehrere Nodes und gewährleistet so die Datenverfügbarkeit im Falle eines Ausfalls.

**Hochverfügbarkeit für Mailcow:**

- **Datenbank-Replikation**: Nutze MariaDB-Galera für eine Master-Master-Replikation der Datenbank. Dies erlaubt es, Mailcow-Daten auf mehrere Instanzen zu verteilen.
- **Dovecot-Cluster**: Setze Dovecot in einem Cluster mit geteiltem Speicher ein, um die Mail-Postfächer auf mehrere Server zu verteilen.

### 13.3 Integration mit Nextcloud, Rocket.Chat und Mattermost: Erweiterte Kollaborations-Tools

**Nextcloud-Integration:**

- **Nextcloud als Webmail-Client**: Binde Nextcloud ein, um Mail-Services direkt über die Nextcloud-Oberfläche bereitzustellen. Dies kann über die Integration des Nextcloud-Mail-Moduls erfolgen.
- Installiere das Nextcloud-Mail-Plugin und konfiguriere es für die Verbindung mit Mailcow.

**Rocket.Chat:**

- **Rocket.Chat für Team-Kommunikation**: Ermögliche es Benutzern, E-Mails direkt über Rocket.Chat-Kanäle zu empfangen oder zu versenden. Nutze Mailcow als SMTP-Server für Rocket.Chat-Benachrichtigungen und -E-Mail-Verkehr.

**Mattermost:**

- **Mattermost als Alternative zu Rocket.Chat**: Richte Mattermost ein, um eine Slack-ähnliche Kommunikationsplattform zu betreiben. Mailcow kann als Benachrichtigungs- und SMTP-Server genutzt werden.

### 13.4 Integration von Authentifizierungssystemen (SSO, LDAP)

**SSO (Single Sign-On):**

- **Keycloak oder OpenID-Connect**: Integriere Keycloak oder einen anderen SSO-Dienst, um eine einheitliche Authentifizierung zu ermöglichen. Benutzer können sich zentral über SSO bei Mailcow, Nextcloud und anderen Tools anmelden.

**LDAP-Integration:**

- **LDAP für Benutzerverwaltung**: Integriere LDAP (z.B. OpenLDAP) für die zentrale Benutzerverwaltung. Dies erleichtert die Verwaltung von Benutzern über mehrere Dienste hinweg und sorgt für einheitliche Anmeldedaten.
- **Mailcow** unterstützt die native Integration von LDAP:
  ```bash
  docker-compose exec dovecot-mailcow doveadm auth test user@domain.com 'password'
  ```

### 13.5 Checkliste für erweiterte Funktionen und Integration

- \autocheckbox{} Proxmox-Cluster für Hochverfügbarkeit eingerichtet.
- \autocheckbox{} Mailcow-Instanzen für horizontale Skalierung eingerichtet.
- \autocheckbox{} Docker-Cluster (Swarm oder Kubernetes) konfiguriert.
- \autocheckbox{} Integration von Nextcloud, Rocket.Chat oder Mattermost durchgeführt.
- \autocheckbox{} SSO- und LDAP-Integration getestet.
- \autocheckbox{} Hochverfügbarkeit der Mailcow-Datenbank und des Speichers implementiert.

### 13.6 Weiterführende Links und Ressourcen

- [Proxmox VE Cluster-Dokumentation](https://pve.proxmox.com/wiki/Cluster_Manager)
- [Ceph-Integration in Proxmox](https://pve.proxmox.com/wiki/Ce

## Kapitel 14: Sicherheitsupdates und Wartung

Regelmäßige Sicherheitsupdates und die Wartung von Docker, Mailcow und pfSense sind essenziell, um die Sicherheit und Stabilität des Systems zu gewährleisten. In diesem Kapitel konzentrieren wir uns auf die Automatisierung von Updates, die Verwaltung von Backups sowie die Integration von Benachrichtigungen über Sicherheitslücken und Wartungsaufgaben.

### 14.1 Regelmäßige Updates für Docker, Mailcow und pfSense: Automatisierte Update-Prozesse

1. **Mailcow-Updates:**
   - Mailcow-Container sollten regelmäßig aktualisiert werden, um Sicherheitslücken zu schließen und neue Features zu nutzen.
   - Manuelles Update:
     ```bash
     cd /opt/mailcow-dockerized
     sudo ./update.sh
     ```
   - Automatisierte Updates mit Cronjob: Um regelmäßige Updates ohne manuelles Eingreifen durchzuführen, kann ein Cronjob eingerichtet werden:
     ```bash
     crontab -e
     0 3 * * 0 /opt/mailcow-dockerized/update.sh >> /var/log/mailcow_update.log 2>&1
     ```

2. **pfSense-Updates:**
   - pfSense-Updates sollten regelmäßig über die Web-GUI (System > Firmware > Update) oder via CLI durchgeführt werden:
     ```bash
     pfSense-upgrade
     ```
   - Automatische Benachrichtigungen für pfSense-Updates: In den pfSense-Einstellungen können E-Mail-Benachrichtigungen für verfügbare Updates eingerichtet werden: System > Advanced > Notifications.

### 14.2 Automatisierung der Backups und Wartung mit Cronjobs

1. **Automatisierte Backups für Docker-Volumes:**
   - Um sicherzustellen, dass Docker-Volumes und Mailcow-Konfigurationen gesichert sind, können regelmäßige Backups mittels Cronjob eingerichtet werden:
     ```bash
     crontab -e
     0 2 * * * /usr/bin/docker-compose -f /opt/mailcow-dockerized/docker-compose.yml run --rm backup-volumes
     ```
   - Komprimierung der Backups: Um Speicherplatz zu sparen, sollten Backups komprimiert werden:
     ```bash
     tar -czvf mailcow-backup-$(date +\%F).tar.gz /path/to/backup
     ```

2. **Automatisierte pfSense-Backups:**
   - pfSense-Konfigurationsbackups können regelmäßig über SCP oder FTP auf externe Server gespeichert werden.
   - *Diagnostics > Backup/Restore > Backup*: Hier können automatische Backups an externe Ziele eingerichtet werden.
   - Cronjob für pfSense-Backups: Nutze `scp` und `rsync`, um pfSense-Konfigurationen über Cronjobs automatisiert zu sichern.

### 14.3 Einrichtung von Benachrichtigungen über Sicherheitslücken (z.B. CISA, CVE-Datenbanken)

1. **CVE-Benachrichtigungen und Sicherheitslücken:**
   - Melde dich bei Diensten wie CISA oder CVE Details an, um Benachrichtigungen über kritische Sicherheitslücken zu erhalten.
   - Tools wie Lynis können dabei helfen, das System auf bekannte Sicherheitslücken zu überprüfen:
     ```bash
     sudo apt install lynis
     sudo lynis audit system
     ```
   - Automatische Benachrichtigungen: Verwende Tools wie osquery, um Sicherheitslücken zu überwachen:
     ```bash
     sudo apt install osquery
     ```

2. **Benachrichtigungen in pfSense einrichten:**
   - E-Mail-Benachrichtigungen bei System- und Sicherheitsereignissen können in pfSense eingerichtet werden: System > Advanced > Notifications.

### 14.4 Checkliste für Sicherheitsupdates und Wartung

- \autocheckbox{} Mailcow-Updates sind automatisiert und laufen regelmäßig.
- \autocheckbox{} pfSense-Updates sind eingerichtet und werden überwacht.
- \autocheckbox{} Automatisierte Backups für Docker-Volumes und pfSense-Konfigurationen sind eingerichtet.
- \autocheckbox{} Benachrichtigungen für CVE und Sicherheitslücken sind aktiviert.
- \autocheckbox{} E-Mail-Benachrichtigungen in pfSense sind konfiguriert.

---

## Kapitel 15: Datenschutz und DSGVO-Konformität

**Einführung**

Die DSGVO (Datenschutz-Grundverordnung) regelt den Umgang mit personenbezogenen Daten und ist für alle Betreiber von E-Mail-Servern relevant, die mit solchen Daten arbeiten. Dieses Kapitel befasst sich sowohl mit den Anforderungen für private als auch für geschäftliche Betreiber.

### 15.1 Datenschutzkonforme E-Mail-Verarbeitung und -Archivierung

#### 15.1.1 Für Unternehmen und Vereine

- Verarbeitung nach Treu und Glauben: Daten dürfen nur für legitime Zwecke verarbeitet werden. Mehr dazu hier: [Datenschutz-Grundverordnung Art. 5 (Rechtsgrundlagen der Verarbeitung)](https://gdpr-info.eu/art-5-gdpr/).
- Datenminimierung und Speicherbegrenzung: Detaillierte Informationen findest du in Artikel 5 Absatz 1 DSGVO.
- Recht auf Löschung: Siehe [Artikel 17 DSGVO -- Recht auf Vergessenwerden](https://gdpr-info.eu/art-17-gdpr/).

#### 15.1.2 Für private Betreiber

Auch wenn die DSGVO keine explizite Anwendung auf private Betreiber findet, sind Datenschutz und Sicherheit wichtig. Siehe hierzu:

- Empfohlene Verschlüsselungsmethoden: [E-Mail-Verschlüsselung mit PGP und S/MIME (heise.de)](https://www.heise.de/).
- Sicherer E-Mail-Verkehr im privaten Bereich: [Tipps für private E-Mail-Nutzung (Netzpolitik.org)](https://netzpolitik.org/).

### 15.2 Datenaufbewahrungspflichten und Löschfristen

#### 15.2.1 Für Unternehmen und Vereine

- Aufbewahrungspflichten: E-Mails mit geschäftsrelevantem Inhalt müssen archiviert werden. Siehe dazu [Gesetzliche Anforderungen an die E-Mail-Archivierung (Bitkom)](https://www.bitkom.org/).
- Voraussetzungen für die steuerrechtliche Archivierung: GoBD-konforme E-Mail-Archivierung.

#### 15.2.2 Für private Betreiber

Für den privaten Gebrauch gibt es keine gesetzlichen Pflichten zur Aufbewahrung von E-Mails. Trotzdem sind Backups und Datensicherung eine gute Praxis:

- [Datensicherung und Backup-Tipps für Privatanwender (ct.de)](https://www.ct.de/).

### 15.3 Überprüfung und Dokumentation der DSGVO-Konformität

#### 15.3.1 Für Unternehmen und Vereine

- Verarbeitungsverzeichnis: Gemäß Artikel 30 DSGVO muss ein Verzeichnis über die Verarbeitung von personenbezogenen Daten geführt werden. Hierzu findest du hilfreiche Hinweise: [Mustervorlage Verzeichnis der Verarbeitungstätigkeiten (BayLDA)](https://www.lda.bayern.de/).
- Datenschutz-Folgeabschätzung: Siehe [Artikel 35 DSGVO -- Datenschutz-Folgenabschätzung](https://gdpr-info.eu/art-35-gdpr/).

#### 15.3.2 Für private Betreiber

Es besteht keine Pflicht zur Dokumentation, aber du kannst dir Datenschutz-Grundlagen aneignen:

- [Grundlagen des Datenschutzes im privaten Bereich: Netzpolitik.org -- Datenschutz-Tipps](https://netzpolitik.org/).

### 15.4 Checkliste für DSGVO-Konformität

Für Unternehmen und Vereine:

- \autocheckbox{} Rechtliche Vorgaben zur E-Mail-Archivierung: [E-Mail-Archivierung in Unternehmen (DATEV)](https://www.datev.de/).
- \autocheckbox{} Sichere Datenaufbewahrung und Löschprozesse: [Automatisierte Löschung von Daten (bsi.de)](https://www.bsi.bund.de/).

Für private Betreiber:

- \autocheckbox{} Best Practices zur Datensicherung und -löschung: [Private E-Mail-Sicherung (Netzpolitik.org)](https://netzpolitik.org/).

### 15.5 Weiterführende Links und Ressourcen

1. [Offizielle DSGVO-Texte: Europäische Union -- DSGVO (europa.eu)](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
2. [Gesetzliche Vorgaben zur E-Mail-Archivierung: E-Mail-Archivierung für Unternehmen (Bitkom)](https://www.bitkom.org/)
3. [Datenschutz-Folgeabschätzung (DSFA): DSFA-Leitfaden (BayLDA)](https://www.lda.bayern.de/)
4. [Grundlagen des Datenschutzes im Alltag: Netzpolitik.org -- Datenschutz im Alltag](https://netzpolitik.org/)
5. [Backup-Tipps für Privatanwender: Backup-Strategien für private E-Mail-Nutzung (Heise.de)](https://www.heise.de/)

## Kapitel 16: IPv6-Integration und Optimierung

Die Integration und Optimierung von IPv6 für Mailcow bietet moderne Netzwerkkonnektivität und verbessert die Erreichbarkeit deines Mailservers. IPv6 ermöglicht eine größere Anzahl von IP-Adressen und bietet Sicherheitsvorteile durch bessere Unterstützung von IPsec und erweiterte Routing-Techniken. Dieses Kapitel befasst sich mit der Konfiguration und Optimierung von IPv6 für Mailcow und pfSense.

### 16.1 IPv6-Unterstützung in Mailcow aktivieren und testen

**Schritt 1: Sicherstellen, dass IPv6 auf der Mailcow-VM aktiv ist**  
Stelle sicher, dass die Netzwerkkonfiguration der Mailcow-VM die richtige IPv6-Adresse enthält. Verwende dazu den Befehl:

```bash
ip -6 addr show
```
Prüfe, ob die folgende IPv6-Adresse zugewiesen ist:

- **IPv6-Adresse**: fd03::4/48 (wie in der ursprünglichen Netzwerkkonfiguration).

**Schritt 2: Aktivieren von IPv6 in Mailcow**  
Mailcow unterstützt von Haus aus IPv6. Die folgende Konfiguration überprüft und aktiviert die IPv6-Funktionalität für die Mailcow-Dienste. Öffne dazu die Datei `mailcow.conf` und stelle sicher, dass folgende Parameter gesetzt sind:

```bash
USE_IPV6=y
```

**Schritt 3: Test der IPv6-Konnektivität**  
Nachdem IPv6 aktiviert wurde, führe Tests durch, um die Erreichbarkeit über IPv6 zu überprüfen:

- Verwende den folgenden Befehl, um den SMTP-Server über IPv6 zu testen:
  
  ```bash
  telnet fd03::4 25
  ```

- Teste die Erreichbarkeit von HTTPS (Mailcow-Admin-UI):

  ```bash
  curl -6 https://[fd03::4]/
  ```

Hinweis: Ersetze `fd03::4` durch die tatsächliche öffentliche IPv6-Adresse, wenn du den Test von außen durchführst.

### 16.2 Optimierung der IPv6-Konfiguration in pfSense

**Schritt 1: IPv6-Weiterleitung in pfSense aktivieren**  
Stelle sicher, dass pfSense für die IPv6-Weiterleitung konfiguriert ist. Gehe dazu zu **System > Advanced > Networking** und aktiviere die Option:

- **Allow IPv6**: Erlaube IPv6-Pakete über pfSense.

**Schritt 2: Erstellen von IPv6-Firewall-Regeln**  
Erstelle spezifische Firewall-Regeln für die Mailcow-VM, um den IPv6-Verkehr zu steuern. Die wichtigsten Ports für Maildienste (SMTP, IMAP, POP3) müssen freigegeben werden. Beispiel einer Firewall-Regel:

- **Interface**: LAN
- **Source**: any
- **Destination**: IPv6-Adresse der Mailcow-VM (fd03::4)
- **Ports**:
  - SMTP: Port 25
  - IMAP: Port 143
  - HTTPS: Port 443

Erstelle entsprechende Regeln auch für die öffentlichen IPv6-Adressen.

### 16.3 Fehlerbehebung bei IPv6-Konfigurationen

**Schritt 1: Überprüfung der IPv6-Routen**  
Stelle sicher, dass die IPv6-Routen korrekt gesetzt sind. Verwende den folgenden Befehl, um die Routing-Tabelle zu überprüfen:

```bash
ip -6 route
```

**Schritt 2: Firewall-Logs überprüfen**  
Wenn die IPv6-Konnektivität nicht funktioniert, prüfe die pfSense-Firewall-Logs. Gehe zu **Status > System Logs > Firewall** und filtere nach IPv6-Einträgen. Dies hilft, mögliche Blockierungen oder Weiterleitungsprobleme zu identifizieren.

**Schritt 3: DNS-Auflösung für IPv6 testen**  
Stelle sicher, dass die DNS-Einträge für IPv6 (AAAA-Einträge) korrekt gesetzt sind. Verwende den folgenden Befehl, um die DNS-Auflösung zu testen:

```bash
dig AAAA mail.xd-cloud.de
```

Falls keine IPv6-Adressen zurückgegeben werden, überprüfe die DNS-Konfiguration und füge die entsprechenden AAAA-Einträge hinzu.

### 16.4 Checkliste für IPv6-Integration und Optimierung

- \autocheckbox{} IPv6 auf der Mailcow-VM aktiviert (`USE_IPV6=y` in `mailcow.conf`).
- \autocheckbox{} IPv6-Adressen in der Mailcow-VM und pfSense richtig konfiguriert.
- \autocheckbox{} Firewall-Regeln in pfSense für IPv6-Verkehr erstellt.
- \autocheckbox{} IPv6-Konnektivität mit `curl`, `telnet` und `dig` getestet.
- \autocheckbox{} DNS-AAAA-Einträge für IPv6 im DNS-System konfiguriert.
- \autocheckbox{} Firewall-Logs auf Blockierungen von IPv6-Verkehr überprüft.

### 16.5 Weiterführende Links und Ressourcen

- **pfSense IPv6-Dokumentation**: [pfSense IPv6 Support](https://docs.netgate.com/pfsense/en/latest/book/ipv6/index.html)
- **Mailcow IPv6 Support**: [Mailcow Documentation](https://mailcow.github.io/mailcow-dockerized-docs/)
- **IPv6 Best Practices**: [RIPE IPv6 Best Practices](https://www.ripe.net/publications/docs/ripe-690)

---

## Kapitel 17: Logging und Protokollanalyse

### 17.1 Einrichtung von Langzeit-Logging und Audit-Logs
Langzeit-Logging und Audit-Logs sind essenziell, um die Integrität des Systems und die Einhaltung von Vorschriften (z.B. DSGVO) sicherzustellen. Hier sind einige grundlegende Schritte zur Implementierung:

- **Standard-Logging in Mailcow**: Mailcow verwendet Docker, sodass die Logs der Container direkt zugänglich sind. Für eine dauerhafte Aufbewahrung sollten diese Logs in einem zentralen Log-Server gespeichert werden.

  ```bash
  docker logs <container_name> -f
  ```

- **Implementierung von Audit-Logs mit `auditd`**: Installiere und konfiguriere das `auditd`-Tool, um alle sicherheitsrelevanten Aktionen zu protokollieren:

  ```bash
  sudo apt install auditd audispd-plugins
  sudo systemctl enable auditd
  ```

- **Graylog-Integration für Langzeit-Logging**: Graylog ermöglicht das zentrale Sammeln und Analysieren von Logs in großen Infrastrukturen. Installiere den Graylog-Server und konfiguriere Mailcow so, dass die Logs an Graylog gesendet werden:

  ```bash
  echo "*.* @<graylog-server-ip>:514" >> /etc/rsyslog.conf
  sudo systemctl restart rsyslog
  ```

- **ELK-Stack (Elasticsearch, Logstash, Kibana)**: Für größere Setups kann auch der ELK-Stack genutzt werden. Konfiguriere Logstash, um Logs aus Docker-Containern zu sammeln und in Elasticsearch zu speichern.

### 17.2 Protokollarchivierung und langfristige Aufbewahrung
Die Protokollarchivierung sollte DSGVO-konform erfolgen. Es ist wichtig, dass Logs sicher gespeichert und alte Logs gelöscht oder archiviert werden, sobald sie nicht mehr benötigt werden.

- **Logrotation mit `logrotate`**: Konfiguriere `logrotate`, um die Logs regelmäßig zu rotieren und Speicherplatz zu sparen.

  Beispielkonfiguration in `/etc/logrotate.d/mailcow`:

  ```bash
  /var/log/mailcow/*.log {
      daily
      missingok
      rotate 14
      compress
      delaycompress
      notifempty
      create 640 root adm
      sharedscripts
      postrotate
          docker restart mailcow
      endscript
  }
  ```

- **Langzeitaufbewahrung mit Cloud-Speicher** (z.B. Amazon S3, Backblaze B2): Richte Cloud-Speicher als Ziel für die Protokollarchivierung ein. Hier ein Beispiel für die Konfiguration mit `awscli` zur automatischen Speicherung in Amazon S3:

  ```bash
  aws s3 cp /var/log/mailcow/ s3://my-bucket/mailcow-logs/ --recursive
  ```

### 17.3 Automatisierte Überwachung von Protokollen und Alarme
Die Überwachung der Protokolle kann durch Tools wie Prometheus und Grafana erfolgen. Diese Tools überwachen die Mailcow-Dienste und visualisieren Anomalien in der Systemleistung.

- **Prometheus für Docker-Container-Monitoring**: Prometheus kann verwendet werden, um den Zustand der Docker-Container zu überwachen und Alarme bei ungewöhnlichen Aktivitäten auszulösen. Installiere den Prometheus-Docker-Exporter:

  ```bash
  docker run -d -p 9100:9100 prom/node-exporter
  ```

- **Integration von Syslog und Fluentd**: Fluentd kann eingesetzt werden, um Logs aus den Docker-Containern in Echtzeit zu verarbeiten und gezielte Alarme basierend auf Log-Daten zu erstellen.

  Beispiel für die Konfiguration von Fluentd, um Logs an externe Systeme oder Slack zur Überwachung und Alarmierung zu senden:

  ```
  <source>
    @type forward
    port 24224
  </source>

  <match **>
    @type slack
    webhook_url https://hooks.slack.com/services/your/slack/hook
    channel '#logs'
    username 'fluentd'
  </match>
  ```

### 17.4 Checkliste für Logging und Protokollanalyse

- \autocheckbox{} Langzeit-Logs für alle Mailcow-Container eingerichtet und getestet.
- \autocheckbox{} Logrotation mit `logrotate` konfiguriert, um Speicherplatz zu sparen.
- \autocheckbox{} Protokolle werden DSGVO-konform archiviert (Cloud-Backup).
- \autocheckbox{} Prometheus-Monitoring für Docker-Container aktiviert und Alarme konfiguriert.
- \autocheckbox{} Protokollüberwachung und Alarmierung mit Syslog oder Fluentd implementiert.
- \autocheckbox{} Graylog oder ELK-Stack für zentrale Log-Sammlung und Analyse eingerichtet.

### 17.5 Verknüpfung zu Dokumentationen und Ressourcen

- **Graylog-Dokumentation**: [Graylog Docs](https://docs.graylog.org/)
- **ELK-Stack-Dokumentation**: [Elastic Stack](https://www.elastic.co/guide/index.html)
- **Prometheus und Grafana**: [Prometheus Docs](https://prometheus.io/docs/), [Grafana Docs](https://grafana.com/docs/)
- **Fluentd-Dokumentation**: [Fluentd Docs](https://docs.fluentd.org/)

## Kapitel 18: Hochverfügbarkeit und Failover-Strategien

### 18.1 Proxmox-Cluster für Hochverfügbarkeit: Einrichtung eines Proxmox-Clusters

Ein Proxmox-Cluster bietet eine einfache Möglichkeit, mehrere physische Server zu verbinden, um VMs im Falle eines Hardwarefehlers zwischen den Nodes zu migrieren.

**Schritte zur Einrichtung eines Proxmox-Clusters:**

1. **Cluster-Setup:** In Proxmox kannst du mehrere Nodes zu einem Cluster verbinden.
   - Verwende den Befehl, um einen Node hinzuzufügen:
     ```bash
     pvecm create <cluster-name>
     ```
   - Füge weitere Nodes hinzu:
     ```bash
     pvecm add <IP-Adresse-des-Cluster-Nodes>
     ```

2. **Shared Storage:** Um eine Live-Migration und Hochverfügbarkeit zu ermöglichen, ist geteilte Speicher notwendig. Lösungen wie Ceph, NFS, oder ZFS können eingesetzt werden.

3. **HA-Konfiguration:** Weise einer VM eine HA-Ressource zu, sodass diese bei einem Serverausfall automatisch neu gestartet wird:
   ```bash
   ha-manager add vm:<VMID> --group <HA-Group>
   ```

### 18.2 Alternative Hochverfügbarkeitslösungen

**Lösung 1: MariaDB Galera Cluster für Datenbank-HA**

- **Beschreibung:** Für Mailcow bietet ein MariaDB Galera Cluster eine hohe Verfügbarkeit der Datenbank, da es eine Master-Master-Replikation ermöglicht. Jeder Node im Cluster ist ein "Master", wodurch Lese- und Schreiboperationen auf jedem Node durchgeführt werden können.

  **Vorteile:**
  - Keine Single-Point-of-Failure.
  - Daten werden in Echtzeit auf mehrere Nodes repliziert.

  **Nachteile:**
  - Komplexe Einrichtung und Wartung.
  - Erfordert sehr gut synchronisierte Netzwerke.

**Lösung 2: Ceph Distributed Storage**

- **Beschreibung:** Ceph bietet eine verteilte Speicherlösung, die ideal für Hochverfügbarkeit ist. Ceph repliziert Daten über mehrere Nodes und ermöglicht self-healing, wenn ein Node ausfällt.

  **Vorteile:**
  - Hohe Fehlertoleranz.
  - Skalierbar für große Mailcow-Installationen.

  **Nachteile:**
  - Höherer Speicherbedarf durch Replikation.
  - Komplexe Einrichtung und Wartung.

**Lösung 3: DRBD (Distributed Replicated Block Device)**

- **Beschreibung:** DRBD repliziert die Daten einer Partition oder eines ganzen Volumes in Echtzeit auf einen sekundären Node.

  **Vorteile:**
  - Bietet kostengünstige, simple Hochverfügbarkeitslösung.
  - Direkte Replikation auf Blockebene.

  **Nachteile:**
  - Keine echte Cluster-Lösung, da der sekundäre Node als "Standby" agiert.
  - Manuelle Failover-Maßnahmen erforderlich, wenn der primäre Node ausfällt.

### 18.3 Replikation und Synchronisierung von Mail-Daten für Failover

**Option 1: NFS/GlusterFS für Mail-Daten-Storage**

- **Beschreibung:** Für eine schnelle und sichere Synchronisierung von Mail-Daten (z.B. IMAP-Postfächer) kannst du NFS oder GlusterFS verwenden.
  - **NFS:** Relativ einfache Einrichtung, ermöglicht Dateizugriffe von mehreren Servern.
  - **GlusterFS:** Bietet skalierbare, verteilte Dateisysteme mit Redundanz und Fehlertoleranz.

**Option 2: Dovecot-Cluster**

- **Beschreibung:** Dovecot kann in einem Cluster mit geteiltem Storage betrieben werden. Mit einem Dovecot-Cluster können Benutzer auf ihre E-Mails zugreifen, auch wenn ein Node offline geht.
  - **Vorteile:** Erhöht die Ausfallsicherheit des Mailzugriffs.
  - **Nachteile:** Erfordert geteilten Speicher oder eine hochverfügbare Speicherlösung (z.B. Ceph).

### 18.4 Checkliste für Hochverfügbarkeit und Failover

- \autocheckbox{} Proxmox-Cluster ist eingerichtet und getestet.
- \autocheckbox{} Shared Storage für VMs implementiert (Ceph, NFS, etc.).
- \autocheckbox{} MariaDB Galera Cluster für Datenbank-Hochverfügbarkeit konfiguriert.
- \autocheckbox{} Dovecot-Cluster für den Mail-Datenzugriff eingerichtet.
- \autocheckbox{} Ceph oder GlusterFS für Mail-Daten-Synchronisierung konfiguriert.
- \autocheckbox{} Failover-Strategien auf den Nodes getestet und erfolgreich durchgeführt.

### 18.5 Weiterführende Links und Ressourcen

- [Proxmox VE Cluster-Dokumentation](https://pve.proxmox.com/wiki/Cluster_Manager)
- [MariaDB Galera Cluster](https://mariadb.com/kb/en/galera-cluster/)
- [Ceph Distributed Storage](https://docs.ceph.com/en/latest/)
- [DRBD Hochverfügbarkeit](https://www.linbit.com/en/drbd-community/)
- [Dovecot Cluster-Konfiguration](https://doc.dovecot.org/cluster/)

## Kapitel 19: Erweiterte DNS-Sicherheit (DNSSEC, DANE)

### 19.1 Einführung in DNSSEC und seine Vorteile

DNSSEC (Domain Name System Security Extensions) wurde entwickelt, um Sicherheitslücken im traditionellen DNS-Protokoll zu schließen, das ursprünglich nicht für Authentifizierung und Datenintegrität konzipiert war. Mit DNSSEC können DNS-Daten durch digitale Signaturen abgesichert werden, die von einem Zertifizierungsweg validiert werden, der bis zur Root-Zone des DNS zurückreicht.

**Vorteile von DNSSEC:**

- **Schutz vor DNS-Spoofing und Cache Poisoning:** DNSSEC sorgt dafür, dass Angreifer keine gefälschten DNS-Antworten in den DNS-Cache eines Servers einschleusen können.
- **Integrität von DNS-Daten:** DNSSEC stellt sicher, dass die DNS-Antworten auf Anfragen korrekt und unverändert sind. Dies verhindert, dass Benutzer auf gefälschte Server umgeleitet werden.
- **Verbesserte Authentifizierung:** DNSSEC bestätigt, dass die Antworten auf DNS-Anfragen tatsächlich von der autorisierten Quelle stammen.

### 19.2 Aktivierung und Konfiguration von DNSSEC und DANE

**DNSSEC-Aktivierung:**

1. **Überprüfung des DNS-Providers:**
   - Zunächst musst du sicherstellen, dass der DNS-Provider oder Registrar, bei dem deine Domain registriert ist, DNSSEC unterstützt. Viele moderne Provider bieten DNSSEC-Management an, aber es ist wichtig, dies zu überprüfen.
   - **Beispiel von Providern, die DNSSEC unterstützen:** Cloudflare, Google Domains, GoDaddy.

2. **Einrichtung der DNSSEC-Signierung:**
   - DNSSEC arbeitet mit zwei Schlüsselpaaren: dem Zone Signing Key (ZSK) und dem Key Signing Key (KSK). Der ZSK signiert die DNS-Daten innerhalb der Zone, während der KSK verwendet wird, um den ZSK zu signieren. Der KSK wird wiederum von der übergeordneten DNS-Zone (z.B. TLD-Zone wie ".com") signiert.
   - **Beispiel für die Zone-Signierung:**
     ```bash
     dnssec-keygen -a RSASHA256 -b 2048 -n ZONE example.com
     dnssec-signzone -A -3 <random> -N INCREMENT -o example.com -t example.com.zone
     ```

3. **Delegation Signer (DS) Record einrichten:**
   - Sobald die Zone signiert ist, muss ein DS-Record beim Registrar erstellt werden, der den öffentlichen Schlüssel der signierten Zone enthält. Dies verknüpft die DNSSEC-Signaturen mit der übergeordneten Zone (z.B. ".com").
   - **Ein DS-Record sieht etwa so aus:**
     ```bash
     example.com. 3600 IN DS <key-tag> <alg> <digest-type> <digest>
     ```

4. **Überprüfung der DNSSEC-Implementierung:**
   - Verwende Tools wie `dig` oder Online-DNSSEC-Checker, um sicherzustellen, dass DNSSEC korrekt eingerichtet ist.
   - **Beispiel:**
     ```bash
     dig +dnssec example.com
     ```

**DANE (DNS-based Authentication of Named Entities):**

DANE fügt eine zusätzliche Sicherheitsstufe hinzu, indem es erlaubt, TLS-Zertifikate über DNS zu veröffentlichen und deren Echtheit zu prüfen. Dies schützt vor Man-in-the-Middle-Angriffen und gefälschten Zertifikaten, die von kompromittierten Zertifizierungsstellen (CAs) ausgestellt werden könnten.

1. **Einführung von TLSA-Records:**
   - Ein TLSA-Record wird erstellt, um anzugeben, welches Zertifikat ein Client beim Verbindungsaufbau erwarten soll. Diese Records werden im DNS gespeichert und durch DNSSEC abgesichert.
   - **Arten von TLSA-Records:**
     - `3 0 1`: Bedeutet, dass der Client das Zertifikat des Servers überprüfen soll, ohne den CA-Pfad zu nutzen. Es wird ein Hash des Zertifikats angegeben.

2. **Erstellen eines TLSA-Records:**
   - Für einen Mailserver auf Port 25 (SMTP über TLS) würde der TLSA-Record so aussehen:
     ```bash
     _25._tcp.mail.xd-cloud.de. IN TLSA 3 0 1 <SHA256-Digest-des-Zertifikats>
     ```
   - Dies gibt an, dass der Client das im Record angegebene Zertifikat validieren soll und nur dann eine Verbindung aufbauen darf, wenn das Zertifikat dem Hash entspricht.

3. **Validierung von DANE:**
   - Teste die DANE-Konfiguration mit Tools wie `daneverify` oder Online-Validatoren.
   - **Beispiel:**
     ```bash
     daneverify mail.xd-cloud.de 25
     ```

**Sicherheitsvorteile durch DANE:**

- **DANE verhindert das Vertrauen auf CAs allein,** da es den Zertifikatspfad durch DNSSEC absichert.
- **Selbst wenn eine CA kompromittiert wird,** können Angreifer keine gefälschten Zertifikate verwenden, da der Client das TLSA-Record überprüft.

### 19.3 Checkliste für erweiterte DNS-Sicherheit

- \autocheckbox{} DNSSEC bei deinem Domain-Registrar aktiviert und konfiguriert.
- \autocheckbox{} DS-Records beim Registrar hinterlegt.
- \autocheckbox{} DNS-Zonen erfolgreich signiert und getestet.
- \autocheckbox{} DANE durch die Konfiguration von TLSA-Records implementiert.
- \autocheckbox{} Tests zur Validierung der DNSSEC- und DANE-Konfiguration durchgeführt (z.B. mit `dnssec-debugger` und `daneverify`).
- \autocheckbox{} Regelmäßige Überprüfung der Schlüsselrotation und -signatur in DNSSEC implementiert.

### 19.4 Weiterführende Links und Ressourcen

- **DNSSEC Ressourcen:**
  - [ICANN DNSSEC-Informationen](https://www.icann.org/dnssec)
  - [DNSSEC-Debugging-Tool](https://dnssec-debugger.verisignlabs.com/)
  - [DNSSEC Key Generation Tool](https://tools.ietf.org/html/rfc6781)
- **DANE Ressourcen:**
  - [IETF RFC 6698 (DANE Standard)](https://tools.ietf.org/html/rfc6698)
  - [DANE Test-Tools](https://www.huque.com/bin/danecheck)
  - [DANE Validator](https://www.dnssec-tools.org/test/dane/)

## Kapitel 20: Leistungstest und Optimierung

#### 20.1 Durchführung von Lasttests für Mailcow: Lasttests und Optimierungen

**Einleitung:**  
Lasttests sind entscheidend, um sicherzustellen, dass der Mailcow-Server auch unter hoher Belastung zuverlässig arbeitet. In diesem Abschnitt geht es darum, wie Lasttests auf der Mailcow-Instanz durchgeführt und optimiert werden können, um die Serverleistung zu maximieren.

**Schritte zur Durchführung von Lasttests:**

1. **Vorbereitung:**  
   Bevor du einen Lasttest durchführst, solltest du sicherstellen, dass die Systemressourcen (CPU, RAM, Netzwerk) überwacht werden. Tools wie `htop`, `iftop` oder das Proxmox Monitoring Panel sind nützlich, um die Ressourcen in Echtzeit zu beobachten.

2. **Test mit smtp-source:**  
   Nutze das Tool `smtp-source` (Teil von Postfix), um Massen-E-Mails an den Mailcow-Server zu senden und die Serverreaktionen zu messen:
   
   ```bash
   smtp-source -s 100 -l 1000 -c 50 -f from@example.com -t to@example.com <mailcow-ip>
   ```
   
   - `-s 100`: Sendet 100 Nachrichten.
   - `-l 1000`: Jede Nachricht hat eine Größe von 1000 Bytes.
   - `-c 50`: Öffnet 50 Verbindungen gleichzeitig.

3. **Test für IMAP/POP3-Last:**  
   Du kannst Tools wie `imaptest` oder `pop3test` verwenden, um den Zugriff und die Leistung der Mail-Clients zu simulieren. Diese Tools simulieren viele gleichzeitige Verbindungen und Abrufe von E-Mails.

4. **Auswertung:**  
   Überwache die CPU-Auslastung, RAM-Nutzung und Netzwerklast während des Tests. Nutze Tools wie Grafana in Kombination mit Prometheus, um die Daten aufzuzeichnen und Engpässe zu identifizieren.

#### 20.2 Docker-Ressourcenoptimierung und Feinabstimmung

**Einleitung:**  
Die Docker-Container für Mailcow können so konfiguriert werden, dass sie Ressourcen effizient nutzen und die Performance optimieren. Hier geht es darum, wie CPU- und RAM-Limits in den Docker-Compose-Dateien gesetzt werden, um die Serverlast optimal zu verteilen.

**Optimierungsschritte:**

1. **CPU- und RAM-Limits setzen:**  
   Öffne die `docker-compose.yml`-Datei und setze die Ressourcenlimits für die Container:

   ```yaml
   services:
     postfix-mailcow:
       mem_limit: 512m
       cpus: "0.5"
     dovecot-mailcow:
       mem_limit: 1024m
       cpus: "1.0"
   ```

   - `mem_limit`: Begrenze den Arbeitsspeicherverbrauch des Containers.
   - `cpus`: Begrenze die Anzahl der CPU-Kerne, die der Container verwenden darf.

2. **Performance durch Caching optimieren:**  
   Konfiguriere Redis und Memcached, um das Caching für Mailcow zu optimieren. Dies reduziert die Lese- und Schreibvorgänge auf der Festplatte.

#### 20.3 Optimierung der Netzwerkressourcen für Mail-Server: Netzwerkoptimierung

**Einleitung:**  
Netzwerkoptimierung ist entscheidend, um die Antwortzeit und die Durchsatzleistung des Mailcow-Servers zu maximieren, insbesondere bei hohem Mail-Verkehrsaufkommen.

**Schritte zur Optimierung:**

1. **Anpassung der TCP-Puffergrößen:**  
   Passe die TCP-Puffergrößen auf dem Server an, um die Netzwerklatenz und den Datendurchsatz zu optimieren. Dies geschieht durch Anpassen der `sysctl`-Parameter:

   ```bash
   sudo sysctl -w net.core.rmem_max=26214400
   sudo sysctl -w net.core.wmem_max=26214400
   sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 6291456"
   sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 6291456"
   ```

2. **Aktivierung von tcp_fastopen:**  
   TCP Fast Open reduziert die Latenz beim Aufbau von TCP-Verbindungen:

   ```bash
   echo 3 | sudo tee /proc/sys/net/ipv4/tcp_fastopen
   ```

3. **Optimierung von SMTP- und IMAP-Verbindungen:**  
   Stelle sicher, dass Postfix und Dovecot so konfiguriert sind, dass sie mehrere gleichzeitige Verbindungen handhaben können:

   ```bash
   smtpd_client_connection_count_limit = 100
   smtpd_client_message_rate_limit = 50
   ```

#### 20.4 Checkliste für Leistungstests und Optimierung

- \autocheckbox{} Lasttests für SMTP, IMAP und POP3 erfolgreich durchgeführt.  
- \autocheckbox{} Docker-Container mit CPU- und RAM-Limits konfiguriert.  
- \autocheckbox{} Redis und Memcached für optimiertes Caching eingerichtet.  
- \autocheckbox{} Netzwerkressourcen durch `sysctl` und TCP-Einstellungen optimiert.  
- \autocheckbox{} Optimierung der Verbindungen und Limits für Postfix und Dovecot durchgeführt.

#### 20.5 Verknüpfung zu weiterführenden Ressourcen und Dokumentation

- [Docker-Optimierung: Docker Performance Best Practices](#)
- [Postfix-Tuning: Postfix Performance Tuning](#)
- [TCP Fast Open: Linux TCP Fast Open](#)
- [Prometheus & Grafana Monitoring: Prometheus Documentation](#)

## Kapitel 21: Automatisierung der Aufgaben mit Cronjobs

### 21.1 Geplante Aufgaben für regelmäßige Wartung und Backups

**Einleitung:**  
Automatisierte Aufgaben über Cronjobs sind eine effiziente Methode, um regelmäßige Wartungsaufgaben wie Backups, Updates und Systemprüfungen durchzuführen. In diesem Kapitel wird beschrieben, wie du Cronjobs für deinen Mailcow-Server und die Docker-Container einrichtest, um die regelmäßige Wartung sicherzustellen.

**Schritte zur Einrichtung:**

1. **Backups automatisieren:**  
   Richte einen Cronjob ein, um regelmäßige Backups der Docker-Volumes zu erstellen. Ein täglicher Backup-Job könnte folgendermaßen aussehen:

   ```bash
   0 2 * * * /usr/bin/docker-compose exec -T mysql-mailcow mysqldump --all-databases -u root -p'PASSWORT' > /backup/mailcow_$(date +%F).sql
   ```
   
   Dieser Befehl sichert die MySQL-Datenbank von Mailcow täglich um 2:00 Uhr.

2. **Automatische Docker-Updates:**  
   Automatisiere das Update der Docker-Container, um sicherzustellen, dass Mailcow immer auf dem neuesten Stand ist:

   ```bash
   0 4 * * 0 /usr/bin/docker-compose pull && /usr/bin/docker-compose up -d
   ```
   
   Dieser Cronjob wird wöchentlich ausgeführt, um alle Docker-Container zu aktualisieren.

3. **Log-Rotation und Protokollpflege:**  
   Stelle sicher, dass die Logdateien regelmäßig rotiert werden, um Speicherplatz zu sparen:

   ```bash
   /etc/logrotate.d/docker-container-logs
   ```
   
   Passe die Rotation der Logs so an, dass sie z.B. wöchentlich rotiert und nach einem Monat gelöscht werden.

### 21.2 Automatisierung von Prüf- und Validierungsaufgaben

1. **SSL-Zertifikate überprüfen:**  
   Richte einen Cronjob ein, um regelmäßig die Gültigkeit der SSL-Zertifikate zu prüfen und bei Bedarf zu erneuern:

   ```bash
   0 3 * * * /usr/bin/docker-compose exec -T acme-mailcow acme.sh --cron --home /acme.sh
   ```

2. **Überprüfung der Mailprotokolle (SPF, DKIM, DMARC):**  
   Nutze `cron` zur regelmäßigen Validierung der SPF-, DKIM- und DMARC-Einstellungen:

   ```bash
   0 5 * * 0 /usr/bin/dig TXT mail.xd-cloud.de | grep 'v=spf1'
   ```

### 21.3 Checkliste für Automatisierung der Aufgaben

- \autocheckbox{} Tägliche Backups für Mailcow konfiguriert.  
- \autocheckbox{} Wöchentliche Docker-Container-Updates automatisiert.  
- \autocheckbox{} Log-Rotation eingerichtet, um die Größe der Protokolldateien zu kontrollieren.  
- \autocheckbox{} Automatische SSL-Erneuerung mittels ACME/Cronjob eingerichtet.  
- \autocheckbox{} Automatisierte Validierung von SPF, DKIM und DMARC-Einstellungen konfiguriert.

### 21.4 Weiterführende Links und Ressourcen

- [Cronjob-Dokumentation: Cron How-To](#)
- [Logrotate-Dokumentation: Logrotate Manual](#)
- [Docker Maintenance: Docker Maintenance Best Practices](#)

## Kapitel 22: Protokollarchivierung und Langzeitprotokollierung 

### 22.1 Langfristige Protokollarchivierung

Die langfristige Protokollarchivierung sorgt dafür, dass Logs sicher aufbewahrt und jederzeit zugänglich sind. Dies ist nicht nur für Fehlerbehebung und Sicherheitsanalysen wichtig, sondern auch für rechtliche Anforderungen, die z.B. durch die DSGVO auferlegt werden können.

**Tools und Plattformen zur Langzeit-Archivierung:**

1. **Graylog**: Ein leistungsstarkes Tool für das zentrale Management und die Langzeitaufbewahrung von Logs. Graylog bietet erweiterte Such- und Filterfunktionen und kann Logs von Mailcow, Docker und pfSense verarbeiten. Die Logs werden zentral gespeichert und können komprimiert und archiviert werden.
   - **Vorteile**: Schnelle Abfragen, anpassbare Dashboards, erweiterte Suchmöglichkeiten.
   - **Anbindung**: Du kannst Mailcow und pfSense so konfigurieren, dass sie ihre Logs an Graylog senden, das zentral alle Logs aufzeichnet und speichert.

2. **ELK Stack (Elasticsearch, Logstash, Kibana)**: Der ELK Stack ist ein weiteres gängiges Log-Management-Tool, das es dir ermöglicht, Logs zentral zu speichern, zu durchsuchen und zu analysieren. Die Logs werden mit Logstash gesammelt, in Elasticsearch gespeichert und mit Kibana visualisiert.
   - **Vorteile**: Anpassbare Dashboards, hohe Skalierbarkeit und eine flexible Architektur für die Langzeitaufbewahrung.
   - **Nutzung**: pfSense und Mailcow können so konfiguriert werden, dass sie ihre Logs über Syslog an Logstash weiterleiten.

3. **Splunk**: Ein umfassendes Tool zur Log- und Sicherheitsüberwachung, das speziell für größere Unternehmen mit umfangreichen Protokollierungsanforderungen entwickelt wurde. Splunk bietet integrierte Funktionen zur Protokollierung, Langzeitarchivierung und Analyse.
   - **Vorteile**: Echtzeit-Analyse, maschinelles Lernen für Anomalie-Erkennung, leistungsstarke Dashboards.
   - **Kosten**: Splunk ist kostenpflichtig, aber es gibt eine kostenlose Version für kleinere Projekte.

4. **Logrotate**: Für eine einfache und ressourcenschonende Lösung kann Logrotate verwendet werden, um Logs zu komprimieren, zu rotieren und archivieren. Es ist in den meisten Linux-Distributionen integriert und lässt sich leicht anpassen.
   - **Anwendung**: Zum Beispiel für die Mailcow-Container und deren Logs. Logrotate kann so konfiguriert werden, dass ältere Logs automatisch in einem Backup-Verzeichnis gespeichert und archiviert werden.

   Beispielkonfiguration in `/etc/logrotate.conf`:
   
   ```bash
   /var/log/mailcow/*.log {
       daily
       missingok
       rotate 12
       compress
       delaycompress
       notifempty
       create 0640 root adm
       sharedscripts
       postrotate
           systemctl reload mailcow
       endscript
   }
   ```

5. **Cloud-Speicherlösungen**:
   - **Amazon S3**: Amazon S3 bietet skalierbaren Speicher für die Archivierung von Protokollen. Die S3-Speicherklassen wie Glacier sind besonders günstig für langfristige Speicherung und eignen sich ideal für Protokolldaten, auf die nur selten zugegriffen wird.
   - **Backblaze B2**: Eine kostengünstige Alternative zu S3, die sich ebenfalls für die langfristige Archivierung von Logs eignet.
   - **Google Cloud Storage**: Bietet ähnliche Archivierungsfunktionen wie S3, aber mit Google-Diensten integriert.

   Ein Beispiel für die automatisierte Protokollarchivierung in die Cloud könnte wie folgt aussehen:

   - **S3 CLI**: Mit dem S3-CLI-Befehl kannst du Protokolle direkt auf einem S3-Bucket sichern:

   ```bash
   aws s3 cp /var/log/mailcow/ s3://my-log-backup-bucket/ --recursive
   ```

### 22.2 Strategie für Daten- und Protokollaufbewahrung (erweitert)

Die Strategie zur Protokollaufbewahrung sollte Folgendes berücksichtigen:

1. **Rechtliche Anforderungen für Unternehmen**:
   - Die DSGVO erfordert, dass personenbezogene Daten sicher gespeichert und gelöscht werden, sobald sie nicht mehr benötigt werden. In der Praxis bedeutet das für Protokolle, dass sie anonymisiert oder gelöscht werden müssen, wenn sie keine betrieblichen Zwecke mehr erfüllen.
   - **Aufbewahrungsfristen**: Für Geschäfts-E-Mails und sicherheitsrelevante Protokolle sind Aufbewahrungsfristen von bis zu 10 Jahren vorgeschrieben (z.B. im Rahmen des Handelsgesetzbuches oder der Abgabenordnung in Deutschland).

2. **Sicherheits- und Datenschutzanforderungen für Privatpersonen**:
   - Für private Betreiber von Mailservern gelten weniger strikte Aufbewahrungsrichtlinien. Die Protokollaufbewahrung sollte jedoch den Prinzipien der Datensparsamkeit folgen: Es sollten nur die unbedingt notwendigen Logs gespeichert werden, und die Aufbewahrung sollte so kurz wie möglich gehalten werden.

3. **Datenschutzkonforme Archivierung**:
   - Nutze verschlüsselte Archive für die Langzeitaufbewahrung von Logs, insbesondere bei der Speicherung in Cloud-Diensten.
   - Anonymisiere Protokolle oder maskiere personenbezogene Daten, wenn diese nicht mehr benötigt werden, um DSGVO-konform zu sein.

### 22.3 Checkliste für Protokollarchivierung und Langzeitaufbewahrung

- \autocheckbox{} Zentrales Log-Management mit Graylog, ELK Stack oder Splunk ist eingerichtet.  
- \autocheckbox{} Log-Retention-Policies für kurzfristige und langfristige Archivierung sind festgelegt.  
- \autocheckbox{} Automatisierte Logrotation und Archivierung ist implementiert (z.B. mit Logrotate).  
- \autocheckbox{} Cloud-Backups (S3, B2) sind für die Langzeitaufbewahrung aktiviert.  
- \autocheckbox{} Rechtliche Aufbewahrungsfristen sind berücksichtigt (DSGVO, HGB, etc.).  
- \autocheckbox{} Logs werden verschlüsselt gespeichert und sind vor unbefugtem Zugriff geschützt.  
- \autocheckbox{} Langzeitprotokollierung für Audits und Sicherheitsüberprüfungen ist aktiv.

### 22.4 Weiterführende Links und Ressourcen

- [Graylog Dokumentation](#)
- [ELK Stack Dokumentation](#)
- [Logrotate Dokumentation](#)
- [AWS S3 Speicherklassen](#)
- [Backblaze B2 Cloud Storage](#)
- [Splunk Dokumentation](#)

## Kapitel 23: Vorfallreaktionsplan und Sicherheitsrichtlinien

### 23.1 Erstellung eines Vorfallreaktionsplans: Aufbau eines Sicherheitsvorfallsplans

Ein Vorfallreaktionsplan ist eine unverzichtbare Komponente jeder IT-Infrastruktur, um bei Sicherheitsvorfällen strukturiert und effizient zu reagieren. Dieser Abschnitt befasst sich mit der Erstellung eines umfassenden Plans zur Erkennung, Analyse, Eindämmung und Behebung von Sicherheitsvorfällen. Der Plan muss die Eskalationsstufen, Meldepflichten sowie die Dokumentation des Vorfalls abdecken.

#### **23.1.1 Kategorisierung von Vorfällen**

- **Niedrige Priorität**: Fehlgeschlagene Login-Versuche, ungewöhnliche Zugriffsversuche oder falsch konfigurierte Systeme. Diese Vorfälle erfordern Beobachtung und regelmäßige Überprüfung, müssen aber nicht sofort behandelt werden.
- **Mittlere Priorität**: Verdächtige Aktivitäten, wie beispielsweise ungewöhnlich viele fehlgeschlagene Anmeldeversuche oder Zugriffe auf sensible Daten. Diese erfordern sofortige Analyse und potenziell eine Systemanpassung.
- **Hohe Priorität**: Schwere Sicherheitsvorfälle wie Datenexfiltration, Malware-Befall oder DDoS-Angriffe. Diese erfordern sofortige Eskalation und Notfallmaßnahmen zur Eindämmung.

#### **23.1.2 Eskalationsstufen**

- **Stufe 1: Lokale Reaktion**  
  Lokale IT-Administratoren überwachen die Systeme und reagieren sofort auf Vorfälle niedriger Priorität. Alle Vorfälle werden protokolliert und bewertet.

- **Stufe 2: Eskalation an das Sicherheitsmanagement**  
  Sicherheitsvorfälle mittlerer und hoher Priorität werden an das IT-Sicherheitsmanagement eskaliert. Es wird eine sofortige Reaktion eingeleitet, die oft eine Zusammenarbeit mit externen Sicherheitspartnern erfordert.

- **Stufe 3: Externe Einbindung und Notfallplan**  
  Bei schwerwiegenden Vorfällen, die den Fortbestand des Unternehmens gefährden (z.B. Datenverlust oder kompromittierte Systeme), werden externe Spezialisten (z.B. CERT, Incident Response Teams) hinzugezogen.

#### **23.1.3 Reaktionszeiten und Service Level Agreements (SLAs)**

- **Niedrige Priorität**: Beobachtung und Analyse innerhalb von 24 Stunden.
- **Mittlere Priorität**: Reaktion und Analyse innerhalb von 4 Stunden.
- **Hohe Priorität**: Sofortige Reaktion und Eskalation innerhalb von 15 Minuten.

#### **23.1.4 Technische Unterstützung für Vorfallserkennung**

- **Automatisierte Erkennung**: Setze Tools wie Wazuh oder Suricata ein, um Sicherheitsvorfälle automatisch zu erkennen. Diese Tools analysieren Netzwerkverkehr und Logs auf verdächtige Aktivitäten.
- **SIEM-Lösungen**: Implementiere eine SIEM-Lösung wie Splunk oder Elastic SIEM, um Log-Daten zu sammeln und sicherheitsrelevante Ereignisse in Echtzeit zu analysieren.

### 23.2 Sicherheitsrichtlinien für den E-Mail-Betrieb

Sicherheitsrichtlinien sind für den E-Mail-Betrieb unerlässlich, um sicherzustellen, dass vertrauliche Informationen geschützt und gesetzliche Anforderungen eingehalten werden. Diese Richtlinien sollten regelmäßig überprüft und aktualisiert werden.

#### **23.2.1 Richtlinien zur E-Mail-Nutzung**

- **Verschlüsselung**: Alle E-Mails mit sensiblen Daten müssen mit TLS gesendet werden. Zudem sollte bei besonders vertraulichen Informationen die Ende-zu-Ende-Verschlüsselung (z.B. mit PGP) vorgeschrieben sein.
- **Zugriffskontrollen**: Nur autorisierte Benutzer haben Zugriff auf E-Mail-Dienste. Der Zugriff sollte durch Zwei-Faktor-Authentifizierung (2FA) abgesichert werden.
- **E-Mail-Weiterleitungen**: Weiterleitungen zu externen, nicht verwalteten E-Mail-Adressen sind zu verhindern, um Datenlecks zu vermeiden.

#### **23.2.2 E-Mail-Sicherheitsmaßnahmen**

- **Phishing-Prävention**: Regelmäßige Schulungen und simulierte Phishing-Angriffe, um die Sensibilität der Mitarbeiter gegenüber Phishing-Versuchen zu erhöhen. Tools wie PhishMe oder GoPhish können dabei unterstützen.
- **E-Mail-Filterung**: Aktivierung von Spam- und Virenfiltern durch Tools wie Rspamd, um potenziell gefährliche E-Mails zu blockieren, bevor sie den Empfänger erreichen.

#### **23.2.3 Spezifische Regeln für den Umgang mit vertraulichen Informationen**

- **Vertrauliche Kommunikation**: Einführung von strikten Richtlinien für den Umgang mit sensiblen Daten in E-Mails. Vertrauliche Informationen (z.B. Kundendaten) dürfen nur in verschlüsselter Form übermittelt werden.
- **Datenlöschung**: Definiere, wie lange E-Mails gespeichert werden und wann sie sicher gelöscht werden müssen, um der DSGVO zu entsprechen.

### 23.3 Checkliste für Vorfallreaktionsplan und Sicherheitsrichtlinien

- \autocheckbox{} Reaktionszeiten für Vorfälle festgelegt und dokumentiert.  
- \autocheckbox{} Eskalationsstufen klar definiert und kommuniziert.  
- \autocheckbox{} Sicherheitsüberwachungs-Tools wie Wazuh oder Suricata implementiert.  
- \autocheckbox{} SIEM-System für zentrale Log-Analyse eingerichtet.  
- \autocheckbox{} Verschlüsselungsrichtlinien für E-Mails festgelegt und durchgesetzt.  
- \autocheckbox{} Phishing-Schulungen und simulierte Angriffe regelmäßig durchgeführt.  
- \autocheckbox{} Spam- und Virenfilter konfiguriert und regelmäßig überprüft.  
- \autocheckbox{} Richtlinien zur Weiterleitung und Speicherung von E-Mails implementiert.  
- \autocheckbox{} Datenschutzrichtlinien für vertrauliche Daten in E-Mails durchgesetzt.

### 23.4 Integration mit externen Sicherheitspartnern

In Fällen, in denen die eigenen Ressourcen nicht ausreichen, sollte der Vorfallreaktionsplan die Einbindung externer Sicherheitspartner vorsehen. Dies kann notwendig sein bei:

- **Komplexen Angriffen**: Einsatz von CERT-Teams (Computer Emergency Response Team) zur Unterstützung bei der Analyse und Behebung schwerer Angriffe.
- **Datenpannen**: Bei einem größeren Datenleck muss ein externes Incident Response Team hinzugezogen werden, um die Angriffsvektoren schnell zu identifizieren und eine rechtzeitige Meldung bei der Datenschutzbehörde sicherzustellen

## Kapitel 24: E-Mail-Verschlüsselung mit S/MIME und PGP

### 24.1 Einführung in E-Mail-Verschlüsselung
S/MIME und PGP sind zwei gängige Standards zur Verschlüsselung von E-Mails und zur Sicherstellung der Authentizität und Vertraulichkeit der Kommunikation. Beide Technologien verwenden asymmetrische Verschlüsselung, bei der ein öffentlicher und ein privater Schlüssel verwendet werden.

- **S/MIME (Secure/Multipurpose Internet Mail Extensions)**: Nutzt Zertifikate, um E-Mails zu signieren und zu verschlüsseln.
- **PGP (Pretty Good Privacy)**: Setzt auf ein dezentrales Vertrauen und verwendet Schlüsselpaare für die Verschlüsselung und Signatur von E-Mails.

### 24.2 Voraussetzungen für S/MIME

- Ein gültiges S/MIME-Zertifikat für jeden Benutzer, der verschlüsselte E-Mails senden und empfangen möchte. Diese Zertifikate können über Zertifizierungsstellen (CA) erworben oder in einigen Fällen auch selbst erstellt werden.
- Mailclients, die S/MIME-Unterstützung bieten, z.B. Outlook, Thunderbird oder Apple Mail.

### 24.3 S/MIME in Mailcow konfigurieren

**Schritt 1: Zertifikate beschaffen**
- Für jeden Benutzer, der S/MIME verwenden soll, muss ein Zertifikat beantragt und installiert werden. Dieses Zertifikat wird auf dem Mailclient des Benutzers installiert.

**Schritt 2: Zertifikate im Mailclient installieren**
1. **Outlook**:
   - Gehe zu den E-Mail-Einstellungen.
   - Wähle den Tab Sicherheit aus und klicke auf "S/MIME-Zertifikat installieren".
   - Wähle das Zertifikat aus und füge es für die Verschlüsselung und Signatur ein.
2. **Thunderbird**:
   - Gehe zu den Kontoeinstellungen und öffne den Abschnitt S/MIME.
   - Importiere das Zertifikat und wähle es als Standardzertifikat für die Verschlüsselung und Signatur aus.

**Schritt 3: Verwendung von S/MIME**
- Nachdem die Zertifikate installiert sind, kannst du beim Verfassen einer E-Mail auswählen, ob die Nachricht verschlüsselt oder signiert werden soll.
- Empfänger müssen ebenfalls ein S/MIME-Zertifikat haben, um verschlüsselte Nachrichten zu lesen.

### 24.4 Voraussetzungen für PGP

- PGP-Schlüsselpaare müssen für jeden Benutzer erstellt werden. Tools wie GnuPG oder PGP Desktop können verwendet werden.
- Öffentliche Schlüssel müssen mit den Kommunikationspartnern ausgetauscht werden.

### 24.5 PGP in Mailcow konfigurieren

**Schritt 1: Erstellung von PGP-Schlüsselpaaren**
1. Installiere GnuPG (falls nicht bereits vorhanden):

   ```bash
   sudo apt install gnupg
   ```

2. Erstelle ein neues Schüsselpaar:

   ```bash
   gpg --gen-key
   ```
   Folge den Anweisungen, um deinen Namen, deine E-Mail-Adresse und ein Passwort einzugeben.

**Schritt 2: Öffentliche Schlüssel exportieren und verteilen**
- Exportiere deinen öffentlichen Schlüssel und sende ihn an deine E-Mail-Kontakte, damit sie deine verschlüsselten Nachrichten lesen können:

  ```bash
  gpg --export -a 'dein Name' > publickey.asc
  ```

**Schritt 3: Import von öffentlichen Schlüsseln**
- Importiere den öffentlichen Schlüssel eines Kontakts, um verschlüsselte Nachrichten an ihn zu senden:

  ```bash
  gpg --import publickey.asc
  ```

**Schritt 4: Signieren und Verschlüsseln von E-Mails**
1. In Thunderbird kannst du das Add-on Enigmail installieren, um PGP-Schlüsselpaare zu verwalten und E-Mails zu verschlüsseln.
2. In der Mailcow-Weboberfläche musst du sicherstellen, dass die E-Mail-Clients korrekt konfiguriert sind, um verschlüsselte E-Mails zu senden.

### 24.6 Validierung und Test der S/MIME- und PGP-Konfiguration
- Sende eine Test-E-Mail mit einer Signatur, um zu überprüfen, ob der Empfänger die Signatur validieren kann.
- Verschlüssle eine E-Mail und stelle sicher, dass der Empfänger den Inhalt entschlüsseln kann.

### 24.7 Best Practices für E-Mail-Verschlüsselung
- Vertraue nur zertifizierten Absendern: Importiere nur S/MIME- oder PGP-Zertifikate von vertrauenswürdigen Quellen.
- Zertifikate regelmäßig erneuern: Stelle sicher, dass S/MIME-Zertifikate vor Ablauf erneuert werden.
- Schlüssel sicher aufbewahren: Private Schlüssel sollten niemals an Dritte weitergegeben werden.

### 24.8 Checkliste für S/MIME und PGP

- \autocheckbox{} S/MIME-Zertifikate erfolgreich installiert und konfiguriert.
- \autocheckbox{} PGP-Schlüsselpaare erstellt und mit den entsprechenden Kontakten ausgetauscht.
- \autocheckbox{} Verschlüsselte E-Mails gesendet und empfangen.
- \autocheckbox{} Test-E-Mails zur Validierung der Signaturen durchgeführt.

### 24.9 Verknüpfung zu Ressourcen und Dokumentationen
- **S/MIME-Dokumentation**: Link zur S/MIME-Dokumentation
- **PGP-Dokumentation**: Link zur PGP-Dokumentation
- **Thunderbird Enigmail**: [Enigmail-Dokumentation](https://www.enigmail.net)
- **GnuPG**: [GnuPG Documentation](https://www.gnupg.org/documentation)

---

## Kapitel 25: Schlusswort

### **25.1 Zusammenfassung der wichtigsten Punkte**
In dieser umfassenden Dokumentation wurden alle relevanten Aspekte zur Installation, Konfiguration und Absicherung eines Mailcow-Servers auf Proxmox VE unter Nutzung von pfSense behandelt. Die einzelnen Kapitel haben detailliert erklärt, wie die wichtigsten Sicherheitsprotokolle wie SPF, DKIM, DMARC, MTA-STS und DANE korrekt eingerichtet und wie der Mailserver gegen potenzielle Bedrohungen abgesichert wird.
Zusätzlich haben wir uns intensiv mit der Implementierung von Hochverfügbarkeit, Skalierung, IPv6-Unterstützung und Monitoring auseinandergesetzt, um sicherzustellen, dass der Server nicht nur sicher, sondern auch performant und zukunftssicher läuft. Besonders die Integration von Datenschutz und DSGVO-Konformität war ein essenzieller Teil, um sicherzustellen, dass die E-Mail-Kommunikation rechtskonform ist.

### **25.2 Ausblick auf zukünftige Erweiterungen**
Die E-Mail-Infrastruktur ist ständig wechselnden Anforderungen ausgesetzt, sei es durch wachsende Nutzerzahlen oder neue Bedrohungen. Zukünftige Erweiterungen könnten den Einsatz von Zero Trust Architecture umfassen, um das Sicherheitsniveau weiter zu erhöhen. Ebenso könnte die Integration zusätzlicher Kollaborationsplattformen wie Microsoft Teams oder Slack eine Rolle spielen. Die Entwicklung neuer Verschlüsselungstechnologien und die fortlaufende Verbesserung von Quarantäne- und Anti-Phishing-Maßnahmen sind ebenfalls Bereiche, in denen weitere Optimierungen sinnvoll sind.

### **25.3 Abschluss-Checkliste**

- \autocheckbox{} Alle DNS-Einträge (SPF, DKIM, DMARC) korrekt eingerichtet und validiert.
- \autocheckbox{} Let's Encrypt SSL-Zertifikate erfolgreich integriert und automatisiert.
- \autocheckbox{} Mailcow-Instanz getestet und betriebsbereit.
- \autocheckbox{} Sicherheitsrichtlinien und Vorfallreaktionsplan dokumentiert und implementiert.
- \autocheckbox{} IPv6-Unterstützung vollständig integriert und getestet.
- \autocheckbox{} pfSense-Firewall-Regeln und NAT-Weiterleitungen korrekt eingerichtet.
- \autocheckbox{} Monitoring, Protokollanalyse und Backup-Strategien implementiert und getestet.
- \autocheckbox{} Hochverfügbarkeits- und Failover-Strategien einsatzbereit.
- \autocheckbox{} DSGVO-Konformität gewährleistet und dokumentiert.