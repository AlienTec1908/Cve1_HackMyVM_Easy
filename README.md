# HackMyVM - Quick .5

![Quick5.png](Quick5.png)

Ein detaillierter Bericht über die Kompromittierung der HackMyVM-Maschine "Quick .5". Dieser Bericht dokumentiert den gesamten Prozess von der initialen Erkundung bis zur Erlangung von Root-Rechten.

---

### **Maschinen-Details**

| Kategorie | Information |
| :--- | :--- |
| **Name** | Quick .5 |
| **Plattform** | HackMyVM |
| **Autor** | DarkSpirit |
| **Schwierigkeit** | Easy |
| **Veröffentlichungsdatum** | 05. Juni 2025 |
| **Link zur VM** | [https://hackmyvm.eu/machines/machine.php?vm=Quick5](https://hackmyvm.eu/machines/machine.php?vm=Quick5) |
| **Mein Walkthrough** | [https://alientec1908.github.io/Quick5_HackMyVM_Easy/](https://alientec1908.github.io/Quick5_HackMyVM_Easy/) |

---

### **Benötigte Fähigkeiten**

*   **Netzwerk-Scanning:** `nmap`, `arp-scan`
*   **Web-Enumeration & vHost Discovery:** `gobuster`, `nikto`, `wfuzz`
*   **Client-Side Exploitation & Social Engineering**
*   **Erstellung bösartiger ODT-Dateien mit Makros** (LibreOffice)
*   **Post-Exploitation Enumeration**
*   **Firefox-Profil-Exfiltration und Passwort-Extraktion** (`firefox_decrypt`)
*   **Privilege Escalation durch Passwort-Wiederverwendung**

---

### **Zusammenfassung des Lösungswegs**

Der Weg zur Kompromittierung dieser Maschine war ein mehrstufiger Prozess, der von der Web-Enumeration über einen kreativen Client-Side-Exploit bis hin zur Ausnutzung schwacher Passwortpraktiken führte.

1.  **Initiale Erkundung:**
    Ein `nmap`-Scan offenbarte einen Webserver auf Port 80. Die grundlegende Web-Enumeration zeigte aktive Verzeichnisauflistungen, aber keine direkten Schwachstellen.

2.  **vHost Discovery & Angriffsvektor:**
    Der entscheidende Schritt in der Enumeration war das vHost-Bruteforcing mit `wfuzz`. Dies deckte mehrere Subdomains auf, darunter `careers.quick.hmv`. Diese Seite enthielt eine Funktion zum Hochladen von Bewerbungsunterlagen, die auf `.odt`- und `.pdf`-Dateien beschränkt war.

3.  **Initialer Zugriff (ODT-Makro-Angriff):**
    Der Angriffsplan bestand darin, eine `.odt`-Datei mit einem bösartigen Makro zu erstellen. Mittels LibreOffice wurde ein Basic-Makro geschrieben, das beim Öffnen des Dokuments eine Reverse Shell auslöst. Diese präparierte "Bewerbungsdatei" wurde hochgeladen. Nachdem ein (simulierter) Mitarbeiter das Dokument öffnete, wurde erfolgreich eine Shell mit den Rechten des Benutzers `andrew` etabliert.

4.  **Privilege Escalation (Passwort-Wiederverwendung):**
    *   **Enumeration:** Im Home-Verzeichnis von `andrew` wurde ein Firefox-Profil gefunden.
    *   **Exfiltration:** Das gesamte Profil wurde über `tar` und `netcat` auf die Angreifer-Maschine übertragen.
    *   **Entschlüsselung:** Mit dem Tool `firefox_decrypt.py` wurden die im Browser gespeicherten Anmeldeinformationen aus dem Profil extrahiert. Dies enthüllte das Passwort `SuperSecretPassword` für das Mitarbeiterportal.
    *   **Root-Zugriff:** In einem klassischen Fall von Passwort-Wiederverwendung wurde dieses Passwort erfolgreich für den `root`-Account über `su` verwendet. Dies gewährte vollständige Kontrolle über das System.
