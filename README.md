# HackMyVM - Cve1

![Cve1.png](Cve1.png)

Ein detaillierter Bericht über die Kompromittierung der HackMyVM-Maschine "Cve1". Dieser Bericht dokumentiert den gesamten Prozess von der initialen Erkundung bis zur Erlangung von Root-Rechten durch die Ausnutzung mehrerer bekannter Schwachstellen (CVEs).

---

### **Maschinen-Details**

| Kategorie | Information |
| :--- | :--- |
| **Name** | Cve1 |
| **Plattform** | HackMyVM |
| **Autor** | *[DarkSpirit]* |
| **Schwierigkeit** | Easy |
| **Veröffentlichungsdatum** | 05. Juni 2025 |
| **Link zur VM** | *[(https://hackmyvm.eu/machines/machine.php?vm=cve1)]* |
| **Mein Walkthrough** | *[(https://alientec1908.github.io/Cve1_HackMyVM_Easy/)]* |

---

### **Benötigte Fähigkeiten**

*   **Netzwerk-Scanning:** `nmap`, `arp-scan`
*   **Web-Enumeration:** `gobuster`, `feroxbuster`
*   **Ausnutzung von Deserialisierungs-Schwachstellen:** Insbesondere unsichere YAML-Verarbeitung (CVE-2022-24707).
*   **Ausnutzung von Cron-Job-Fehlkonfigurationen**.
*   **Ausnutzung von Command Injection in Dateinamen** (CVE-2022-1292).
*   **Privilege Escalation durch unsichere `sudo`-Regeln**.
*   **Verständnis der Linux-Systemadministration** (insb. `/etc/passwd`).

---

### **Zusammenfassung des Lösungswegs**

Die Kompromittierung dieser Maschine war ein schrittweiser Prozess, der die Verkettung von drei separaten Schwachstellen erforderte, um vom initialen Zugriff bis zu Root-Rechten zu gelangen.

1.  **Initialer Zugriff (RCE via YAML Deserialization - CVE-2022-24707):**
    Ein `nmap`-Scan offenbarte einen Webserver auf Port 9090, auf dem eine Anwendung lief, die im Quellcode als **PyTorch Lightning 1.5.9** identifiziert wurde. Diese Version ist anfällig für eine Remote Code Execution durch unsichere YAML-Deserialisierung (CVE-2022-24707). Durch das Hochladen einer speziell präparierten `file.yaml` mit einem Reverse-Shell-Payload konnte ein initialer Zugriff als Benutzer `www-data` erlangt werden.

2.  **Lateral Movement (www-data → wicca via CVE-2022-1292):**
    Die Enumeration als `www-data` deckte einen Cron-Job auf, der minütlich als Benutzer `wicca` den Befehl `c_rehash` im Verzeichnis `/etc/ssl/certs/` ausführte. Die auf dem System installierte OpenSSL-Version war anfällig für CVE-2022-1292. Durch das Erstellen einer Datei mit einem bösartigen Namen, der einen per Backticks eingebetteten `netcat`-Befehl enthielt, wurde beim nächsten Ausführen des Cron-Jobs eine Command Injection ausgelöst. Dies führte zu einer neuen Shell mit den Rechten des Benutzers `wicca`.

3.  **Privilege Escalation (wicca → root via Sudo-Misconfiguration):**
    Eine Überprüfung der `sudo`-Rechte für `wicca` mit `sudo -l` ergab, dass der Befehl `/usr/bin/tee` ohne Passwort als `root` ausgeführt werden durfte. Diese Fehlkonfiguration wurde ausgenutzt, um die Datei `/etc/passwd` zu überschreiben. Dabei wurde der Passwort-Hash für den `root`-Benutzer entfernt. Anschließend konnte mit `su -` ohne Passwort zur `root`-Shell gewechselt werden, was die vollständige Kompromittierung der Maschine bedeutete.
