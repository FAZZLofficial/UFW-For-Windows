<p align="center">
  <img src="logo.jpg" alt="UFW for Windows Server" width="220" />
</p>

# UFW for Windows Server (2019, 2022, 2025)

Emuliert das vertraute Linux **UFW (Uncomplicated Firewall)** Tool nahtlos unter **Windows Server** mithilfe der nativen Windows Defender Firewall Cmdlets.

---

## 🚀 Installation & Deinstallation

### Installation
1. Lade die neueste `UFW-Windows-Setup-vX.X.X.exe` aus den [GitHub Releases](../../releases) herunter.
2. Führe den Installer als Administrator aus.
3. Der Installer kopiert UFW nach `C:\Program Files\UFW-Windows` und trägt es automatisch in den systemweiten `PATH` ein.
4. Anschließend kann sofort in **jeder beliebigen CMD oder PowerShell** der Befehl `ufw` ausgeführt werden.

> **Unattended / Silent Install (für Server):**  
> `UFW-Windows-Setup-v2.0.0.exe /VERYSILENT /NORESTART`

### Deinstallation
- Über die Windows **Systemsteuerung** bzw. **Einstellungen -> Apps & Features (Installierte Apps)** -> `UFW for Windows Server` auswählen und auf **Deinstallieren** klicken.
- Der Uninstaller entfernt das Verzeichnis, säubert die PATH-Variable und fragt nach, ob zuvor angelegte Firewall-Regeln behalten oder gelöscht werden sollen.

---

## 🛠 Features & Syntax

### 1. Ports freigeben oder sperren
```powershell
# Port auf TCP & UDP öffnen
ufw allow 25565

# Explizit TCP oder UDP
ufw allow 80/tcp
ufw deny 445/tcp

# Port-Bereiche
ufw allow 7000:7010/udp
```

### 2. Bekannte Service-Namen (Aliase)
Unterstützt geläufige Protokolle direkt beim Namen:
```powershell
ufw allow ssh       # Port 22/tcp
ufw allow rdp       # Port 3389/tcp
ufw allow http      # Port 80/tcp
ufw allow https     # Port 443/tcp
ufw allow dns       # Port 53 (TCP/UDP)
ufw allow mysql     # Port 3306/tcp
ufw allow mssql     # Port 1433/tcp
ufw allow redis     # Port 6379/tcp
```

### 3. IP-Filter & Subnetze (from / to / proto)
```powershell
# Zugriff auf SSH nur von einer bestimmten IP erlauben
ufw allow from 192.168.1.100 to any port 22 proto tcp

# Zugriff aus einem Subnetz erlauben
ufw allow from 10.0.0.0/24 to any port 3389 proto tcp

# Ganze IP komplett blockieren
ufw deny from 45.33.32.1
```

### 4. Statusanzeige & Regeln nach Index löschen
```powershell
# Status und aktive Regeln ansehen
ufw status

# Nummerierte Liste anzeigen (wie in Linux)
ufw status numbered

# Gezielt Regel nach Zeilennummer löschen
ufw delete 3

# Regel nach Definition löschen
ufw delete allow 80/tcp
```

### 5. Allgemeine Firewall-Steuerung
```powershell
# Firewall ein- oder ausschalten
ufw enable
ufw disable

# Standard-Richtlinie (Default Policy)
ufw default deny incoming
ufw default allow outgoing

# Alle UFW-Regeln zurücksetzen
ufw reset
```
