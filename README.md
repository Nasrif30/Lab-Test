

# 📖 Lab Test – Agent/Listener System

This project demonstrates a **secure reporting agent** and **listener service** running in isolated VMs.
The agent collects system info and sends it to the listener over HTTPS, using:

* TLS with a lab CA + server cert
* HMAC-SHA256 integrity/authentication
* Nonce + timestamp for replay protection
* JSON log storage

⚠️ This setup was only tested in a **controlled, consented lab environment** with my own VMs. It is **not for real-world spying or malicious use**.

---

## 📂 Files

* `listener_secure_final.py` → HTTPS listener (server)
* `agent_secure_final.py` → silent one-shot agent (client)
* `lab-ca.crt` → lab CA cert (trusted by agent)
* `cert.pem`, `key.pem` → server cert + private key

---

## 🛠️ Setup

### 1. Generate CA & certs (on listener VM)

```bash
# Create CA
openssl genrsa -out lab-ca.key 4096
openssl req -x509 -new -nodes -key lab-ca.key -sha256 -days 36500 \
  -out lab-ca.crt -subj "/CN=Lab-CA/O=HomeworkLab"

# Server key + CSR
openssl genrsa -out key.pem 2048
openssl req -new -key key.pem -out server.csr -subj "/CN=lab-listener"

# Sign server cert with CA
openssl x509 -req -in server.csr -CA lab-ca.crt -CAkey lab-ca.key -CAcreateserial \
  -out cert.pem -days 36500 -sha256
```

---

### 2. Trust CA on agent VM

* **Linux:**

  ```bash
  sudo cp lab-ca.crt /usr/local/share/ca-certificates/lab-ca.crt
  sudo update-ca-certificates
  ```
* **Windows (PowerShell as Admin):**

  ```powershell
  Import-Certificate -FilePath "C:\path\to\lab-ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
  ```

Or just use `--cafile lab-ca.crt` when running the agent.

---

### 3. Run listener (manual test)

```bash
python3 listener_secure_final.py --host 0.0.0.0 --port 8000 \
  --secret "S#per$ecret" --cert cert.pem --key key.pem
```

---

### 4. Run agent (manual test)

```bash
python3 agent_secure_final.py --collector 192.168.56.1:8000 \
  --secret "S#per$ecret" --name agent1 --cafile lab-ca.crt
```

* Silent on success
* Listener console prints full JSON report

---

### 5. Package agent (double-click app)

**Windows:**

```bash
pip install pyinstaller
pyinstaller --onefile --windowed agent_secure_final.py
```

Executable in: `dist/agent_secure_final.exe`

Create desktop shortcut with Target:

```
"C:\path\to\dist\agent_secure_final.exe" --collector 192.168.56.1:8000 --secret "S#per$ecret" --name agent1 --cafile "C:\path\to\lab-ca.crt"
```

Double-click → runs silently, exits.

**Linux:**

```bash
pip install pyinstaller
pyinstaller --onefile agent_secure_final.py
chmod +x dist/agent_secure_final
```

Create `~/Desktop/LabAgent.desktop`:

```ini
[Desktop Entry]
Type=Application
Terminal=false
Name=Lab Agent
Exec=/home/you/dist/agent_secure_final --collector 192.168.56.1:8000 --secret S#per$ecret --name agent1 --cafile /home/you/lab-ca.crt
Icon=utilities-terminal
```

---

### 6. Run listener as background service

**Linux systemd unit** (`/etc/systemd/system/lab-listener.service`):

```ini
[Unit]
Description=Lab Secure Listener
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/lab/listener_secure_final.py \
  --host 0.0.0.0 --port 8000 \
  --secret S#per$ecret \
  --cert /opt/lab/cert.pem \
  --key /opt/lab/key.pem
Restart=always
User=nobody
WorkingDirectory=/opt/lab

[Install]
WantedBy=multi-user.target
```

Enable + start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lab-listener
```

---

## 🔬 Security tests

1. **Normal run:** agent sends → listener logs → `reports.jsonl` grows
2. **Replay test:** resend same JSON/HMAC → listener replies `409 Replay`
3. **Invalid HMAC:** modify secret → listener replies `403 HMAC invalid`
4. **Stale timestamp:** set old `ts` → listener replies `408 Stale timestamp`

---

## 📊 Example report

```json
{
  "agent_name": "agent1",
  "hostname": "agent-vm",
  "os": { "system": "Linux", "release": "5.15.0", "version": "#1 SMP Tue ..." },
  "local_ips": ["192.168.56.101"],
  "time_iso": "2025-09-30T12:34:56Z",
  "nonce": "9d8f7e6a4b3c2a1f0e9d8f7e6a4b3c2a",
  "ts": 1745684096,
  "_received_at": "2025-09-30T12:34:57+00:00",
  "_from": "192.168.56.101"
}
```

---

## 📌 Notes for report

* TLS with custom CA prevents MITM
* HMAC ensures authenticity/integrity
* Nonce + timestamp prevent replay
* Silent agent packaging → double-click “app” behavior
* Listener can run as background service


