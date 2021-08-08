#!/bin/bash

echo "####################################################################################"
echo "#     Absicherung von Cent OS 8 nach BSI IT-Grundschutz Vorgaben (SYS.1.1.A16)     #"
echo "####################################################################################"

if [ "$EUID" -ne 0 ] ; then                                                                           # Check, ob das Skript mit dem User Root (aktuelle UID = 0) ausgeführt wird. Dies ist notwendig, da entsprechende Rechte für die Ausführung benötigt werden.
      echo "Zugriff verweigert. Das Skript muss mit Root-Rechten ausgeführt werden"
      exit 0                                                                                          # Script wird ohne Fehlercode beendet.
fi

echo "SYS.1.1.A2: Der Passwortschutz und Inaktivitätsschutz des Systems wird gehärtet. Sind Sie damit einverstanden?"
read -p "[J/n]: " FRAGEANFANG
case $FRAGEANFANG in
	J|j)
		echo "#%PAM-1.0" > /etc/pam.d/passwd																			                        # Diese Einstellungen sind vorgeschlagen worden von Arch Wiki: https://wiki.archlinux.org/index.php/security (letzter Aufruf: 29.10.2020). Per > werden aktuelle Default-Eintragungen überschrieben.
		echo "password required pam_pwquality.so debug retry=1 minlen=16 difok=10 dcredit=-2 ucredit=-2 ocredit=-2 lcredit=-2 enforce_for_root" >> /etc/pam.d/passwd      # genaue Erklärung zu einzelnen Punkten: https://linux.die.net/man/8/pam_pwquality
		echo "password required pam_unix.so use_authtok sha512 shadow" >> /etc/pam.d/passwd
		echo "auth optional pam_faildelay.so delay=20000000" >> /etc/pam.d/system-login									  # Das Delay ist in Millisekunden angegeben.
		
		echo "TMOUT = 60" >> /etc/profile																				                          # Quelle: https://www.cyberciti.biz/faq/linux-tmout-shell-autologout-variable/, hierfür wird der Reboot im letzten Schritt benötigt.
		echo "readonly TMOUT" >> /etc/profile
		echo "export TMOUT" >> /etc/profile

		echo "Überprüfen Sie, ob es Profile gibt, die ein leeres Passwort gesetzt haben und führen Sie ggf. Anpassungen durch: (Wird kein Account angezeigt, ist keiner betroffen)"
		awk -F: '($2 == "") {print}' /etc/shadow																		                      # Quelle: https://www.cyberciti.biz/tips/linux-security.html
		;;
	*)
		echo "Passen Sie bitte händisch die Netzwerkeinstellungen an, um das System dahingehend zu härten. Das Skript wird fortgeführt."
		;;
esac

echo "SYS.1.1.A3,4 und SYS.1.3.A4,9,12,17: Es werden sicherheitsrelevante Anpassungen am Kernel und am System vorgenommen. Soll dies umgesetzt werden?"
read -p "[J/n]: " FRAGEANFANG
case $FRAGEANFANG in
	J|j)
		echo "kernel.dmesg_restrict = 1" > /etc/sysctl.d/51-dmesg-restrict.conf											      # Zugriff auf Kernel-Logs werden unterbunden. Konfiguration wird in eine neu angelegte Datei geschrieben. Quelle: https://wiki.archlinux.org/index.php/security
		echo "kernel.kptr_restrict = 2" > /etc/sysctl.d/51-kptr-restrict.conf											        # Kernel-Pointer werden versteckt.
		echo "kernel.kexec_load_disabled = 1" > /etc/sysctl.d/51-kexec-restrict.conf								    	# Deaktiviert Kexec, was für das Live-Patchen des Kernels genutzt wird. Warnung: So kann auch nicht der Systemupdate-Dienst den Kernel Live patchen.
		echo "kernel.exec-shield = 1" > /etc/sysctl.d/51-exec-shield.conf												          # Aktiviert ExecShield protection (Flag setzen: Datenspeicher nicht ausführbar und Programmspeicher nicht beschreibbar). Quelle: https://www.cyberciti.biz/tips/linux-security.html
		echo "kernel.randomize_va_space = 2" > /etc/sysctl.d/51-randomize_va_space.conf							  		# Randomisiert die Positionen des Stacks, der Virtual Dynamic Shared Object (VDSO)-Page und der gemeinsamen Speicherbereiche. 
		echo "kernel.core_pattern = | /bin/false" > /etc/sysctl.d/51-disable-coredumps.conf								# Deaktiviert Coredumps. Quelle: https://github.com/Obscurix/Obscurix/blob/master/airootfs/etc/sysctl.d/disable-coredumps.conf
		echo "kernel.unprivileged_bpf_disabled = 1" > /etc/sysctl.d/51-unprivileged_bpf.conf							# Schränkt den BPF JIT-Compiler auf root ein. Quelle: https://github.com/Obscurix/Obscurix/blob/master/airootfs/etc/sysctl.d/harden_bpf.conf
		echo "vm.mmap_rnd_bits = 32" > /etc/sysctl.d/51-mmap_aslr.conf												          	# Verbessert die ASLR-Effektivität für mmap (Unix-Systemaufruf, der Dateien oder Geräte dem Speicher zuordnet). Quelle: https://github.com/Obscurix/Obscurix/blob/master/airootfs/etc/sysctl.d/mmap_aslr.conf
		echo "vm.mmap_rnd_compat_bits = 16" > /etc/sysctl.d/51-mmap_aslr.conf
		echo "kernel.yama.ptrace_scope = 2" > /etc/sysctl.d/51-ptrace_scope.conf									      	# ptrace (Durch ptrace kann ein Prozess einen anderen Prozess steuern) auf root beschränken. Quelle: https://github.com/Obscurix/Obscurix/blob/master/airootfs/etc/sysctl.d/ptrace_scope.conf
		echo "kernel.sysrq = 0" > /etc/sysctl.d/51-sysrq.conf															                # Deaktiviert den SysRq-Key (Tastenkombination zur Kernelsteuerung). Quelle: https://github.com/Obscurix/Obscurix/blob/master/airootfs/etc/sysctl.d/sysrq.conf
		echo "kernel.unprivileged_userns_clone=0" > /etc/sysctl.d/51-unprivileged_userns_clone.conf				# Deaktiviert unprivilegierte Benutzernamensräume. Quelle: https://github.com/Obscurix/Obscurix/blob/master/airootfs/etc/sysctl.d/unprivileged_userns_clone.conf
		
		sed -i -- 's/+::0:0:::/ /g' /etc/passwd
		sed -i -- 's/+::0:0:::/ /g' /etc/group

		sed -i -e 's/umask 022/umask 077/g' -e 's/umask 002/umask 077/g' /etc/bashrc								    	# Ändert die Standardrechtevergabe. umask ist die invertierte binäre Darstellung von Rechten auf Dateien und Ordnern. Konfiguration-Quelle: https://www.lisenet.com/2017/centos-7-server-hardening-guide/ und https://wiki.centos.org/HowTos/OS_Protection
		sed -i -e 's/umask 022/umask 077/g' -e 's/umask 002/umask 077/g' /etc/csh.cshrc
		sed -i -e 's/umask 022/umask 077/g' -e 's/umask 002/umask 077/g' /etc/profile
		sed -i -e 's/umask 022/umask 077/g' -e 's/umask 002/umask 077/g' /etc/init.d/functions

		echo "Grundsätzlich sollten die Dateiberechtigungen bzw. Rechte von Nutzern und Gruppen regelmäßig überprüft und ggf. angepasst werden, obwohl die Default-Einstellungen von RHEL, CentOS bzw. Fedora bereits akzeptabel sind. Sollte SELinux im vollen Umfang aktiv sein, gilt dies auch für diese Kernel-Erweiterung."
		
		echo "Verwenden Sie den root-User nur für selektive Tätigkeiten. Administrative Aufgaben sollten restriktiv an andere User deligiert werden."

		sed -i "/^CLASS=/s/ --unrestricted/ /" /etc/grub.d/10_linux													            	# Schutz des Bootloaders GRUB2. Quelle: https://www.thegeekdiary.com/centos-rhel-7-how-to-password-protect-grub2-menu-entries/ und https://www.lisenet.com/2017/centos-7-server-hardening-guide/
		echo "Setzen Sie ein Bootloader (GRUB2) Passwort: "
		grub2-setpassword
		grub2-mkconfig -o /boot/grub2/grub.cfg
		chmod 0600 /boot/grub2/grub.cfg
		echo "Für die Einrichtung von einem signierten Bootloader empfiehlt sich folgende Quelle: https://wiki.archlinux.org/index.php/Unified_Extensible_Firmware_Interface/Secure_Boot#Using_a_signed_boot_loader"

		sed -i -- 's/HISTSIZE=1000/HISTSIZE=10000/g' /etc/profile														              # Vergrößert die Datei der eingegebenen CLI-Befehle auf 10.000 Einträge: Z.T. Quelle: https://www.lisenet.com/2017/centos-7-server-hardening-guide/

		# Es werden nun Limits für Aktionen von Nutzern (/etc/security/limits.conf) vorgenommen. Das soll Denial of Service Angriffe abwehren, die entweder aus dem Netzwerk gestartet werden oder von einer lokal ausgeführten maliziösen Datei.
		echo "*      hard   core      0" >> /etc/security/limits.conf													            # Deaktiviert Core Dumps
		echo "*      soft   nofile    4096" >> /etc/security/limits.conf												          # Anpassungen für alle User außer root. Soft und Hard definieren die zwei unterschiedlichen Limit-Typen.
		echo "*      hard   nofile    8192" >> /etc/security/limits.conf												          # nofile = Maximale Anzahl von geöffneten Dateien. (basierend auf File Descriptors = Indikator für Zugriff einer Datei auf Ressourcen)
		echo "*      soft   nproc     512" >> /etc/security/limits.conf												          	# nproc = Maximale Anzahl von Prozessen
		echo "*      hard   nproc     1024" >> /etc/security/limits.conf
		echo "*      soft   locks     4096" >> /etc/security/limits.conf											          	# locks = Maximale Anzahl von Dateien, die von einem Nutzer gesperrt werden können. (Prozesse sperren den Zugriff auf eine Datei, damit kein anderer Prozess gleichzeigt die Datei manipuliert und es somit zu Fehlern in Programmabläufen kommt)
		echo "*      hard   locks     4096" >> /etc/security/limits.conf
		echo "*      soft   stack     10240" >> /etc/security/limits.conf												          # stack = Maximale Stack Größe in KB. (Stack = Stapelspeicher für die Zwischenspeicherung von Werten)
		echo "*      hard   stack     32768" >> /etc/security/limits.conf
		echo "*      soft   memlock   64" >> /etc/security/limits.conf													          # memlock = Maximale Größe des reservierten Speichers (locked-in-Memory) in KB.
		echo "*      hard   memlock   64" >> /etc/security/limits.conf
		echo "*      hard   maxlogins 10" >> /etc/security/limits.conf													          # maxlogins = Maximale Anzahl von Logins des Users auf dem System.
		echo "*      soft   fsize     33554432" >> /etc/security/limits.conf										         	# fsize = Maximale Dateigröße in KB.
		echo "*      hard   fsize     67108864" >> /etc/security/limits.conf
		echo "root   soft   nofile    4096" >> /etc/security/limits.conf											           	# Anpassungen für den User root.
		echo "root   hard   nofile    8192" >> /etc/security/limits.conf
		echo "root   soft   nproc     512" >> /etc/security/limits.conf
		echo "root   hard   nproc     1024" >> /etc/security/limits.conf
		echo "root   soft   stack     10240" >> /etc/security/limits.conf
		echo "root   hard   stack     32768" >> /etc/security/limits.conf
		echo "root   soft   fsize     33554432" >> /etc/security/limits.conf										         	# Quelle für einige der angegebenen Werte: https://www.lisenet.com/2017/centos-7-server-hardening-guide/
		;;
	*)
		echo "Passen Sie bitte händisch die Netzwerkeinstellungen an, um das System dahingehend zu härten. Das Skript wird fortgeführt."
		;;
esac

echo "SYS.1.1.A5,6 und SYS.1.3.A8,12: Der SSH-Zugang des Systems wird gehärtet. Sind Sie damit einverstanden?"
read -p "[J/n]: " FRAGEANFANG
case $FRAGEANFANG in
	J|j)
		cp /usr/lib/firewalld/services/ssh.xml /etc/firewalld/services/ssh-custom.xml
		echo "Der Standardport 22 sollte abgeändert werden. Es wird empfohlen, sich einen Port auszusuchen, der noch nicht in Benutzung ist. Die Maßnahme wirkt nur, wenn es im Netzwerk Schutzmaßnahmen vor Portscans umgesetzt wurden."
		read -p "Geben Sie den gewünschten Port ein, oder ein beliebigen Buchstaben, um den empfohlenden Port 33846 zu verwenden: " SSHPORT
		if (( $SSHPORT>1 && $SSHPORT<65534))
		then 
			sed -i -- "s/#Port 22/Port $SSHPORT/g" /etc/ssh/sshd_config
			sed -i -- "s/22/$SSHPORT/g" /etc/firewalld/services/ssh-custom.xml
			semanage port -a -t ssh_port_t -p tcp $SSHPORT
			firewall-cmd --add-port=$SSHPORT/tcp --zone=internal --permanent
		else
			sed -i -- 's/#Port 22/Port 33846/g' /etc/ssh/sshd_config
			sed -i -- "s/22/33846/g" /etc/firewalld/services/ssh-custom.xml
			semanage port -a -t ssh_port_t -p tcp 33846
			firewall-cmd --add-port=33846/tcp --zone=internal --permanent
		fi
		firewall-cmd --permanent --remove-service='ssh'
		firewall-cmd --permanent --add-service='ssh-custom'
		firewall-cmd --reload

		sed -i -- "s/#LoginGraceTime 2m/LoginGraceTime 120m/g" /etc/ssh/sshd_config
		sed -i -- "s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config
		sed -i -- "s/#MaxAuthTries 6/MaxAuthTries 2/g" /etc/ssh/sshd_config
		sed -i -- "s/#MaxSessions 10/MaxSessions 1/g" /etc/ssh/sshd_config
		sed -i -- "s/#PubkeyAuthentication yes/PubkeyAuthentication yes/g" /etc/ssh/sshd_config
		sed -i -- "s/#PermitEmptyPasswords no/PermitEmptyPasswords no/g" /etc/ssh/sshd_config
		sed -i -- "s/#AllowAgentForwarding yes/AllowAgentForwarding no/g" /etc/ssh/sshd_config
		sed -i -- "s/#AllowTcpForwarding yes/AllowTcpForwarding no/g" /etc/ssh/sshd_config
		sed -i -- "s/X11Forwarding yes/X11Forwarding no/g" /etc/ssh/sshd_config
		sed -i -- "s/#IgnoreRhosts yes/IgnoreRhosts yes/g" /etc/ssh/sshd_config
		sed -i -- "s/#LogLevel INFO/LogLevel VERBOSE/g" /etc/ssh/sshd_config

		echo "Protocol 2" >> /etc/ssh/sshd_config

		echo "ClientAliveInterval 2m" >> /etc/ssh/sshd_config														                 	# Quelle: https://www.thegeekdiary.com/centos-rhel-how-to-setup-session-idle-timeout-inactivity-timeout-for-ssh-auto-logout/
		echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config

		systemctl restart sshd

		echo "In diesem Zusammenhang werden weitere nicht benötigte Dienste entfernt, die meist einen Zugang zu dem System herstellen."
		yum erase xinetd ypserv ypbind tftp-server telnet telnet-server rsh rsh-server tfsp-server vsfptd dovecot squid talk-server talk -y 		# z.T. Quelle: https://www.cyberciti.biz/tips/linux-security.html und https://www.lisenet.com/2017/centos-7-server-hardening-guide/

		echo "Grundsätzlich empfehlt es sich, nur zertifikatsbasierte Anmeldungen zuzulassen und passwortbasierte zu deaktivieren."
		;;
	*)
		echo "Passen Sie bitte händisch die Netzwerkeinstellungen an, um das System dahingehend zu härten. Das Skript wird fortgeführt."
		;;
esac

echo "SYS.1.1.A6: Bitte gehen Sie händisch die installierten Software-Pakete durch und entfernen Sie die nicht benötigten. Wichtig ist die Beachtung von Abhängigkeiten. Folgende Befehle unterstützen Sie dabei: "
echo "- yum list installed"
echo "- yum erase Paketname"
echo "Bitte gehen Sie auch die Liste der aktiven Services und Daemons durch und deaktivieren Sie ggf. nicht benötigte Dienste (systemctl stop/disable [service_name]):"
echo "- systemctl list-unit-files"

echo "SYS.1.1.A7: Das System wird zunächst aktualisiert."
systemctl enable chronyd.service																					                         	# Aktiviert NTP Dienst. Bei falscher Zeitkonfiguration könnte es zu Problemen mit dem Abrufen von Updates kommen.
systemctl start chronyd.service
yum update -y 																										                                 	# Das System checkt bei den hinterlegten Repositories, ob für die installierten Softwarepakete Aktualisierungen vorliegen. Wenn dies der Fall ist, werden diese ohne Nutzerinteraktion installiert.
echo "Es wird empfohlen, sich über Aktualisierungen per Mail informieren zu lassen: https://lists.centos.org/mailman/listinfo/centos-announce"
echo "Es wird automatisiert nach Sicherheitsupdates gesucht. Soll dies eingerichtet werden?"
read -p "[J/n]: " FRAGEANFANG																						                          	# -p legt einen Prompt fest, inkl. Ausgabe, welche Eingaben zu erwarten sind. Damit wird die entsprechende Variable gefüllt.
case $FRAGEANFANG in																									                              # case-Abfrage, ob der Nutzer wirklich fortfahren will. Anwortmöglichkeit J = Ausführung, N und andere Eingaben = abbruch. Case bezieht sich auf die Variable Frageanfang, die mit einem $-Zeichen aufgerufen wird
	J|j)																												                                      # Möglichkeiten J oder j führen zu dem eigentlichen Scriptablauf, | als logisches ODER
		dnf install dnf-automatic -y
		sed -i -- "s/upgrade_type = default/upgrade_type = security/g" /etc/dnf/automatic.conf					# Es werden nicht alle Updates automatisiert installiert, sondern nur die sicherheitsbezogenen. Dies geschiet u. a. aufgrund von Stabilitätsgründen.
		sed -i -- "s/apply_updates = no/apply_updates = yes/g" /etc/dnf/automatic.conf									# Updates werden nicht nur heruntergeladen, sondern auch installiert.
		echo "Sollte die E-Mail Benachrichtung aktiviert werden, editieren Sie bitte folgende Datei: /etc/dnf/automatic.conf"
		systemctl enable dnf-automatic.timer
		systemctl start dnf-automatic.timer
		;;																											                                      	# Ende der Durchführung, wenn erste Bedingung der case-Struktur erfüllt ist
	*)																												                                      	# sollte erste Bedinung der case-Struktur nicht gegeben sein, werden jegliche andere Eingaben abgefangen.
		echo "Bitte achten Sie darauf, dass System regelmäßig zu aktualisieren. Das Skript wird fortgeführt."	
		;;
esac

echo "SYS.1.1.A9: Das Skript installiert ClamAV als Virenschutz und konfiguriert das Schutzsystem anschließend. Sind Sie damit einverstanden?"
read -p "[J/n]: " FRAGEANFANG
case $FRAGEANFANG in
	J|j)
		yum install epel-release -y																					                           	# Quelle: https://github.com/Adminbyaccident/CentOS/blob/master/clamav_centos8.sh, https://www.adminbyaccident.com/gnu-linux/how-to-install-the-clamav-antivirus-on-centos-8/, https://medium.com/swlh/how-to-install-an-open-source-antivirus-on-centos-e1c09734096f sowie https://www.clamav.net/documents/installation-on-redhat-and-centos-linux-distributions und https://www.clamav.net/documents/on-access-scanning
		dnf install clamav clamav-update clamd -y
		setsebool -P antivirus_can_scan_system 1
		sed -i 's/#LocalSocket \/run/LocalSocket \/run/g' /etc/clamd.d/scan.conf
		sed -i 's/scanner (%i) daemon/scanner daemon/g' /usr/lib/systemd/system/clamd@.service
		sed -i 's/\/etc\/clamd.d\/%i.conf/\/etc\/clamd.d\/scan.conf/g' /usr/lib/systemd/system/clamd@.service
		systemctl enable clamav-freshclam.service
		systemctl start clamav-freshclam.service
		freshclam
		sed -i 's/#OnAccessPrevention yes/OnAccessPrevention yes/g' /etc/clamd.d/scan.conf
		sed -i 's/#OnAccessIncludePath \/home/OnAccessIncludePath \/home/g' /etc/clamd.d/scan.conf
		sed -i 's/#OnAccessExcludeUname clamav/OnAccessExcludeUname clamscan/g' /etc/clamd.d/scan.conf
		touch /usr/lib/systemd/system/clamonacc.service
		echo "[Unit]" > /usr/lib/systemd/system/clamonacc.service
		echo "Description=ClamAV On Access Scanner" >> /usr/lib/systemd/system/clamonacc.service
		echo "Requires=clamd@service" >> /usr/lib/systemd/system/clamonacc.service
		echo "After=clamd.service syslog.target network-online.target" >> /usr/lib/systemd/system/clamonacc.service
		echo " " >> /usr/lib/systemd/system/clamonacc.service
		echo "[Service]" >> /usr/lib/systemd/system/clamonacc.service
		echo "Type=simple" >> /usr/lib/systemd/system/clamonacc.service
		echo "User=root" >> /usr/lib/systemd/system/clamonacc.service
		echo "ExecStart=/usr/bin/clamonacc -F --log=/var/log/clamonacc --move=/tmp/clamav-quarantine" >> /usr/lib/systemd/system/clamonacc.service
		echo "Restart=on-failure" >> /usr/lib/systemd/system/clamonacc.service
		echo "RestartSec=7s" >> /usr/lib/systemd/system/clamonacc.service
		echo " " >> /usr/lib/systemd/system/clamonacc.service
		echo "[Install]" >> /usr/lib/systemd/system/clamonacc.service
		echo "WantedBy=multi-user.target" >> /usr/lib/systemd/system/clamonacc.service
		touch /var/log/clamonacc
		mkdir /tmp/clamav-quarantine
		usermod -aG wheel clamscan
		systemctl daemon-reload
		systemctl enable clamd@.service
		systemctl start clamd@service
		systemctl enable clamonacc.service
		systemctl start clamonacc.service
		;;
	*)
		echo "Das Skript wird fortgeführt. Alternativ kann Comodo Antivirus über https://www.comodo.com/home/download/during-download.php?prod=linuxantivirus&os=centos&bit=64 installiert werden. Zuvor sollte ClamAV wieder entfernt werden."
		;;
esac

echo "SYS.1.1.A9: Es wird rkhunter als Rootkit-Scanner installiert. Sind Sie damit einverstanden?"
read -p "[J/n]: " FRAGEANFANG
case $FRAGEANFANG in
	J|j)
		yum install epel-release -y																						                          # Notwendige Pakete werden ohne Nutzerinteraktion installiert.
		yum install rkhunter -y
		rkhunter --update
		rkhunter --propupd																							                              	# Datenbank über aktuelle im System hinterlegte Dateien erstellt (Hash).
		rkhunter --check --sk
		echo "Es sollten regelmäßig Checks mit dem folgenden Befehl gemacht werden: rkhunter --check --sk"
		;;
	*)
		echo "Das Skript wird fortgeführt."
		;;
esac

echo "SYS.1.1.A10: Bitte prüfen Sie regelmäßig die Protokolle oder nutzen Sie ein zentrales Tool wie ein SIEM. Folgende Log-Files sind von Relevanz:"
echo "- /var/log/messages: Allgemeine Nachrichten und systembezogene Informationen"
echo "- /var/log/auth.log: Authentifizierungsprotokolle"
echo "- /var/log/kern.log: Kernel-Logs"
echo "- /var/log/boot.log: Boot-Logs"
echo "- /var/log/yum.log: YUM-Logs"

echo "SYS.1.1.A19,20: Es werden nun Anpassungen an der Netzwerkkonfiguration vorgenommen. In der Datei /etc/sysctl.conf können diese anschließend angepasst werden. Zudem werden Anpassungen an der Firewall vorgenommen. Soll dies umgesetzt werden?"
read -p "[J/n]: " FRAGEANFANG
case $FRAGEANFANG in
	J|j)
		echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf																              # Diese Einstellungen stammen von der offiziellen Seite von CentOS: https://wiki.centos.org/HowTos/OS_Protection#Network_Security (Letzer Aufruf: 29.10.2020)
		echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf												         	# /etc/systctl.conf ist aktuell ohne Konfigurationsinhalt. Somit können folgende Parameter per >> an den Inhalt angehangen werden.
		echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_max_syn_backlog = 1280" >> /etc/sysctl.conf
		echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
		echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
		echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
		echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
		echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
		echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
		echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
		echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
		echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
		echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
		echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
		echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_timestamps = 0" >> /etc/sysctl.conf
		echo "net.ipv4.conf.all.forwarding = 0" >> /etc/sysctl.conf
		echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf											        	# Quelle: https://www.lisenet.com/2017/centos-7-server-hardening-guide/
		echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
		echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_timestamps = 1" >> /etc/sysctl.conf
		echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
		echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
		echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
		echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
		echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
		echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf													          # Quelle: https://github.com/Obscurix/Obscurix/blob/master/airootfs/etc/sysctl.d/tcp_hardening.conf
		echo "net.ipv4.tcp_rfc1337 = 1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_sack = 0" >> /etc/sysctl.conf															                	# Quelle: https://github.com/Obscurix/Obscurix/blob/master/airootfs/etc/sysctl.d/tcp_sack.conf
		echo "net.core.bpf_jit_harden = 2" >> /etc/sysctl.conf													            		# Quelle: https://obscurix.github.io/security/kernel-hardening.html
		echo "NOZEROCONF = yes" >> /etc/sysconfig/network															                	# Disable Zeroconf Networking. Quelle: https://www.lisenet.com/2017/centos-7-server-hardening-guide/
		echo "NETWORKING_IPV6 = no" >> /etc/sysconfig/network 												            			# Disable Interface Usage of IPv6
		echo "IPV6INIT = no" >> /etc/sysconfig/network

		echo "Es wird firewall-config als GUI für die Firewall-Konfiguration installiert. Sollte das Skript nicht fortfahren, muss firewall-config geschlossen werden."
		yum install firewalld firewall-config -y
		systemctl enable firewalld
		systemctl start firewalld
		firewall-cmd --set-default-zone=drop																		                      	# Die Standard-Zone für den Firewall-Daemon wird zu Drop (alle eingehenden Pakete werden ohne Response verworfen. Ausgehende Verbindungen werden nicht angepasst).
		echo "Bitte passen Sie die zugelassenen Dienste und Ports auf ein Minimum an. Folgende Befehle sind hierzu zu verwenden:"
		echo "- firewall-cmd --list-services --zone=[Zone]"
		echo "- firewall-cmd --list-ports --zone=[Zone]"
		;;
	*)
		echo "Passen Sie bitte händisch die Netzwerkeinstellungen an, um das System dahingehend zu härten. Das Skript wird fortgeführt."
		;;
esac

echo "SYS.1.1.A19,20: Es werden nun Anpassungen an der Konfiguration von TCP-Wrapper vorgenommen. TCP-Wrapper schützt das System vor unerwünschten Zugriffen aus einem Netzwerk. Soll dies umgesetzt werden?"
read -p "[J/n]: " FRAGEANFANG
case $FRAGEANFANG in
	J|j)
		touch /etc/hosts.allow																						                           	# beide notwendigen Dateien sind noch nicht vorhanden und müssen per touch erstellt werden.
		touch /etc/hosts.deny
		echo "ALL: 127.0.0.1" >> /etc/hosts.allow 											                							# Erlaubt den Zugriff von lokal (Localhost). /etc/hosts.allow ist akuell ohne Inhalt. Also können die folgenden Konfigurationen per >> an den Text angehangen werden.
		echo "sshd: ALL" >> /etc/hosts.allow 																                    			# Erlaubt den Zugriff auf den SSH Daemon
		echo "ALL: ALL" >> /etc/hosts.deny 																	                    			# Jeder weitere Zugriff wird blockiert.
		;;
	*)
		echo "Prüfen Sie bitte den Einsatz von TCP-Wrapper. Das Skript wird fortgeführt."
		;;
esac

echo "SYS.1.1.A26: Es wird Google Authenticator als Zwei-Faktor-Authentifizierung (2FA) installiert. Sind Sie damit einverstanden?"
read -p "[J/n]: " FRAGEANFANG
case $FRAGEANFANG in
	J|j)
		yum install google-authenticator qrencode -y																                	# z.T. Quelle: https://www.howtoforge.com/tutorial/secure-ssh-with-google-authenticator-on-centos-7/ und https://www.linode.com/docs/guides/how-to-use-one-time-passwords-for-two-factor-authentication-with-ssh-on-centos/
		sed -i -- 's/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/g' /etc/ssh/sshd_config
		sed -i -- 's/UsePAM no/UsePAM yes/g' /etc/ssh/sshd_config
		echo "AuthenticationMethods keyboard-interactive" >> /etc/ssh/sshd_config
		echo "auth required pam_google_authenticator.so" >> /etc/pam.d/sshd 
		echo "Führen Sie als Standardnutzer folgende Schritte aus, um 2FA zu aktivieren:"
		echo "Das Programm google-authenticator starten. Bitte beantworten die Fragen wie folgt: y, y, y, n, y und notieren Sie sich die genannten Emergency Scratch Codes"
		echo "Nun muss SELinux angepasst werden, da sonst der Zugriff auf pam_google_authenticator blockiert wird: Per root ausführen: semanage fcontext -a -s user_u -t lib_t /usr/lib/security/pam_google_authenticator.so"
		echo "Abschließend den SSH-Daemon als root neustarten: systemctl restart sshd"
		;;
	*)
		echo "Bitte installieren Sie händisch eine weitere Form der Mehr-Faktor-Authentifizierung."
		;;
esac

echo "SYS.1.1.A23: Es wird nun ARPWatch für die Überwachung des ARP Netzwerkverkehrs installiert. Sind Sie damit einverstanden?"
read -p "[J/n]: " FRAGEANFANG
case $FRAGEANFANG in
	J|j)
		yum install arpwatch -y
		systemctl enable arpwatch
		systemctl start arpwatch
		arpwatch -f /var/log/arpwatch																				                      	# ARPWatch schreibt die Logs in die Datei /var/log/arpwatch > Anbindung SIEM.
		;;
	*)
		echo "Das Skript wird fortgeführt."
		;;
esac

echo "SYS.1.1.A23: Es wird nun psacct als Dienstprogramm-Sammlung zur Überwachung von Prozessaktivitäten installiert. Sind Sie damit einverstanden?"
read -p "[J/n]: " FRAGEANFANG
case $FRAGEANFANG in
	J|j)
		yum install psacct -y
		systemctl enable psacct.service
		systemctl start psacct.service
		;;
	*)
		echo "Das Skript wird fortgeführt."
		;;
esac

echo "SYS.1.1.A5,27: Es wird Fail2Ban installiert und konfiguriert. Sind Sie damit einverstanden?"
read -p "[J/n]: " FRAGEANFANG
case $FRAGEANFANG in
	J|j)
		yum install epel-release -y
		yum install fail2ban fail2ban-systemd -y
		yum update selinux-policy* -y																					                      # Die Datenbank von SELinux wird aktualisiert mit den Rules, die mit den Paketen aus dem Repository kamen.
		cp /etc/fail2ban/jail.{conf,local}																				                  # Quelle zum Teil: https://linuxize.com/post/install-configure-fail2ban-on-centos-8/
		sed -i -- 's/#ignoreip/ignoreip/g' /etc/fail2ban/jail.local												        	# In der Datei /etc/fail2ban/jail.local wird jeder gefundene Eintrag # ignoreip = 127.0.0.1/8 ::1 ersetzt mit dem gleichen ohne vorgesetzem # Zeichen (Kommentar)
		sed -i -- 's/bantime = 10m/bantime = 60m/g' /etc/fail2ban/jail.local										  	# Sollte ein Host permanent gesperrt werden, müsste dieser Wert zu einem negativen geändert werden.
		sed -i -- 's/maxretry = 5/maxretry = 3/g' /etc/fail2ban/jail.local
		sed -i -- 's/findtime = 10m/findtime = 60m/g' /etc/fail2ban/jail.local											# Findtime: Wenn ein Host die Obergrenze der Maxretry-Einstellung innerhalb des durch die findtime-Option festgelegten Zeitraums überschreitet, wird er für den durch die bantime-Option festgelegten Zeitraum gesperrt.

		touch /etc/fail2ban/jail.d/sshd.local																	                  		# Eine Konfigurationsdatei für den SSH-Daemon wird erstellt.
		echo "[sshd]" >> /etc/fail2ban/jail.d/sshd.local
		echo "enabled = true" >> /etc/fail2ban/jail.d/sshd.local
		echo "port = ssh" >> /etc/fail2ban/jail.d/sshd.local
		echo "logpath = %(sshd_log)s" >> /etc/fail2ban/jail.d/sshd.local
		echo "maxretry = 3" >> /etc/fail2ban/jail.d/sshd.local
		echo "bantime = 60m" >> /etc/fail2ban/jail.d/sshd.local

		systemctl enable fail2ban
		systemctl start fail2ban
		;;
	*)
		echo "Das Skript wird fortgeführt."
		;;
esac

echo "SYS.1.1.A24: Es wird nun Lynis als Audit Tool installiert und das System mit diesem Programm gescannt. Sind Sie damit einverstanden?"
read -p "[J/n]: " FRAGEANFANG
case $FRAGEANFANG in
	J|j)
		yum update ca-certificates curl nss openssl	-y																          	# Quelle: https://packages.cisofy.com/community/#centos-rhel (zum Teil)
		echo "[lynis]" >> /etc/yum.repos.d/cisofy-lynis.repo														        	# Hinzufügen des Repository, um die Softwarequelle zu definieren. Hierbei wird die Lynis Community Version verwendet, bei der keine Anmeldung notwendig ist.
		echo "name=CISOfy Software - Lynis package" >> /etc/yum.repos.d/cisofy-lynis.repo
		echo "baseurl=https://packages.cisofy.com/community/lynis/rpm/" >> /etc/yum.repos.d/cisofy-lynis.repo
		echo "enabled=1" >> /etc/yum.repos.d/cisofy-lynis.repo
		echo "gpgkey=https://packages.cisofy.com/keys/cisofy-software-rpms-public.key" >> /etc/yum.repos.d/cisofy-lynis.repo
		echo "gpgcheck=1" >> /etc/yum.repos.d/cisofy-lynis.repo
		echo "priority=2" >> /etc/yum.repos.d/cisofy-lynis.repo
		yum install lynis -y
		echo "Die Ergebnisse des Scans durch Lynis sind in der Datei /tmp/Lynis_Results.txt zu finden. Der Vorgang kann einige Minuten in Anspruch nehmen."
		touch /tmp/Lynis_Results.txt
		lynis audit system --verbose > /tmp/Lynis_Results.txt
		;;
	*)
		echo "Das Skript wird fortgeführt."
		;;
esac

echo "SYS.1.1.A31: Es wird fapolicyd als Application Whitelisting Daemon installiert. Sind Sie damit einverstanden? Eine anschließende Anpassung der Rules sollte unbedingt folgen!"
read -p "[J/n]: " FRAGEANFANG
case $FRAGEANFANG in
	J|j)
		yum install fapolicyd -y																						                      # Quelle: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/configuring-and-managing-application-whitelists_security-hardening
		echo "Der Dienst sollte nach Konfiguration über systemctl enable --now fapolicyd gestartet werden."
		echo "Bei auftretenden Problemen hilft folgender Befehl: fapolicyd --debug"
		echo "Folgende Quelle ist zu empfehlen: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/configuring-and-managing-application-whitelists_security-hardening und https://github.com/linux-application-whitelisting/fapolicyd"
		echo "Bitte rufen Sie Websites nicht von zu schützenden Webservern auf."
		;;
	*)
		echo "Das Skript wird fortgeführt."
		;;
esac

echo "SYS.1.1.A27: Es wird nun AIDE als HIDS (Host Intrustion Detection System) installiert und die Datenbank des Programms initialisiert. Sind Sie damit einverstanden?"
read -p "[J/n]: " FRAGEANFANG
case $FRAGEANFANG in
	J|j)
		yum install aide -y
		echo "Die Datenbank wird nun initialisiert. Dies kann mehrere Minuten in Anspruch nehmen."
		echo "Durch den Befehl aide --check -V können Abweichungen, die durch AIDE registriert wurden, angezeigt werden."
		echo "Die Konfiguration von AIDE ist in der Datei /etc/aide.conf anpassbar."
		aide --init
		;;
	*)
		echo "Das Skript wird fortgeführt."
		;;
esac

echo "SYS.1.3.A10,16: SELinux wird in Enforcing Mode gestellt. Sind Sie damit einverstanden?"
read -p "[J/n]: " FRAGEANFANG
case $FRAGEANFANG in
	J|j)
		yum update selinux-policy* -y																				                      	# Die Datenbank von SELinux wird aktualisiert mit den Rules, die mit den Paketen aus dem Repository kamen.
		setenforce 1																								                              	# SELinux wird in Enforcing Mode gesetzt. Damit werden unerlaupte Zugriffe wie im Permissive Mode nicht nur geloggt, sondern auch unterbunden.
		;;
	*)
		echo "Der SELinux Modus wurde nicht angepasst."
		;;
esac

echo "Das Skript ist abgeschlossen und terminiert nun. Soll das System neugestartet werden, damit alle Änderungen angewendet werden?"
read -p "[J/n]: " FRAGEANFANG
case $FRAGEANFANG in
	J|j)
		echo "Der Server startet in 2 Minuten neu. Bitte beenden Sie laufende Prozesse und sichern Sie in Bearbeitung befindliche Dateien."
		shutdown -r +2																								                            	# Das System wird heruntergefahren mit dem Parameter +2, welcher den Zeitpunkt deklariert. -r definiert den Neustart (Vergleich zu -h = Herunterfahren).
		;;
	*)
		exit 0
		;;
esac

# HINWEIS: NICHT JEDE ZEILE WURDE KOMMENTIERT, DIE ERKLÄRUNGEN FINDET MAN IN ANDEREN ZEILEN, ODER SIND SELBSTERKLÄREND.
# ERSTELLT DURCH ANGELO T. ASCHERT. https://twitter.com/ATAschert
