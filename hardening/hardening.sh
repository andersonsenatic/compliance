#!/bin/bash

#-----------------------------------------
# Configurações de Hardening para RHEL 9
#-----------------------------------------

SSH_Params() {
cat <<_CONF
Protocol 2
SyslogFacility AUTHPRIV
LogLevel VERBOSE
LoginGraceTime 2m
PermitRootLogin no
MaxAuthTries 3
PermitEmptyPasswords no
PasswordAuthentication yes
ClientAliveInterval 7m
ClientAliveCountMax 3
MaxStartups 4
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
PermitAgentForwarding no
GSSAPIAuthentication no
Banner /etc/issue.ssh
_CONF
}

SSH_Banner() {
cat <<_BANNER > /etc/issue.ssh
*************************************************************
* Atenção: Acesso não autorizado é proibido.                *
* Todo acesso e atividade neste sistema são monitorados.    *
* Ao continuar, você concorda com os termos de uso e        *
* políticas de segurança da organização.                    *
*************************************************************
_BANNER
}

SSH_Security_check() {
    SSH_Params > /etc/ssh/sshd_config
    SSH_Banner
    systemctl restart sshd
    echo "Configuração de segurança do SSH aplicada."
}



SystemServiceList() {
cat <<_list
auditd              enable
sshd                enable
# Desativar serviços desnecessários
firewalld           disable
cups                disable
avahi-daemon        disable
bluetooth           disable
_list
}

Kernel_Params() {
cat <<_Params
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
_Params
}

Firewall_Config() {
    # Permitir apenas portas essenciais
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    firewall-cmd --reload
}

PAM_Config() {
    # Configuração básica de política de senha do PAM
    echo "password requisite pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1" >> /etc/pam.d/password-auth
    echo "password requisite pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1" >> /etc/pam.d/system-auth
}

SELinux_Config() {
    # Verificar e definir o SELinux para disabled
    if [ "$(getenforce)" != "Disabled" ]; then
        setenforce 0
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    fi
}

Auditd_Config() {
    # Configuração do auditd para auditoria de segurança
	sudo rm -f /etc/audit/rules.d/*.rules
        sudo auditctl -D

    # Arquivos de autenticação e identidade
    echo "-w /etc/passwd -p wa -k auth" >> /etc/audit/rules.d/audit.rules
    echo "-w /etc/group -p wa -k auth" >> /etc/audit/rules.d/audit.rules
    echo "-w /etc/shadow -p wa -k auth" >> /etc/audit/rules.d/audit.rules
    echo "-w /etc/sudoers -p wa -k auth" >> /etc/audit/rules.d/audit.rules

    # Configuração de rede e firewall
    echo "-w /etc/hosts -p wa -k network" >> /etc/audit/rules.d/audit.rules
    echo "-w /etc/resolv.conf -p wa -k network" >> /etc/audit/rules.d/audit.rules

    # Logs de segurança e sistema
    echo "-w /var/log/auth.log -p wa -k authlog" >> /etc/audit/rules.d/audit.rules
    echo "-w /var/log/syslog -p wa -k syslog" >> /etc/audit/rules.d/audit.rules
    echo "-w /var/log/audit/audit.log -p wa -k auditlog" >> /etc/audit/rules.d/audit.rules

    # Configuração do SSH
    echo "-w /etc/ssh/sshd_config -p wa -k ssh" >> /etc/audit/rules.d/audit.rules

    # Parâmetros do kernel
    echo "-w /etc/sysctl.conf -p wa -k sysctl" >> /etc/audit/rules.d/audit.rules

    # Binários e diretórios críticos do sistema
    echo "-w /bin/ -p wa -k binaries" >> /etc/audit/rules.d/audit.rules
    echo "-w /sbin/ -p wa -k binaries" >> /etc/audit/rules.d/audit.rules

    # Recarregar as regras do auditd
    augenrules --load
}


Disable_Compilers() {
    # Restringir uso de compiladores para usuários não root
    chmod 750 /usr/bin/gcc*
    chmod 750 /usr/bin/make*
}

Kernel_Tuning() {
    # Aplicar configurações de kernel de hardening
    local Conf='/etc/sysctl.conf'
    Kernel_Params > "$Conf"
    sysctl -p "$Conf"
}

Service_Control() {
    # Controle de serviços usando systemd
    ServiceList="$(mktemp)"
    SystemServiceList > "$ServiceList"
    while IFS=' ' read -r srv option; do
        if systemctl list-units --type=service --all | grep -q "$srv.service"; then
            if [ "$option" == "enable" ]; then
                systemctl enable --now "$srv"
            elif [ "$option" == "disable" ]; then
                systemctl disable --now "$srv"
            fi
        else
            echo "Serviço $srv não encontrado no systemctl."
        fi
    done < "$ServiceList"
    rm -f "$ServiceList"
}

#-----------------------------------------
# Menu Principal
#-----------------------------------------
while true; do
    cat <<_EOF
    ------------------------------------
    |     Menu de Segurança            |
    ------------------------------------
    |   1. Configurar Segurança SSH    |
    |   2. Configurar de Kernel        |
    |   3. Política de Senhas PAM      |
    |   4. Desabilitar SELinux         |
    |   5. Auditoria e Logs            |
    |   6. Controle de Serviços        |
    |   7. Restringir Compiladores     |
    |   8. Executar Todas as Opções    |
    |   9. Sair                        |
    ------------------------------------
_EOF
    read -rp "Selecione uma opção: " input
    case "$input" in
        1) echo "Configuração de Segurança SSH"; SSH_Security_check ;;
        2) echo "Configuração de Kernel"; Kernel_Tuning ;;
        3) echo "Política de Senhas PAM"; PAM_Config ;;
        4) echo "Configuração do SELinux"; SELinux_Config ;;
        5) echo "Configuração de Auditoria"; Auditd_Config ;;
        6) echo "Controle de Serviços"; Service_Control ;;
        7) echo "Restringir Compiladores"; Disable_Compilers ;;
        8) echo "Executando todas as opções"; SSH_Security_check; Firewall_Config; PAM_Config; SELinux_Config; Auditd_Config; Service_Control; Disable_Compilers ;;
        9) echo "Saindo"; exit 0 ;;
        *) echo "Opção inválida" ;;
    esac
done

