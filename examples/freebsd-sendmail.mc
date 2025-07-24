# FreeBSD Sendmail Configuration for FOFF Milter
# Add these lines to your /etc/mail/`hostname`.mc file

# FOFF milter configuration
INPUT_MAIL_FILTER(`foff-milter', `S=unix:/var/run/foff-milter.sock, F=5, T=S:30s;R:30s')

# The F=5 flag enables header modifications:
# F=1 = add headers, F=4 = change headers, F=5 = both

# Optional: Configure milter macros for better context
define(`confMILTER_MACROS_CONNECT', `j, _, {daemon_name}, {if_name}, {if_addr}')
define(`confMILTER_MACROS_HELO', `{tls_version}, {cipher}, {cipher_bits}, {cert_subject}, {cert_issuer}')
define(`confMILTER_MACROS_ENVFROM', `i, {auth_type}, {auth_authen}, {auth_ssf}, {auth_author}, {mail_mailer}, {mail_host}, {mail_addr}')
define(`confMILTER_MACROS_ENVRCPT', `{rcpt_mailer}, {rcpt_host}, {rcpt_addr}')

# After adding these lines:
# 1. cd /etc/mail
# 2. make
# 3. make restart
# 
# Or use the FreeBSD-specific commands:
# 1. cd /etc/mail
# 2. make all install
# 3. service sendmail restart
