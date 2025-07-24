# Example sendmail.mc configuration for FOFF milter
# Add this line to your /etc/mail/sendmail.mc file

# FOFF milter configuration
INPUT_MAIL_FILTER(`foff-milter', `S=unix:/var/run/foff-milter.sock, F=5, T=S:30s;R:30s')

# Optional: Set milter default action (what to do if milter fails)
# accept = accept mail if milter fails (recommended for production)
# tempfail = temporary failure if milter fails
# reject = reject mail if milter fails
define(`confMILTER_MACROS_CONNECT', `j, _, {daemon_name}, {if_name}, {if_addr}')
define(`confMILTER_MACROS_HELO', `{tls_version}, {cipher}, {cipher_bits}, {cert_subject}, {cert_issuer}')
define(`confMILTER_MACROS_ENVFROM', `i, {auth_type}, {auth_authen}, {auth_ssf}, {auth_author}, {mail_mailer}, {mail_host}, {mail_addr}')
define(`confMILTER_MACROS_ENVRCPT', `{rcpt_mailer}, {rcpt_host}, {rcpt_addr}')

# The F=5 flag enables header modifications (add/change headers)
# F=1 = add headers, F=4 = change headers, F=5 = both

# After adding this, rebuild sendmail configuration:
# sudo make -C /etc/mail
# sudo systemctl restart sendmail
