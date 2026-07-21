FROM nginx:alpine
# Templates in /etc/nginx/templates/*.template are passed through envsubst
# at container start (output -> /etc/nginx/conf.d/).
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY index.html admin.html chat.html netflow.html blocked.html monitored.html agent.html agent-workflow.html firewalls.html firewall-anomalies.html endpoints.html hosts.html honeypot.html email.html o365.html osint.html stats.html dossier.html /usr/share/nginx/html/
COPY css/ /usr/share/nginx/html/css/
COPY js/ /usr/share/nginx/html/js/
COPY i18n/ /usr/share/nginx/html/i18n/
COPY docs/ /usr/share/nginx/html/docs/
