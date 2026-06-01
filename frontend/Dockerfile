FROM nginx:alpine
# Templates in /etc/nginx/templates/*.template are passed through envsubst
# at container start (output -> /etc/nginx/conf.d/).
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY index.html admin.html netflow.html blocked.html agent.html agent-workflow.html firewalls.html endpoints.html email.html osint.html stats.html /usr/share/nginx/html/
COPY css/ /usr/share/nginx/html/css/
COPY js/ /usr/share/nginx/html/js/
COPY docs/ /usr/share/nginx/html/docs/
