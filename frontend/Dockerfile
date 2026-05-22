FROM nginx:alpine
# Templates in /etc/nginx/templates/*.template are passed through envsubst
# at container start (output -> /etc/nginx/conf.d/).
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY index.html admin.html netflow.html /usr/share/nginx/html/
COPY css/ /usr/share/nginx/html/css/
COPY js/ /usr/share/nginx/html/js/
