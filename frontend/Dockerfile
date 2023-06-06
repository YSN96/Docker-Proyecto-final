FROM ubuntu/apache2
WORKDIR /home
RUN chmod 755 /var/www/html
RUN a2enmod rewrite
RUN service apache2 restart

