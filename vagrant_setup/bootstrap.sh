#!/usr/bin/env bash

echo "Installing project dependencies..."
apt-get update
apt-get install -fy apache2 libapache2-mod-wsgi python python-dev python-pip python-mysqldb build-essential libssl-dev libffi-dev ruby
export DEBIAN_FRONTEND=noninteractive
apt-get -q -y install mysql-server
gem install sass

echo "Symlinking /var/www..."
if ! [ -L /var/www ]; then
  rm -rf /var/www
  ln -fs /vagrant /var/www
fi

echo "Installing Python libraries..."
pip install -r /var/www/requirements.txt

echo "Setting up MySQL..."
mysql -u root < /var/www/vagrant_setup/setup.sql

echo "Updating MySQL config to allow external connections..."
sudo sed -i "s/bind-address.*/bind-address = 0.0.0.0/" /etc/mysql/my.cnf
sudo service mysql restart

echo "Importing MySQL sample data..."
mysql -u root < /var/www/vagrant_setup/sample_data.sql

echo "Setting up Apache..."
chmod 777 /var/www/site.wsgi
cp /var/www/vagrant_setup/apache.conf /etc/apache2/sites-available/
a2ensite apache.conf
service apache2 reload
