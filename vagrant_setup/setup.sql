DROP DATABASE IF EXISTS frrm;
CREATE DATABASE frrm;

DELETE FROM mysql.user WHERE Host='localhost' AND User='frrm';
GRANT ALL PRIVILEGES ON *.* TO 'frrm'@'localhost' IDENTIFIED BY 'bdenm94JgAnwxeJW';
DELETE FROM mysql.user WHERE Host='localhost' AND User='vagrant';
GRANT ALL PRIVILEGES ON *.* TO 'vagrant'@'%' IDENTIFIED BY 'vagrant' WITH GRANT OPTION;
FLUSH PRIVILEGES;
