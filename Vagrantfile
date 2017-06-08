# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/trusty64"
  config.vm.provision :shell, path: "vagrant_setup/bootstrap.sh"
  config.vm.hostname = "advisordd"
  config.vm.network :forwarded_port, host:4567, guest: 80
  config.vm.network :forwarded_port, host:3306, guest: 3306
end
