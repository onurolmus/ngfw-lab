Vagrant.configure("2") do |config|
  config.vm.box = "ngfw-rocky9"
  config.vm.box_check_update = false
  config.vm.synced_folder ".", "/vagrant", disabled: true
  config.vm.boot_timeout = 600

  config.vm.define "ngfw" do |ngfw|
    ngfw.vm.hostname = "ngfw"

    # Management
    ngfw.vm.network "private_network",
                    ip: "192.168.60.10"

    # WAN
    ngfw.vm.network "private_network",
                    ip: "10.10.10.1",
                    virtualbox__intnet: "ngfw-wan"

    # LAN
    ngfw.vm.network "private_network",
                    ip: "192.168.50.1",
                    virtualbox__intnet: "ngfw-lan"

    ngfw.vm.provider "virtualbox" do |vb|
      vb.name = "ngfw-lab-firewall"
      vb.memory = 3072
      vb.cpus = 2
      vb.gui = false
    end
  end

  config.vm.define "internet-sim" do |internet|
    internet.vm.hostname = "internet-sim"

    # WAN
    internet.vm.network "private_network",
                        ip: "10.10.10.10",
                        virtualbox__intnet: "ngfw-wan"

    internet.vm.provider "virtualbox" do |vb|
      vb.name = "ngfw-lab-internet-sim"
      vb.memory = 1024
      vb.cpus = 1
      vb.gui = false
    end
  end

  config.vm.define "lan-client" do |lan|
    lan.vm.hostname = "lan-client"

    # LAN
    lan.vm.network "private_network",
                   ip: "192.168.50.10",
                   virtualbox__intnet: "ngfw-lan"

    lan.vm.provider "virtualbox" do |vb|
      vb.name = "ngfw-lab-lan-client"
      vb.memory = 1024
      vb.cpus = 1
      vb.gui = false
    end
  end
end
