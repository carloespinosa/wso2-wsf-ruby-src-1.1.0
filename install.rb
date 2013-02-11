#!/usr/bin/env ruby

require 'find'
require 'rbconfig'
require 'fileutils'

def install_rb_lib_folder(src_dir, sub_dir, site_lib_dir)
  Dir.glob(File.join(src_dir + sub_dir,"*.rb")).each do |i|
        FileUtils.mkdir(site_lib_dir + sub_dir) unless FileTest.exist?(site_lib_dir + sub_dir) && FileTest.directory?(site_lib_dir + sub_dir)
        FileUtils.install(i,site_lib_dir + sub_dir,:preserve=>true, :mode=>0644,:verbose=>true)
  end
end

def install_rb_lib_files(src_dir, site_lib_dir)
      Dir.glob(File.join(src_dir,"*.rb")).each do |i|
        FileUtils.install(i,site_lib_dir,:preserve=>true, :mode=>0644,:verbose=>true)
      end
end
    
begin
    site_arch_dir = Config::CONFIG['sitearchdir']
    site_lib_dir = Config::CONFIG['sitelibdir']

    # install wsf.rb
    install_rb_lib_files("lib", site_lib_dir)
    
    # install wsf stuff
    install_rb_lib_folder("lib", "/wsf", site_lib_dir)
    install_rb_lib_folder("lib", "/config", site_lib_dir)
    install_rb_lib_folder("lib", "/logger", site_lib_dir)
    install_rb_lib_folder("lib", "/util", site_lib_dir)
    install_rb_lib_folder("lib", "/wsdl", site_lib_dir)

    FileUtils.install('WSFC.bundle', File.join(site_arch_dir,'WSFC.bundle'), :mode=>0755, :verbose=>true)
    FileUtils.install('wsservice/wsservice.bundle', File.join(site_arch_dir,'wsservice.bundle'), :mode=>0755, :verbose=>true)
end

