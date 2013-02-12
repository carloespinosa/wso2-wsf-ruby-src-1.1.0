#!/usr/bin/env ruby

require "rbconfig"

puts ::RbConfig::CONFIG["WSFC_HOME"].to_s
