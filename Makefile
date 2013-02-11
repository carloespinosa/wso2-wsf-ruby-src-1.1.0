
SHELL = /bin/sh

# V=0 quiet, V=1 verbose.  other values don't work.
V = 0
Q1 = $(V:1=)
Q = $(Q1:0=@)
n=$(NULLCMD)
ECHO1 = $(V:1=@$n)
ECHO = $(ECHO1:0=@echo)

#### Start of system configuration section. ####

srcdir = .
topdir = /Users/carloespinosa/.rvm/rubies/ruby-1.9.3-p0/include/ruby-1.9.1
hdrdir = /Users/carloespinosa/.rvm/rubies/ruby-1.9.3-p0/include/ruby-1.9.1
arch_hdrdir = /Users/carloespinosa/.rvm/rubies/ruby-1.9.3-p0/include/ruby-1.9.1/$(arch)
VPATH = $(srcdir):$(arch_hdrdir)/ruby:$(hdrdir)/ruby
prefix = $(DESTDIR)/Users/carloespinosa/.rvm/rubies/ruby-1.9.3-p0
rubylibprefix = $(libdir)/$(RUBY_BASE_NAME)
exec_prefix = $(prefix)
vendorhdrdir = $(rubyhdrdir)/vendor_ruby
sitehdrdir = $(rubyhdrdir)/site_ruby
rubyhdrdir = $(includedir)/$(RUBY_BASE_NAME)-$(ruby_version)
vendordir = $(rubylibprefix)/vendor_ruby
sitedir = $(rubylibprefix)/site_ruby
ridir = $(datarootdir)/$(RI_BASE_NAME)
mandir = $(datarootdir)/man
localedir = $(datarootdir)/locale
libdir = $(exec_prefix)/lib
psdir = $(docdir)
pdfdir = $(docdir)
dvidir = $(docdir)
htmldir = $(docdir)
infodir = $(datarootdir)/info
docdir = $(datarootdir)/doc/$(PACKAGE)
oldincludedir = $(DESTDIR)/usr/include
includedir = $(prefix)/include
localstatedir = $(prefix)/var
sharedstatedir = $(prefix)/com
sysconfdir = $(prefix)/etc
datadir = $(datarootdir)
datarootdir = $(prefix)/share
libexecdir = $(exec_prefix)/libexec
sbindir = $(exec_prefix)/sbin
bindir = $(exec_prefix)/bin
rubylibdir = $(rubylibprefix)/$(ruby_version)
archdir = $(rubylibdir)/$(arch)
sitelibdir = $(sitedir)/$(ruby_version)
sitearchdir = $(sitelibdir)/$(sitearch)
vendorlibdir = $(vendordir)/$(ruby_version)
vendorarchdir = $(vendorlibdir)/$(sitearch)

NULLCMD = :

CC = clang
CXX = clang++
LIBRUBY = $(LIBRUBY_SO)
LIBRUBY_A = lib$(RUBY_SO_NAME)-static.a
LIBRUBYARG_SHARED = -l$(RUBY_SO_NAME)
LIBRUBYARG_STATIC = -l$(RUBY_SO_NAME)-static
OUTFLAG = -o 
COUTFLAG = -o 

RUBY_EXTCONF_H = 
cflags   =  $(optflags) $(debugflags) $(warnflags)
optflags = -O3
debugflags = -ggdb
warnflags = -Wextra -Wno-unused-parameter -Wno-parentheses -Wno-long-long -Wno-missing-field-initializers -Wpointer-arith -Wwrite-strings -Wdeclaration-after-statement -Wshorten-64-to-32 -Wimplicit-function-declaration
CFLAGS   = -fno-common $(cflags)  -fno-common -pipe 
INCFLAGS = -I. -I$(arch_hdrdir) -I$(hdrdir)/ruby/backward -I$(hdrdir) -I$(srcdir)
DEFS     = 
CPPFLAGS =  -I/opt/wso2/wsf_c/include/rampart-1.3.0 -I/opt/wso2/wsf_c/include/axis2-1.6.0 -I./wsdlc/include -I/Users/carloespinosa/.rvm/usr/include -D_XOPEN_SOURCE -D_DARWIN_C_SOURCE $(DEFS) $(cppflags)
CXXFLAGS = $(CFLAGS) $(cxxflags)
ldflags  = -L. 
dldflags = -Wl,-undefined,dynamic_lookup -Wl,-multiply_defined,suppress -Wl,-flat_namespace
ARCH_FLAG = 
DLDFLAGS = $(ldflags) $(dldflags)
LDSHARED = $(CC) -dynamic -bundle
LDSHAREDXX = $(CXX) -dynamic -bundle
AR = ar
EXEEXT = 

RUBY_BASE_NAME = ruby
RUBY_INSTALL_NAME = ruby
RUBY_SO_NAME = ruby.1.9.1
arch = x86_64-darwin11.2.0
sitearch = $(arch)
ruby_version = 1.9.1
ruby = /Users/carloespinosa/.rvm/rubies/ruby-1.9.3-p0/bin/ruby
RUBY = $(ruby)
RM = rm -f
RM_RF = $(RUBY) -run -e rm -- -rf
RMDIRS = rmdir -p
MAKEDIRS = mkdir -p
INSTALL = /usr/bin/install -c
INSTALL_PROG = $(INSTALL) -m 0755
INSTALL_DATA = $(INSTALL) -m 644
COPY = cp

#### End of system configuration section. ####

preload = 

libpath = . $(libdir) /opt/wso2/wsf_c/modules/rampart /opt/wso2/wsf_c/lib ./wsdlc/lib /Users/carloespinosa/.rvm/usr/lib
LIBPATH =  -L. -L$(libdir) -L/opt/wso2/wsf_c/modules/rampart -L/opt/wso2/wsf_c/lib -L./wsdlc/lib -L/Users/carloespinosa/.rvm/usr/lib
DEFFILE = 

CLEANFILES = mkmf.log
DISTCLEANFILES = 
DISTCLEANDIRS = 

extout = 
extout_prefix = 
target_prefix = 
LOCAL_LIBS = 
LIBS = $(LIBRUBYARG_SHARED) -lsandesha2_client -lmod_rampart -lneethi_util -lneethi -laxis2_http_receiver -laxis2_http_sender -laxis2_http_common -laxis2_engine -laxis2_parser -laxutil -laxis2_axiom  -lpthread -ldl -lobjc 
SRCS = WSFC_wrapper.c
OBJS = WSFC_wrapper.o
TARGET = WSFC
DLLIB = $(TARGET).bundle
EXTSTATIC = 
STATIC_LIB = 

BINDIR        = $(bindir)
RUBYCOMMONDIR = $(sitedir)$(target_prefix)
RUBYLIBDIR    = $(sitelibdir)$(target_prefix)
RUBYARCHDIR   = $(sitearchdir)$(target_prefix)
HDRDIR        = $(rubyhdrdir)/ruby$(target_prefix)
ARCHHDRDIR    = $(rubyhdrdir)/$(arch)/ruby$(target_prefix)

TARGET_SO     = $(DLLIB)
CLEANLIBS     = $(TARGET).bundle 
CLEANOBJS     = *.o  *.bak

all:    $(DLLIB)
static: $(STATIC_LIB)
.PHONY: all install static install-so install-rb
.PHONY: clean clean-so clean-rb

clean-rb-default::
clean-rb::
clean-so::
clean: clean-so clean-rb-default clean-rb
		@-$(RM) $(CLEANLIBS) $(CLEANOBJS) $(CLEANFILES)

distclean-rb-default::
distclean-rb::
distclean-so::
distclean: clean distclean-so distclean-rb-default distclean-rb
		@-$(RM) Makefile $(RUBY_EXTCONF_H) conftest.* mkmf.log
		@-$(RM) core ruby$(EXEEXT) *~ $(DISTCLEANFILES)
		@-$(RMDIRS) $(DISTCLEANDIRS) 2> /dev/null || true

realclean: distclean
install: install-so install-rb

install-so: $(RUBYARCHDIR)
install-so: $(RUBYARCHDIR)/$(DLLIB)
$(RUBYARCHDIR)/$(DLLIB): $(DLLIB)
	@-$(MAKEDIRS) $(@D)
	$(INSTALL_PROG) $(DLLIB) $(@D)
install-rb: pre-install-rb install-rb-default
install-rb-default: pre-install-rb-default
pre-install-rb: Makefile
pre-install-rb-default: Makefile
pre-install-rb-default: $(RUBYLIBDIR)/config
install-rb-default: $(RUBYLIBDIR)/config/wsconfig.rb $(RUBYLIBDIR)/config
$(RUBYLIBDIR)/config/wsconfig.rb: $(srcdir)/lib/config/wsconfig.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/config/wsconfig.rb $(@D)
pre-install-rb-default: $(RUBYLIBDIR)/logger
install-rb-default: $(RUBYLIBDIR)/logger/wslogger.rb $(RUBYLIBDIR)/logger
$(RUBYLIBDIR)/logger/wslogger.rb: $(srcdir)/lib/logger/wslogger.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/logger/wslogger.rb $(@D)
pre-install-rb-default: $(RUBYLIBDIR)/util
install-rb-default: $(RUBYLIBDIR)/util/wsutil.rb $(RUBYLIBDIR)/util
$(RUBYLIBDIR)/util/wsutil.rb: $(srcdir)/lib/util/wsutil.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/util/wsutil.rb $(@D)
pre-install-rb-default: $(RUBYLIBDIR)/wsdl
install-rb-default: $(RUBYLIBDIR)/wsdl/ws_wsdl_binding.rb $(RUBYLIBDIR)/wsdl
$(RUBYLIBDIR)/wsdl/ws_wsdl_binding.rb: $(srcdir)/lib/wsdl/ws_wsdl_binding.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/wsdl/ws_wsdl_binding.rb $(@D)
install-rb-default: $(RUBYLIBDIR)/wsdl/ws_wsdl_constants.rb $(RUBYLIBDIR)/wsdl
$(RUBYLIBDIR)/wsdl/ws_wsdl_constants.rb: $(srcdir)/lib/wsdl/ws_wsdl_constants.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/wsdl/ws_wsdl_constants.rb $(@D)
install-rb-default: $(RUBYLIBDIR)/wsdl/ws_wsdl_creator.rb $(RUBYLIBDIR)/wsdl
$(RUBYLIBDIR)/wsdl/ws_wsdl_creator.rb: $(srcdir)/lib/wsdl/ws_wsdl_creator.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/wsdl/ws_wsdl_creator.rb $(@D)
install-rb-default: $(RUBYLIBDIR)/wsdl/ws_wsdl_interface.rb $(RUBYLIBDIR)/wsdl
$(RUBYLIBDIR)/wsdl/ws_wsdl_interface.rb: $(srcdir)/lib/wsdl/ws_wsdl_interface.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/wsdl/ws_wsdl_interface.rb $(@D)
install-rb-default: $(RUBYLIBDIR)/wsdl/ws_wsdl_message.rb $(RUBYLIBDIR)/wsdl
$(RUBYLIBDIR)/wsdl/ws_wsdl_message.rb: $(srcdir)/lib/wsdl/ws_wsdl_message.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/wsdl/ws_wsdl_message.rb $(@D)
install-rb-default: $(RUBYLIBDIR)/wsdl/ws_wsdl_operations.rb $(RUBYLIBDIR)/wsdl
$(RUBYLIBDIR)/wsdl/ws_wsdl_operations.rb: $(srcdir)/lib/wsdl/ws_wsdl_operations.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/wsdl/ws_wsdl_operations.rb $(@D)
install-rb-default: $(RUBYLIBDIR)/wsdl/ws_wsdl_port.rb $(RUBYLIBDIR)/wsdl
$(RUBYLIBDIR)/wsdl/ws_wsdl_port.rb: $(srcdir)/lib/wsdl/ws_wsdl_port.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/wsdl/ws_wsdl_port.rb $(@D)
install-rb-default: $(RUBYLIBDIR)/wsdl/ws_wsdl_proxy.rb $(RUBYLIBDIR)/wsdl
$(RUBYLIBDIR)/wsdl/ws_wsdl_proxy.rb: $(srcdir)/lib/wsdl/ws_wsdl_proxy.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/wsdl/ws_wsdl_proxy.rb $(@D)
install-rb-default: $(RUBYLIBDIR)/wsdl/ws_wsdl_service.rb $(RUBYLIBDIR)/wsdl
$(RUBYLIBDIR)/wsdl/ws_wsdl_service.rb: $(srcdir)/lib/wsdl/ws_wsdl_service.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/wsdl/ws_wsdl_service.rb $(@D)
install-rb-default: $(RUBYLIBDIR)/wsdl/ws_wsdl_types.rb $(RUBYLIBDIR)/wsdl
$(RUBYLIBDIR)/wsdl/ws_wsdl_types.rb: $(srcdir)/lib/wsdl/ws_wsdl_types.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/wsdl/ws_wsdl_types.rb $(@D)
pre-install-rb-default: $(RUBYLIBDIR)/wsf
install-rb-default: $(RUBYLIBDIR)/wsf/wsclient.rb $(RUBYLIBDIR)/wsf
$(RUBYLIBDIR)/wsf/wsclient.rb: $(srcdir)/lib/wsf/wsclient.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/wsf/wsclient.rb $(@D)
install-rb-default: $(RUBYLIBDIR)/wsf/wsfault.rb $(RUBYLIBDIR)/wsf
$(RUBYLIBDIR)/wsf/wsfault.rb: $(srcdir)/lib/wsf/wsfault.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/wsf/wsfault.rb $(@D)
install-rb-default: $(RUBYLIBDIR)/wsf/wsmessage.rb $(RUBYLIBDIR)/wsf
$(RUBYLIBDIR)/wsf/wsmessage.rb: $(srcdir)/lib/wsf/wsmessage.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/wsf/wsmessage.rb $(@D)
install-rb-default: $(RUBYLIBDIR)/wsf/wspolicy.rb $(RUBYLIBDIR)/wsf
$(RUBYLIBDIR)/wsf/wspolicy.rb: $(srcdir)/lib/wsf/wspolicy.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/wsf/wspolicy.rb $(@D)
install-rb-default: $(RUBYLIBDIR)/wsf/wssecuritytoken.rb $(RUBYLIBDIR)/wsf
$(RUBYLIBDIR)/wsf/wssecuritytoken.rb: $(srcdir)/lib/wsf/wssecuritytoken.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/wsf/wssecuritytoken.rb $(@D)
pre-install-rb-default: $(RUBYLIBDIR)
install-rb-default: $(RUBYLIBDIR)/wsf.rb $(RUBYLIBDIR)
$(RUBYLIBDIR)/wsf.rb: $(srcdir)/lib/wsf.rb
	$(Q) $(INSTALL_DATA) $(srcdir)/lib/wsf.rb $(@D)
pre-install-rb-default:
	$(ECHO) installing default WSFC libraries
$(RUBYARCHDIR):
	$(Q) $(MAKEDIRS) $@
$(RUBYLIBDIR)/config:
	$(Q) $(MAKEDIRS) $@
$(RUBYLIBDIR)/logger:
	$(Q) $(MAKEDIRS) $@
$(RUBYLIBDIR)/util:
	$(Q) $(MAKEDIRS) $@
$(RUBYLIBDIR)/wsdl:
	$(Q) $(MAKEDIRS) $@
$(RUBYLIBDIR)/wsf:
	$(Q) $(MAKEDIRS) $@
$(RUBYLIBDIR):
	$(Q) $(MAKEDIRS) $@

site-install: site-install-so site-install-rb
site-install-so: install-so
site-install-rb: install-rb

.SUFFIXES: .c .m .cc .mm .cxx .cpp .C .o

.cc.o:
	$(ECHO) compiling $(<)
	$(Q) $(CXX) $(INCFLAGS) $(CPPFLAGS) $(CXXFLAGS) $(COUTFLAG)$@ -c $<

.mm.o:
	$(ECHO) compiling $(<)
	$(Q) $(CXX) $(INCFLAGS) $(CPPFLAGS) $(CXXFLAGS) $(COUTFLAG)$@ -c $<

.cxx.o:
	$(ECHO) compiling $(<)
	$(Q) $(CXX) $(INCFLAGS) $(CPPFLAGS) $(CXXFLAGS) $(COUTFLAG)$@ -c $<

.cpp.o:
	$(ECHO) compiling $(<)
	$(Q) $(CXX) $(INCFLAGS) $(CPPFLAGS) $(CXXFLAGS) $(COUTFLAG)$@ -c $<

.C.o:
	$(ECHO) compiling $(<)
	$(Q) $(CXX) $(INCFLAGS) $(CPPFLAGS) $(CXXFLAGS) $(COUTFLAG)$@ -c $<

.c.o:
	$(ECHO) compiling $(<)
	$(Q) $(CC) $(INCFLAGS) $(CPPFLAGS) $(CFLAGS) $(COUTFLAG)$@ -c $<

.m.o:
	$(ECHO) compiling $(<)
	$(Q) $(CC) $(INCFLAGS) $(CPPFLAGS) $(CFLAGS) $(COUTFLAG)$@ -c $<

$(DLLIB): $(OBJS) Makefile
	$(ECHO) linking shared-object $(DLLIB)
	@-$(RM) $(@)
	$(Q) $(LDSHARED) -o $@ $(OBJS) $(LIBPATH) $(DLDFLAGS) $(LOCAL_LIBS) $(LIBS)



$(OBJS): $(hdrdir)/ruby.h $(hdrdir)/ruby/defines.h $(arch_hdrdir)/ruby/config.h
