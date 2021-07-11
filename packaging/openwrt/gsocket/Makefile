# https://gsocket.io

include $(TOPDIR)/rules.mk

PKG_NAME:=gsocket
PKG_VERSION:=1.4.33
PKG_RELEASE:=1

#PKG_LICENSE:=BSD-2-Clause
#PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

# PKG_SOURCE_PROTO:=git
# PKG_SOURCE_URL:=https://github.com/hackerschoice/gsocket.git
# PKG_SOURCE_VERSION:=98a85e270c8ee5757134f00636a5358432cd3d83

# Direct file download
PKG_SOURCE_URL:=https://github.com/hackerschoice/gsocket/releases/download/v$(PKG_VERSION)/
PKG_HASH:=5bbc850a274b933a4e8b0ac7d5bc8b0527c3eddbaee7f8a9389c284f27a6fe14

# For testing copy to openwrt/dl
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz

# dont need 'make install'
#PKG_INSTALL:=1

PKG_MAINTAINER:=skyper <skyper@thc.org>

include $(INCLUDE_DIR)/package.mk

define Package/gsocket
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libopenssl
  TITLE:=Connect like there is no firewall
  URL:=https://gsocket.io
endef

define Package/gsocket/description
  Connect like there is no firewall
endef

define Build/Configure
 $(call Build/Configure/Default,--with-linux-headers=$(LINUX_DIR) --libdir=$(STAGING_DIR)/usr/lib --includedir=$(STAGING_DIR)/usr/include)
endef
#  $(call Build/Configure/Default,--with-linux-headers=$(LINUX_DIR))

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
	LD="$(TARGET_CXX)" \
	all
endef

define Package/gsocket/install
	$(INSTALL_DIR)	$(1)/bin
	$(INSTALL_DIR)	$(1)/share/gsocket
	$(INSTALL_DIR)	$(1)/lib
	$(INSTALL_DIR)	$(1)/etc
	$(INSTALL_BIN)	$(PKG_BUILD_DIR)/tools/gs-sftp			$(1)/bin/
	$(INSTALL_BIN)	$(PKG_BUILD_DIR)/tools/gs-mount			$(1)/bin/
	$(INSTALL_BIN)	$(PKG_BUILD_DIR)/tools/blitz				$(1)/bin/
	$(INSTALL_BIN)	$(PKG_BUILD_DIR)/tools/gsocket			$(1)/bin/
	$(INSTALL_BIN)	$(PKG_BUILD_DIR)/tools/gs-netcat		$(1)/bin/
	$(INSTALL_BIN)	$(PKG_BUILD_DIR)/tools/gs_funcs			$(1)/share/gsocket/
	$(INSTALL_BIN)	$(PKG_BUILD_DIR)/tools/gsocket_uchroot_dso.so.0		$(1)/lib/
	$(INSTALL_BIN)	$(PKG_BUILD_DIR)/tools/gsocket_dso.so.0						$(1)/lib/
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/tools/gsocket.conf								$(1)/etc/
endef

$(eval $(call BuildPackage,gsocket))
