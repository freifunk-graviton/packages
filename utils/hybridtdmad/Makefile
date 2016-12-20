include $(TOPDIR)/rules.mk

PKG_NAME:=hybridtdmad
PKG_VERSION:=1
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/hybridtdmad
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Hybrid TDMA userspace program and daemon
  DEPENDS:=+zmq +lzmq +libevent2 +libnl-tiny +lua +liblua +uclibcxx
endef

define Package/hybridtdmad/description
	Hybrid TDMA userspace program based on hMAC
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/Compile
	CFLAGS="$(TARGET_CFLAGS)" CPPFLAGS="$(TARGET_CPPFLAGS)" $(MAKE) -C $(PKG_BUILD_DIR) $(TARGET_CONFIGURE_OPTS)
endef

define Package/hybridtdmad/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hybridtdma $(1)/bin/
	$(CP) ./files/* $(1)/
endef

$(eval $(call BuildPackage,hybridtdmad))