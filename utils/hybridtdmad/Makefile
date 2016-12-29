include $(TOPDIR)/rules.mk

PKG_NAME:=hybridtdmad
PKG_VERSION:=1
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

PKG_FIXUP:=libtool-ucxx

include $(INCLUDE_DIR)/uclibc++.mk
include $(INCLUDE_DIR)/package.mk

MAKE_FLAGS += DEBUG=1 LIBNL=tiny

define Package/hybridtdmad
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Hybrid TDMA
  DEPENDS:=+lzmq +libzmq-nc +libevent2 +libnl-tiny +libpthread +lua +liblua $(CXX_DEPENDS)
endef

define Package/hybridtdmad/description
	Hybrid TDMA userspace configuration utility and daemon
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/Compile
	CFLAGS="$(TARGET_CFLAGS)" \
	CPPFLAGS="$(TARGET_CPPFLAGS)" \
	$(MAKE) -C $(PKG_BUILD_DIR) $(TARGET_CONFIGURE_OPTS)
endef

define Package/hybridtdmad/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hybridtdma $(1)/bin/
	$(CP) ./files/* $(1)/
endef

$(eval $(call BuildPackage,hybridtdmad))
