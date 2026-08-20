package=liboqs
$(package)_version=0.12.0
$(package)_download_path=https://github.com/open-quantum-safe/liboqs/archive/refs/tags/
$(package)_file_name=$($(package)_version).tar.gz
$(package)_sha256_hash=df999915204eb1eba311d89e83d1edd3a514d5a07374745d6a9e5b2dd0d59c08
$(package)_dependencies=
$(package)_patches=
$(package)_build_subdir=build

define $(package)_set_vars
  $(package)_config_opts=-DOQS_BUILD_ONLY_LIB=ON
  $(package)_config_opts+=-DOQS_MINIMAL_BUILD="SIG_ml_dsa_44"
  $(package)_config_opts+=-DOQS_USE_OPENSSL=OFF
  $(package)_config_opts+=-DBUILD_SHARED_LIBS=OFF
  $(package)_config_opts+=-DOQS_DIST_BUILD=ON
  $(package)_config_opts_arm=-DCMAKE_SYSTEM_PROCESSOR=armv7
  $(package)_config_opts_x86_64=-DCMAKE_SYSTEM_PROCESSOR=x86_64
endef

define $(package)_preprocess_cmds
  mkdir -p build
endef

define $(package)_config_cmds
  $($(package)_cmake) .. $($(package)_config_opts)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
