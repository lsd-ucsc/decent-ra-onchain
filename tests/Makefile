MODULE_NAME := tests
CONTRACTS   := \
	HelloWorldApp

MKFILE_PATH  := $(abspath $(lastword $(MAKEFILE_LIST)))
CURRENT_DIR  := $(dir $(MKFILE_PATH))
SOLC_BIN     := $(CURRENT_DIR)/../build/solc-static-linux
OPTIMIZE_RUN := 500
CHECKSUM_BIN := openssl sha256


all: $(CONTRACTS) checksums


$(SOLC_BIN):
	$(MAKE) -C .. solc_bin


../build/$(MODULE_NAME)/%.bin: %.sol $(SOLC_BIN)
	( \
		$(SOLC_BIN) --optimize --optimize-runs $(OPTIMIZE_RUN) \
					--revert-strings strip \
					--via-ir \
					--overwrite \
					--bin \
					--include-path node_modules/ --base-path .. \
					--output-dir ../build/$(MODULE_NAME)/all/ \
					$< && \
		cp  ../build/$(MODULE_NAME)/all/$(basename $<).bin \
			../build/$(MODULE_NAME)/$(basename $<).bin \
	)


../build/$(MODULE_NAME)/%.abi: %.sol $(SOLC_BIN)
	( \
		$(SOLC_BIN) --optimize --optimize-runs $(OPTIMIZE_RUN) \
					--revert-strings strip \
					--via-ir \
					--overwrite \
					--abi \
					--include-path node_modules/ --base-path .. \
					--output-dir ../build/$(MODULE_NAME)/all/ \
					$< && \
		cp  ../build/$(MODULE_NAME)/all/$(basename $<).abi \
			../build/$(MODULE_NAME)/$(basename $<).abi \
	)


$(CONTRACTS): %: ../build/$(MODULE_NAME)/%.abi ../build/$(MODULE_NAME)/%.bin


../build/$(MODULE_NAME)/checksums.txt: $(CONTRACTS)
	( \
		cd ../build/$(MODULE_NAME); \
		$(CHECKSUM_BIN) $(addsuffix .abi,$(CONTRACTS)) $(addsuffix .bin,$(CONTRACTS)) > checksums.txt; \
	)


checksums: ../build/$(MODULE_NAME)/checksums.txt


clean:
	rm -rf ../build/$(MODULE_NAME)/


.PHONY: all clean checksums $(CONTRACTS)
