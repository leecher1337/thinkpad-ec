#
# Infrastructure to manage patching thinkpad EC firmware
#
# Copyright (C) 2016-2019 Hamish Coleman
#

all:    list_laptops
	$(info See README file for additional details)
	$(info )

.PHONY: all

QEMU_OPTIONS ?= -enable-kvm

# FIXME - the date should be the date of the last commit, unless the repo is
# dirty, in which case, it should be the date of the last change.
GITVERSION = $(shell git describe --dirty --abbrev=6 ) ($(shell date +%Y%m%d))
BUILDINFO = $(GITVERSION) $(MAKECMDGOALS)

LIST_PATCHED = $(basename $(shell grep ^patched Descriptions.txt |cut -d" " -f1))

list_laptops:
	$(info )
	$(info The following make targets are the supported usb images:)
	$(info )
	@for i in $(LIST_PATCHED); do \
            echo "$$i.img\t- `scripts/describe $$i.iso`"; \
	done
	@echo

.PHONY: list_laptops

DEPSDIR := .d
$(shell mkdir -p $(DEPSDIR))

test: $(addsuffix .iso,$(LIST_PATCHED)) $(addsuffix .img,$(LIST_PATCHED))

ALL_IMG_ORIG := $(addsuffix .orig,$(shell grep rule:IMG Descriptions.txt |cut -d" " -f1))
test.img.orig: $(ALL_IMG_ORIG)

.PHONY: test.pgm
test.pgm: $(addsuffix .pgm,$(ALL_IMG_ORIG))

# Generate a useful report
test.report:
	@echo
	@echo Report summaries for generated images:
	@echo
	@for i in $(LIST_PATCHED); do \
	    echo "Report for $$i\t- `scripts/describe $$i.iso`"; \
	    cat $$i.iso.report; \
	    echo; \
	    echo; \
	done
	@echo Checksums for generated images:
	@echo
	@sha256sum *.iso *.img

# TODO
# - add tests for the non xx30 supported things

# Remove all the locally generated junk (including any patched firmware
# images) and any small downloads
clean:
	rm -f $(CLEAN_FILES) \
            patched.*.iso patched.*.img *.FL2 *.FL2.orig *.img.enc \
            *.img.enc.orig *.img.orig *.bat *.report \
            *.img \
            *.txt.orig
	rm -rf *.iso.extract *.iso.orig.extract

# Also remove the large iso images downloaded from remote servers.
really_clean: clean
	rm -f *.iso.orig .config

# TODO - whilst this could be added to the "pretty named" list, I think
# that it is more useful to use the new generated rules framework to allow
# asking for the iso image by name - in this case "g1uj25us.iso"
#patched.t430.257.iso: g1uj25us.iso
#	$(call patched_iso,$<,$@)

list_iso:
	$(info )
	$(info This list was a duplicate of the list_laptops list - please refer to that)
	$(info )
	@false

.PHONY: list_iso

# FIXME - need to automatically generate the iso image target list

list_images:
	$(info The following make targets are available to produce firmware images:)
	$(info )
	$(info $(basename $(wildcard *.d)))
	$(info )
	$(info Check the Descriptions.txt for the names of the known FL2 files)
	$(info )
	@true

.PHONY: list_images

# All the bios update iso images I have checked have had a fat16 filesystem
# embedded in a dos mbr image as the el-torito ISO payload.  Most of them
# had the same offset to this fat filesystem, so hardcode that offset here.
# FIXME:
# - checking the E330 image showed a different FAT_OFFSET, need to handle that

# The offset value is bytes in decimal.
FAT_OFFSET := 71680

# Some versions of mtools need this flag set to allow them to work with the
# dosfs images used by Lenovo - from my tests, it may be that Debian has
# applied some patch
export MTOOLS_SKIP_CHECK=1

# At least one distribution has set this value poorly for our scripts in their
# global /etc/mtools.conf file, so we set it back to the default value here.
export MTOOLS_LOWER_CASE=0

build-deps:
	apt -y install git mtools libssl-dev build-essential xorriso

#
# Radare didnt seem to let me specify the directory to store the project file,
# so this target hacks around that
#
install.radare.projects:
	mkdir -p ~/.config/radare2/projects/x220.8DHT34WW.d
	cp -fs $(PWD)/radare/x220.8DHT34WW ~/.config/radare2/projects
	mkdir -p ~/.config/radare2/projects/x230.G2HT35WW
	cp -fs $(PWD)/radare/x230.G2HT35WW ~/.config/radare2/projects/x230.G2HT35WW/rc
	mkdir -p ~/.config/radare2/projects/x260.R02HT29W.d/
	cp -fs $(PWD)/radare/x260.R02HT29W ~/.config/radare2/projects


.config:
	cp defconfig .config
include .config

PATCHES-$(CONFIG_KEYBOARD) += \
    001_keysym.patch 002_dead_keys.patch 003_keysym_replacements.patch \
    004_fn_keys.patch 005_fn_key_swap.patch

PATCHES-$(CONFIG_BATTERY) += \
    006_battery_validate.patch

# To enable other misc patches:
# - add a new CONFIG_something value to the defconfig and .config
# - add a new PATCHES-$(CONFIG_something) line referencing the patch
# - optionally, add a patch_enable/patch_disable stanza
#   - however, that will get messy quickly, so perhaps a real config target

#
# These enable and disable targets change which patches are configured to be
# applied.

patch_enable_battery:
	sed -E 's/CONFIG_BATTERY.+/CONFIG_BATTERY = y/'  --in-place .config

patch_disable_battery:
	sed -E 's/CONFIG_BATTERY.+/CONFIG_BATTERY = n/'  --in-place .config

patch_enable_keyboard:
	sed -E 's/CONFIG_KEYBOARD.+/CONFIG_KEYBOARD = y/'  --in-place .config

patch_disable_keyboard:
	sed -E 's/CONFIG_KEYBOARD.+/CONFIG_KEYBOARD = n/'  --in-place .config


# TODO - the scripts/describe output depends on Descriptions.txt -
# could parse that file and create some deps

#
# Download any ISO image that we have a checksum for
# NOTE: makes an assumption about the Lenovo URL not changing
.PRECIOUS: %.iso.orig
%.iso.orig:
	@echo -n "Downloading "
	@scripts/describe $(basename $@)
	@wget -nv -O $@ https://download.lenovo.com/pccbbs/mobiles/$(basename $@)
	scripts/checksum --mv_on_fail $@ $(basename $@)
	@touch $@

# Download any README text file released alongside to ISO images.
# Useful for looking up firmware versions and the changelog.
# Note that Lenovo produces two sets of release notes: *uc.txt and
# *.us.txt - the "us" ones contain instructions for using the .exe
# version of the bios update tool instead of the instructions for
# bootable cdrom image, but other than that they /should/ be identical
# NOTE: we download the one with the same name as the ISO, even if that is
# wrong (it removes a bunch of edge cases)
%.txt.orig:
	@echo -n "Downloading release notes for "
	@scripts/describe $(subst .txt.orig,.iso,$@)
	wget -O $@ https://download.lenovo.com/pccbbs/mobiles/$(basename $@)

# keep intermediate files
.PRECIOUS: %.orig
.PRECIOUS: %.img
.PRECIOUS: %.img.orig

# Generate a working file with any known patches applied
%.img: %.img.orig
	@cp --reflink=auto $< $@
	./scripts/hexpatch.pl --rm_on_fail --fail_on_missing --report $@.report $@ $(addprefix $@.d/,$(PATCHES-y))

# using both __DIR and __FL2 is a hack to get around needing to quote the
# DOS path separator.  It feels like there should be a better way if I put
# my mind to it..
#
%.iso.bat: %.iso.orig autoexec.bat.template
	@sed -e "s%__DIR%`mdir -/ -b -i $<@@$(FAT_OFFSET) |grep FL2 |head -1|cut -d/ -f3`%; s%__FL2%`mdir -/ -b -i $<@@$(FAT_OFFSET) |grep FL2 |head -1|cut -d/ -f4`%" autoexec.bat.template >$@.tmp
	@mv $@.tmp $@

# helper to write the ISO onto a cdrw
%.iso.blank_burn: %.iso
	wodim -eject -v speed=40 -tao gracetime=0 blank=fast $<

# if you want to work on more patches, you probably want the pre-patched ver
%.img.prepatch: %.img.orig
	cp --reflink=auto $< $(basename $<)

%.hex: %
	hd -v $< >$@.tmp
	mv $@.tmp $@

# Generate a patch report
%.diff: %.hex %.orig.hex
	-diff -u $(basename $@).orig.hex $(basename $@).hex >$@.tmp
	mv $@.tmp $@
	cat $@

# If we ever want a copy of the dosflash.exe, just get it from the iso image
%.dosflash.exe.orig: %.iso.orig
	mcopy -m -i $^@@$(FAT_OFFSET) ::FLASH/DOSFLASH.EXE $@

# Extract the "embedded" fat file system from a given iso.
%.iso.extract: %.iso
	mcopy -n -s -i $^@@$(FAT_OFFSET) :: $@
%.iso.orig.extract: %.iso.orig
	mcopy -n -s -i $^@@$(FAT_OFFSET) :: $@

## Use the system provided geteltorito script, if there is one
#GETELTORITO := $(shell if type geteltorito >/dev/null; then echo geteltorito; else echo ./geteltorito; fi)

# use the included geteltorito script always, since we know it does not have
# the hdd size bug
GETELTORITO := ./scripts/geteltorito

# extract the DOS boot image from an iso (and fix it up so qemu can boot it)
%.img: %.iso
	$(GETELTORITO) -o $@.tmp $<
	./scripts/fix_mbr $@.tmp
	@mv $@.tmp $@
	$(call build_info,$<)

# $1 is the base name of the ISO file built
define build_info
	@echo
	@echo
	@echo Your build has completed with the following details:
        @echo
	@echo "Built ISO: `sha1sum $1`"
	@cat $1.report
endef

# Add information about the FL2 file to the current report
# $< is the IMG file
# $@ is the FL2 file being inserted into
define buildinfo_FL2
    @echo "Buildinfo: $(BUILDINFO)" >$@.report
    @echo "Built FL2: `sha1sum $@`" >>$@.report
    @echo "" >>$@.report
    @cat $<.report >>$@.report
endef

# Add information about the ISO file to the current report
# $< is the FL2 file
# $@ is the ISO file being inserted into
define buildinfo_ISO
    @echo "Based on code from: `scripts/describe $@`" >$@.report
    @cat $<.report >>$@.report
    @echo "" >>$@.report
endef

# simple testing of images in an emulator
%.iso.test: %.iso
	qemu-system-x86_64 $(QEMU_OPTIONS) -cdrom $<

%.img.test: %.img
	qemu-system-x86_64 $(QEMU_OPTIONS) -drive index=0,media=disk,format=raw,file=$<

mec-tools/Makefile:
	@[ -e .git ] || (echo ERROR: This must be run on a git clone of the repository; false)
	git submodule update --init --remote

mec-tools/mec_encrypt: mec-tools/Makefile
	git submodule update
	make -C mec-tools

# Simple Visualisation
%.pgm: %
	(echo "P5 256 $$(($(shell stat -c %s $<)/265)) 255" ; cat $< ) > $@

# Extract the FL2 file from an ISO image
#
# Note that the integrity of the FL2 file is determined by two things:
# - The sha1sum for the ISO.orig file has been checked
# - The ./scripts/ISO_copyFL2 script is generating correct data
# We believe these two statements are correct, so there is no need to check
# the checksum for the extracted FL2.orig file
#
# $@ is the FL2 file to create
# $< is the ISO file
# $1 is the pattern to match FL2 file in ISO image
define rule_FL2_extract
    ./scripts/ISO_copyFL2 from_iso $< $@ $(1)
endef
rule_FL2_extract_DEPS = scripts/ISO_copyFL2

# Extract and decyrpt the IMG file from an FL2 file
#
# $@ is the decrypted IMG to create
# $< is the FL2
define rule_IMG_extract
    ./scripts/FL2_copyIMG from_fl2 $< $(subst .orig,.enc.tmp,$@)
    mec-tools/mec_encrypt -d $(subst .orig,.enc.tmp,$@) $@.tmp
    mec-tools/mec_csum_flasher -c $@.tmp >/dev/null
    mec-tools/mec_csum_boot -c $@.tmp >/dev/null
    @rm $(subst .orig,.enc.tmp,$@)
    @mv $@.tmp $@
endef
rule_IMG_extract_DEPS = scripts/FL2_copyIMG mec-tools/mec_encrypt mec-tools/mec_csum_flasher mec-tools/mec_csum_boot

# Create a new ISO image with patches applied
#
# $@ is the ISO to create
# $< is the FL2
# $1 is the pattern to match FL2 file in ISO image
define rule_FL2_insert
    $(call buildinfo_ISO)

    @cp --reflink=auto $@.orig $@.tmp

    @cp --reflink=auto $< $<.tmp
    @cp --reflink=auto $@.report $@.report.tmp
    @cp --reflink=auto $@.bat $@.bat.tmp
    @touch --date="1980-01-01 00:00:01Z" $<.tmp $@.report.tmp $@.bat.tmp
    @# TODO - datestamp here could be the lastcommitdatestamp

    ./scripts/ISO_copyFL2 to_iso $@.tmp $<.tmp $(1)
    mcopy -t -m -o -i $@.tmp@@$(FAT_OFFSET) $@.report.tmp ::report.txt
    mcopy -t -m -o -i $@.tmp@@$(FAT_OFFSET) $@.bat.tmp ::AUTOEXEC.BAT
    -mdel -i $@.tmp@@$(FAT_OFFSET) ::EFI/Boot/BootX64.efi
    -mattrib -i $@.tmp@@$(FAT_OFFSET) -r ::FLASH/README.TXT
    -mdel -i $@.tmp@@$(FAT_OFFSET) ::FLASH/README.TXT

    @rm $<.tmp $@.report.tmp $@.bat.tmp
    @mv $@.tmp $@
endef
rule_FL2_insert_DEPS = scripts/ISO_copyFL2 # TODO - bat file
# TODO
# - maybe mdel any FL1 files, so the image can not accidentally be used to
#   flash the BIOS?
# - only delete the UEFI updater if it exists in the original ISO
# - continue removing variables from the AUTOEXEC bat - perhaps calculate
#   its contents here
# - provide a simple mechanism for selecting the flash command to run, to
#   allow for autoexec bat files that do not use dosflash

# Insert the new firmware into the FL2 file
#
# $@ is the FL2 to create
# $< is the IMG
define rule_IMG_insert
    ./scripts/xx30.encrypt $< $<.enc.tmp
    @cp --reflink=auto $@.orig $@.tmp
    ./scripts/FL2_copyIMG to_fl2 $@.tmp $<.enc.tmp
    @rm $<.enc.tmp
    @mv $@.tmp $@
    $(call buildinfo_FL2)
endef
rule_IMG_insert_DEPS = scripts/FL2_copyIMG scripts/xx30.encrypt

# Take a built ISO file with Lenovo's name and rename it to a nice name
#
# $< is the lenovo named iso
# $@ is the nicely named iso
define rule_niceISO_extract
    cp $< $@
    cp $<.report $@.report
    $(call build_info,$@)
endef
rule_niceISO_extract_DEPS = # no extra dependancies


# Additional macros for any special cases:

# Extract the IMG file from an FL2 file - special case, without decryption
#
# $@ is the IMG to create
# $< is the FL2
define rule_IMGnoenc_extract
    ./scripts/FL2_copyIMG from_fl2 $< $@
endef
rule_IMGnoenc_extract_DEPS = scripts/FL2_copyIMG

# Insert the new firmware into the FL2 file - special case, without encryption
#
# $@ is the FL2 to create
# $< is the IMG
define rule_IMGnoenc_insert
    cp --reflink=auto $@.orig $@.tmp
    ./scripts/FL2_copyIMG to_fl2 $@.tmp $<
    mv $@.tmp $@
    $(call buildinfo_FL2)
endef
rule_IMGnoenc_insert_DEPS = scripts/FL2_copyIMG


# Extract the FL2 file from an ISO image with two FL2 files
#
# $@ is the FL2 file to create
# $< is the ISO file
# $1 is the pattern to match FL2 file in ISO image
# $2 is the second FL2 files, but this is ignored
define rule_FL2multi2_extract
    $(call rule_FL2_extract,$1)
endef
rule_FL2multi2_extract_DEPS = $(rule_FL2_extract_DEPS)

# Create a new ISO image with patches applied - for images with two FL2 files
# with different names but the same content
#
# $@ is the ISO to create
# $< is the FL2
# $1 is the first FL2 pattern
# $2 is the second FL2 pattern
define rule_FL2multi2_insert
    $(call rule_FL2_insert,$1)
    ./scripts/ISO_copyFL2 to_iso $@ $< $(2)
endef
rule_FL2multi2_insert_DEPS = $(rule_FL2_insert_DEPS)

# Extract the FL2 file from an old style ISO image with no Hard disk image
#
# $@ is the FL2 file to create
# $< is the ISO file
# $1 is the pattern to match FL2 file in ISO image
define rule_oldISO_extract
    xorriso -osirrox on -indev $< -extract $(shell xorriso -osirrox on -indev $< -ls '*$(1)*' 2>/dev/null) $@ 2>/dev/null
    @chmod a-x,u+w $@
    @touch $@
endef

# Generate and include the rules that use the above macros
-include $(DEPSDIR)/generated.deps
CLEAN_FILES += $(DEPSDIR)/generated.deps
$(DEPSDIR)/generated.deps: scripts/generate_deps
$(DEPSDIR)/generated.deps: Descriptions.txt
	@./scripts/generate_deps $< >$@
