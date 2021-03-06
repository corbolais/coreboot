################################################################################
##
## This file is part of the coreboot project.
##
## Copyright (C) 2014 The ChromiumOS Authors
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; version 2 of the License.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
##
################################################################################

riscv_flags = -I$(src)/arch/riscv/

riscv_asm_flags =

################################################################################
## bootblock
################################################################################
ifeq ($(CONFIG_ARCH_BOOTBLOCK_RISCV),y)

bootblock_lds = $(src)/arch/riscv/bootblock.ld

bootblock-y = bootblock.S stages.c
bootblock-y += rom_media.c
bootblock-y += \
	$(top)/src/lib/memchr.c \
	$(top)/src/lib/memcmp.c \
	$(top)/src/lib/memcpy.c \
	$(top)/src/lib/memmove.c \
	$(top)/src/lib/memset.c

$(objcbfs)/bootblock.debug: $(src)/arch/riscv/bootblock.ld $(obj)/ldoptions $$(bootblock-objs)
	@printf "    LINK       $(subst $(obj)/,,$(@))\n"
	$(CC_bootblock) $(CFLAGS_bootblock) -nostartfiles -Wl,--gc-sections -static -o $@ -L$(obj) \
		-T $(src)/arch/riscv/bootblock.ld -Wl,--start-group $(bootblock-objs) \
		$(LIBGCC_FILE_NAME_bootblock) -Wl,--end-group

endif

################################################################################
## romstage
################################################################################
ifeq ($(CONFIG_ARCH_ROMSTAGE_RISCV),y)

romstage-y += stages.c
romstage-y += rom_media.c
romstage-y += \
	$(top)/src/lib/memchr.c \
	$(top)/src/lib/memcmp.c \
	$(top)/src/lib/memcpy.c \
	$(top)/src/lib/memmove.c \
	$(top)/src/lib/memset.c

romstage-$(CONFIG_COLLECT_TIMESTAMPS) += timestamp.c

# Build the romstage

$(objcbfs)/romstage.debug: $$(romstage-objs) $(src)/arch/riscv/romstage.ld $(obj)/ldoptions
	@printf "    LINK       $(subst $(obj)/,,$(@))\n"
	$(CC_romstage) $(CFLAGS_romstage) -nostdlib -Wl,--gc-sections -static -o $@ -L$(obj) -T $(src)/arch/riscv/romstage.ld -Wl,--start-group $(romstage-objs) -Wl,--end-group

romstage-c-ccopts += $(riscv_flags)
romstage-S-ccopts += $(riscv_asm_flags)

CBFSTOOL_PRE1_OPTS = -v -m riscv -b $(CONFIG_BOOTBLOCK_ROM_OFFSET) -H $(CONFIG_CBFS_HEADER_ROM_OFFSET) -o $(CONFIG_CBFS_ROM_OFFSET)
CBFSTOOL_PRE_OPTS = -v

endif

################################################################################
## ramstage
################################################################################
ifeq ($(CONFIG_ARCH_RAMSTAGE_RISCV),y)

ramstage-y =
ramstage-y += rom_media.c
ramstage-y += stages.c
ramstage-y += misc.c
ramstage-y += boot.c
ramstage-y += tables.c
ramstage-y += \
	$(top)/src/lib/memchr.c \
	$(top)/src/lib/memcmp.c \
	$(top)/src/lib/memcpy.c \
	$(top)/src/lib/memmove.c \
	$(top)/src/lib/memset.c

$(eval $(call create_class_compiler,rmodules,riscv))

ramstage-$(CONFIG_COLLECT_TIMESTAMPS) += timestamp.c

ramstage-srcs += src/mainboard/$(MAINBOARDDIR)/mainboard.c

# Build the ramstage

$(objcbfs)/ramstage.debug: $$(ramstage-objs) $(src)/arch/riscv/ramstage.ld $(obj)/ldoptions
	@printf "    CC         $(subst $(obj)/,,$(@))\n"
	$(CC_ramstage) $(CFLAGS_ramstage) -nostdlib -Wl,--gc-sections -static -o $@ -L$(obj) -Wl,--start-group $(ramstage-objs) -Wl,--end-group -T $(src)/arch/riscv/ramstage.ld

ramstage-c-ccopts += $(riscv_flags)
ramstage-S-ccopts += $(riscv_asm_flags)

endif
