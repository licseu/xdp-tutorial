
XDP_TARGETS := fdrop_kern
USER_TARGETS := fdrop_ops fdrop_loader

LLC ?= llc
CLANG ?= clang
CC := gcc

COMMON_DIR = ../common
COMMON_OBJS += $(COMMON_DIR)/common_user_bpf_xdp.o

include $(COMMON_DIR)/common.mk
