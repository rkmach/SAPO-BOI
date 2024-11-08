# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := ids
USER_TARGETS   := loader
BPF_TARGETS    := af_xdp_kern
BPF_TARGETS    := xdp_drop
#BPF_TARGETS    := suspicion-xdp

# Define C-code objects USER_TARGETS needs
USER_TARGETS_OBJS := common_params.o common_user_bpf_xdp.o cora.o
USER_TARGETS_OBJS += hashmap.o lib_xsk_extend.o
USER_TARGETS_OBJS += btf.o
USER_TARGETS_OBJS += xsk_socket.o
#USER_TARGETS_OBJS += automaton.o
#USER_TARGETS_OBJS += cora.o

# The USER_TARGETS_OBJS have a dependency of this header file
USER_TARGETS_OBJS_DEPS += common_defines.h

LDLIBS     += -lpthread
LDLIBS     += -lrt

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk
