CL=clang
CFLAGS := -I../../includes -I../../libbpf/src/root/usr/include/

.PHONY: dpi.o

dpi.o: bpf_dpi_kernel.c
	$(CL) $(CFLAGS) -target bpf -O2 -c $< -o $@
