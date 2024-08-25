# Define the target executable name
APP=tc

# Declare $(APP) as a phony target to avoid conflicts with files named "tc"
.PHONY: $(APP)
# Rule to build the $(APP) executable
$(APP): skel
	@# Compile the tc.c source file into the $(APP) executable, linking against libbpf and libelf
	clang tc.c -Wno-unsequenced -lbpf -lelf -o $(APP)

# Declare vmlinux as a phony target
.PHONY: vmlinux
# Rule to generate BTF (BTF Type Information) from the vmlinux file
vmlinux:
	@# Dump the BTF information from the kernel vmlinux file into vmlinux.h in C format
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Declare bpf as a phony target
.PHONY: bpf
# Rule to compile the BPF program
bpf: vmlinux
	@# Compile the BPF program tc.bpf.c to an object file tc.bpf.o with debug info and optimization
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -c tc.bpf.c -o tc.bpf.o

# Declare skel as a phony target
.PHONY: skel
# Rule to generate BPF skeleton code
skel: bpf
	@# Generate the BPF skeleton header file tc.skel.h from the BPF object file tc.bpf.o
	bpftool gen skeleton tc.bpf.o name tc > tc.skel.h

# Declare run as a phony target
.PHONY: run
# Rule to run the $(APP) executable with specified arguments
run: $(APP)
	@# Execute the $(APP) executable with example arguments as root
	sudo ./$(APP) 53 5355 80 443 22 50005 50007 50008

# Declare block as a phony target
.PHONY: block
# Rule to block the network traffic using $(APP)
block: $(APP)
	@# Execute the $(APP) executable to block network traffic
	sudo ./$(APP)

# Declare clean as a phony target
.PHONY: clean
# Rule to remove all generated files
clean:
	@# Remove all object files, skeleton header files, BTF header file, and the $(APP) executable
	rm -rf *.o *.skel.h vmlinux.h $(APP)
