#!/bin/bash

echo "build for arm64"
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j12 O=build-aarch64/ clean &>/dev/null && make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j12 O=build-aarch64/ 2>&1 | tee build-aarch64.log | pv >/dev/null
res="fail"
echo -n "Test core image build result "
n=$(cat build-aarch64.log| tail -n1 | grep "make\[1\]: Leaving directory"| wc -l) && [ $n -eq 1 ] && res="success"
echo $res
res="fail"
echo -n "Test core image "
n=$(cat build-aarch64/.tmp_vmlinux.kallsyms1.syms.alias | grep " name_show@*"|wc -l)&& [ $n -ge 16 ] && res="success"
echo $res
res="fail"
echo -n "Test modules "
n=$(aarch64-linux-gnu-nm -n build-aarch64/net/rfkill/rfkill.ko| grep name_show| wc -l)&& [ $n -eq 2 ] && res="success"
echo $res

echo "build for i386"
make ARCH=i386 CROSS_COMPILE=i686-linux-gnu- -j12 O=build-i386/  clean &>/dev/null  && make ARCH=i386 CROSS_COMPILE=i686-linux-gnu- -j12 O=build-i386/ 2>&1 | tee build-i386.log | pv >/dev/null
res="fail"
echo -n "Test core image build result "
n=$(cat build-i386.log| tail -n1 | grep "make\[1\]: Leaving directory"| wc -l) && [ $n -eq 1 ] && res="success"
echo $res
res="fail"
echo -n "Test core image "
n=$(cat build-i386/.tmp_vmlinux.kallsyms1.syms.alias | grep " name_show@*"|wc -l)&& [ $n -ge 16 ] && res="success"
echo $res
res="fail"
echo -n "Test modules "
n=$(i686-linux-gnu-nm -n build-i386/net/smc/smc.ko| grep " min_sndbuf" |wc -l)&& [ $n -eq 2 ] && res="success"
echo $res

echo "build for mips32"
make ARCH=mips CROSS_COMPILE=mipsel-linux-gnu- -j12 O=build-mipsel32/ clean &>/dev/null  && make ARCH=mips CROSS_COMPILE=mipsel-linux-gnu- -j12 O=build-mipsel32/ 2>&1 | tee build-mipsel32.log | pv >/dev/null
res="fail"
echo -n "Test core image build result "
n=$(cat build-mipsel32.log| tail -n1 | grep "make\[1\]: Leaving directory"| wc -l) && [ $n -eq 1 ] && res="success"
echo $res
res="fail"
echo -n "Test core image "
n=$(cat build-mipsel32/.tmp_vmlinux.kallsyms1.syms.alias | grep " name_show@*"|wc -l)&& [ $n -ge 3 ] && res="success"
echo $res
res="fail"
echo -n "Test modules "
n=$(i686-linux-gnu-nm -n build-mipsel32/net/ipv4/ipip.ko| grep " log_ecn_error" |wc -l)&& [ $n -eq 2 ] && res="success"
echo $res

echo "build for x86_64"
make  -j12 O=build-x86_64/ clean &>/dev/null  && make  -j12 O=build-x86_64/ 2>&1 | tee build-x86_64.log | pv >/dev/null
res="fail"
echo -n "x86_64 build result "
n=$(cat build-x86_64.log| tail -n1 | grep "make\[1\]: Leaving directory"| wc -l) && [ $n -eq 1 ] && res="success"
echo $res
res="fail"
echo -n "Test core image "
n=$(cat build-x86_64/.tmp_vmlinux.kallsyms1.syms.alias | grep " name_show@*"|wc -l)&& [ $n -ge 10 ] && res="success"
echo $res
res="fail"
echo -n "Test modules "
n=$(nm -n build-x86_64/drivers/rpmsg/rpmsg_core.ko| grep " name_show" |wc -l)&& [ $n -eq 2 ] && res="success"
echo $res





echo "build for x86_64w in tmp"
make  -j12 O=/tmp/build-x64w clean &>/dev/null  && make  -j12 O=/tmp/build-x64w 2>&1 | tee build-x86_64_oot_w.log  | pv >/dev/null
res="fail"
echo -n "x86_64w in tmp build result "
n=$(cat build-x86_64_oot_w.log| tail -n1 | grep "make\[1\]: Leaving directory"| wc -l) && [ $n -eq 1 ] && res="success"
echo $res

echo "build for x86_64wo in tmp wo aliases"
make  -j12 O=/tmp/build-x64wo clean &>/dev/null  && make  -j12 O=/tmp/build-x64wo  2>&1 | tee build-x86_64_oot_wo.log  | pv >/dev/null
res="fail"
echo -n "x86_64wo build result "
n=$(cat build-x86_64_oot_wo.log | tail -n1 | grep "make\[1\]: Leaving directory"| wc -l) && [ $n -eq 1 ] && res="success"
echo $res



echo "build for oot module aarch64"
cd hello && rm -rf .Module.symvers.cmd .hello.ko.cmd .hello.mod.cmd .hello.mod.o.cmd .hello.o.cmd .modules.order.cmd Module.symvers hello.ko hello.mod hello.mod.c hello.mod.o hello.o modules.order hello.o.orig *.log
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j1 V=1 -C ../build-aarch64/  KAS_ALIAS_DEBUG=4 M=$PWD modules  | pv >/dev/null
cd ..
res="fail"
echo -n "Test oot module aarch64" 
n=$(nm -n hello/hello.ko| grep name_show | wc -l) && [ $n -eq 2 ] && res="success"
echo $res





