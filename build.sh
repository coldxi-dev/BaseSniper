#!/bin/bash

# Android NDK 交叉编译脚本 - arm64-v8a
# 项目: scan (cfindBase)

NDK_PATH="/home/coldxi/ndk/android-ndk-r27"
TOOLCHAIN="${NDK_PATH}/build/cmake/android.toolchain.cmake"
BUILD_DIR="build_arm64"
API_LEVEL=24

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 检查 NDK 路径
if [ ! -d "$NDK_PATH" ]; then
    echo -e "${RED}[错误] NDK 路径不存在: ${NDK_PATH}${NC}"
    exit 1
fi

if [ ! -f "$TOOLCHAIN" ]; then
    echo -e "${RED}[错误] 找不到工具链文件: ${TOOLCHAIN}${NC}"
    exit 1
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Android arm64-v8a 交叉编译${NC}"
echo -e "${GREEN}  NDK: ${NDK_PATH}${NC}"
echo -e "${GREEN}  API Level: ${API_LEVEL}${NC}"
echo -e "${GREEN}========================================${NC}"

# 清理旧构建 (可选参数 clean)
if [ "$1" = "clean" ]; then
    echo -e "${YELLOW}[清理] 删除构建目录: ${BUILD_DIR}${NC}"
    rm -rf "${BUILD_DIR}"
fi

# 创建构建目录
mkdir -p "${BUILD_DIR}" && cd "${BUILD_DIR}" || exit 1

# CMake 配置
echo -e "${GREEN}[配置] 运行 CMake...${NC}"
cmake .. \
    -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN}" \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-${API_LEVEL} \
    -DANDROID_NDK="${NDK_PATH}" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DANDROID_STL=c++_static \
    -DCMAKE_C_FLAGS="-fsanitize=address -g" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address -g" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address"

if [ $? -ne 0 ]; then
    echo -e "${RED}[错误] CMake 配置失败${NC}"
    exit 1
fi

# 编译
echo -e "${GREEN}[编译] 开始构建...${NC}"
cmake --build . -j$(nproc)

if [ $? -ne 0 ]; then
    echo -e "${RED}[错误] 编译失败${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  编译成功!${NC}"
echo -e "${GREEN}  输出: ${BUILD_DIR}/BaseSniper${NC}"
echo -e "${GREEN}========================================${NC}"

# 显示文件信息
file BaseSniper 2>/dev/null
