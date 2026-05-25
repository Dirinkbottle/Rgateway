#!/bin/bash
# ZFSG 测试环境启动脚本
# 启动 3 个服务：Go 后端 → Rust 网关 → Next.js 前端

set -e

echo "=== ZFSG 测试环境启动 ==="
echo ""

# 1. 启动 Go 测试后端 (端口 8080)
echo "[1/3] 启动 Go 测试后端 (端口 8080)..."
cd test-backend
go run . &
GO_PID=$!
cd ..
sleep 1

# 2. 启动 Rust 网关 (端口 3000)
echo "[2/3] 启动 Rust 网关 (端口 3000)..."
cargo run --release &
GW_PID=$!
sleep 2

# 3. 启动 Next.js 前端 (端口 3333)
echo "[3/3] 启动 Next.js 前端 (端口 3333)..."
cd test-frontend
npm install --silent 2>/dev/null
npm run dev &
FE_PID=$!
cd ..

echo ""
echo "=== 所有服务已启动 ==="
echo "  Go 后端:   http://localhost:8080"
echo "  Rust 网关: http://localhost:3000"
echo "  Next.js:   http://localhost:3333"
echo ""
echo "打开浏览器访问 http://localhost:3333 进行测试"
echo "按 Ctrl+C 停止所有服务"

# 等待中断
trap "kill $GO_PID $GW_PID $FE_PID 2>/dev/null; exit" INT TERM
wait
