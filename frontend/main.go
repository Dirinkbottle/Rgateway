package main

import (
	"io"
	"fmt"
	"log"
	"net/http"
	"time"
)

// ============================================================
// Go 知识点 1: http.HandlerFunc (函数即类型)
// ============================================================
// Go 里函数是一等公民，可以赋值给变量、作为参数传递
// http.HandlerFunc 是一个类型，签名为 func(http.ResponseWriter, *http.Request)
// 任何符合这个签名的函数都能当 handler 用

func handler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	defer r.Body.Close()
	// ============================================================
	// Go 知识点 2: fmt.Fprintf (格式化写入)
	// ============================================================
	// Fprintf 写到指定的 io.Writer（这里 w 是 HTTP 响应体）
	// 类似 C 的 fprintf，但类型安全
	fmt.Fprintf(w, "=== 收到请求 ===\n")

	// r.Method    ← GET / POST / PUT / DELETE ...
	// r.URL.Path  ← 请求路径，如 /api/test
	// r.Host      ← 请求头的 Host 字段
	// r.RemoteAddr ← 客户端 IP:端口
	// r.Header    ← 所有请求头，类型 http.Header (map[string][]string)
	fmt.Fprintf(w, "时间:     %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "方法:     %s\n", r.Method)
	fmt.Fprintf(w, "路径:     %s\n", r.URL.Path)
	fmt.Fprintf(w, "查询参数: %s\n", r.URL.RawQuery)
	fmt.Fprintf(w, "Host:     %s\n", r.Host)
	fmt.Fprintf(w, "来源 IP:  %s\n", r.RemoteAddr)
	fmt.Fprintf(w, "User-Agent: %s\n", r.UserAgent())

	// ============================================================
	// Go 知识点 3: range 遍历 map
	// ============================================================
	// for key, value := range map { ... }
	// 类似 Rust 的 for (k, v) in &map
	fmt.Fprintf(w, "\n--- 请求头 ---\n")
	for name, values := range r.Header {
		// values 是 []string（一个头可以有多个值）
		for _, v := range values {
			// _ 是 blank identifier，忽略不需要的索引值
			fmt.Fprintf(w, "%s: %s\n", name, v)
		}
	}

	// ============================================================
	// Go 知识点 4: r.Body (请求体)
	// ============================================================
	// r.Body 是 io.ReadCloser，读一次就没了
	// 这里简单用 fmt.Fprintln 打印，实际项目会用 json.Decoder 等
	body, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		log.Printf("[backend] read body err: method=%s path=%s remote=%s err=%v",
			r.Method, r.URL.Path, r.RemoteAddr, readErr)
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}
	if len(body) > 0 {
		fmt.Fprintf(w, "\n--- 请求体 (%d bytes) ---\n", len(body))
		fmt.Fprintf(w, "%s\n", body)
	}

	// 同时打印到终端（标准输出）
	fmt.Printf("[%s] %s %s?%s from %s body=%d cost=%s\n",
		time.Now().Format("15:04:05"),
		r.Method, r.URL.Path, r.URL.RawQuery, r.RemoteAddr, len(body), time.Since(start))
}

func main() {
	// ============================================================
	// Go 知识点 5: http.HandleFunc + http.ListenAndServe
	// ============================================================
	// HandleFunc(pattern, handler)
	//   "/" 匹配所有路径（类似 catch-all）
	// ListenAndServe(addr, handler)
	//   addr = ":8080" 监听所有网卡的 8080 端口
	//   handler = nil 时用 DefaultServeMux（刚才 HandleFunc 注册的那个）
	//
	// 这是阻塞调用，程序会一直运行直到出错

	// 注册路由（当前示例把所有路径都交给 handler）
	http.HandleFunc("/", handler)

	fmt.Println("服务器启动在 :8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		// Fatalf = Printf + os.Exit(1)
		log.Fatalf("启动失败: %v", err)
	}
}
