//! SQL 注入 / XSS 检测
//!
//! 预编译正则模式，在请求进入后端之前拦截攻击。
//! 检测范围：URL 路径、Query 字符串、Body 内容、User-Agent

use regex::Regex;

/// SQL 注入 / XSS 检测守卫
pub struct InjectionGuard {
    /// 预编译的攻击模式正则列表
    patterns: Vec<Regex>,
}

impl InjectionGuard {
    /// 初始化：编译所有攻击模式
    pub fn new() -> Self {
        let raw_patterns = [
            // SQL 注入：OR/AND 条件注入
            r"(?i)'(\s)*(or|and)(\s)+'",
            // SQL 注入：UNION SELECT
            r"(?i)union(\s)+select",
            // SQL 注入：DROP TABLE
            r"(?i)drop(\s)+table",
            // SQL 注入：DELETE FROM
            r"(?i)delete(\s)+from",
            // SQL 注入：INSERT INTO
            r"(?i)insert(\s)+into",
            // SQL 注入：UPDATE SET
            r"(?i)update(\s)+\w+(\s)+set",
            // SQL 注入：时间盲注 BENCHMARK/SLEEP
            r"(?i)(benchmark|sleep)\s*\(",
            // SQL 注入：WAITFOR DELAY（MSSQL）
            r"(?i)waitfor(\s)+delay",
            // SQL 注入：分号链式攻击
            r";\s*(drop|delete|insert|update|select)",
            // SQL 注入：注释符（-- 后跟空白或行尾，/* 需闭合或行尾，# 需前有引号/空格）
            r"(?i)(--\s|/\*|\s#)",
            // SQL 注入：1=1 恒真条件（前有引号或空格，后有引号或空格或行尾）
            r#"(?i)["'\s]1\s*=\s*1(?:["'\s;)])?"#,
            // XSS：<script> 标签
            r"(?i)<\s*script[\s>]",
            // XSS：javascript: 协议
            r"(?i)javascript\s*:",
            // XSS：事件处理器 onclick= 等（排除非事件属性如 online=, onload= 等需要空格前缀）
            r"(?i)\son(click|dblclick|load|unload|error|abort|blur|change|focus|keydown|keypress|keyup|mousedown|mousemove|mouseout|mouseover|mouseup|reset|resize|scroll|select|submit|input|paste|cut|copy)\s*=",
            // 路径遍历
            r"\.\./",
            // 空字节注入
            r"%00",
        ];

        let patterns: Vec<Regex> = raw_patterns
            .iter()
            .filter_map(|p| match Regex::new(p) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::error!("正则编译失败 '{}': {}", p, e);
                    None
                }
            })
            .collect();

        Self { patterns }
    }

    /// URL 解码（处理 %XX 和 + 编码），最多解码 max_layers 层
    fn url_decode(text: &str, max_layers: usize) -> String {
        let mut current = text.to_string();
        for _ in 0..max_layers {
            let bytes = current.as_bytes();
            let mut result = Vec::with_capacity(bytes.len());
            let mut i = 0;
            let mut changed = false;
            while i < bytes.len() {
                if bytes[i] == b'%' && i + 2 < bytes.len() {
                    let hex = &current[i + 1..i + 3];
                    if let Ok(byte) = u8::from_str_radix(hex, 16) {
                        result.push(byte);
                        i += 3;
                        changed = true;
                        continue;
                    }
                }
                result.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
                i += 1;
            }
            current = String::from_utf8_lossy(&result).into_owned();
            if !changed {
                break; // 没有更多编码可解
            }
        }
        current
    }

    /// 检测单个文本是否包含攻击模式
    ///
    /// 先 URL 多层解码再匹配，防止 %20 %3D %2527 等多层编码绕过
    pub fn check_text(&self, text: &str) -> bool {
        let decoded = Self::url_decode(text, 3);
        for pattern in &self.patterns {
            if pattern.is_match(&decoded) {
                return false; // 命中攻击模式
            }
        }
        true // 安全
    }

    /// 检测请求的所有可注入字段
    ///
    /// 返回 None 表示安全，Some(reason) 表示检测到攻击
    pub fn inspect_request(
        &self,
        path: &str,
        query: &str,
        body: &str,
        user_agent: &str,
    ) -> Option<String> {
        if !self.check_text(path) {
            return Some(format!("路径包含注入模式: {}", path));
        }
        if !self.check_text(query) {
            return Some(format!("Query 包含注入模式: {}", query));
        }
        if !self.check_text(body) {
            return Some("Body 包含注入模式".to_string());
        }
        if !self.check_text(user_agent) {
            return Some(format!("UA 包含注入模式: {}", user_agent));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> InjectionGuard {
        InjectionGuard::new()
    }

    #[test]
    fn test_detects_union_select() {
        let g = guard();
        assert!(!g.check_text("1 UNION SELECT * FROM users"));
        assert!(!g.check_text("1 union select password"));
    }

    #[test]
    fn test_detects_script_tag() {
        let g = guard();
        assert!(!g.check_text("<script>alert(1)</script>"));
        assert!(!g.check_text("<SCRIPT SRC=evil.js>"));
    }

    #[test]
    fn test_detects_path_traversal() {
        let g = guard();
        assert!(!g.check_text("../../etc/passwd"));
        assert!(!g.check_text("foo/../../../etc/shadow"));
    }

    #[test]
    fn test_safe_text_passes() {
        let g = guard();
        assert!(g.check_text("hello world"));
        assert!(g.check_text("category=news&page=1"));
        assert!(g.check_text("GET /api/sites"));
    }

    #[test]
    fn test_url_encoded_attack_detected() {
        let g = guard();
        // 单层 URL 编码: ' OR 1=1
        assert!(!g.check_text("%27%20OR%201%3D1"));
        // 双重 URL 编码: ' OR 1=1
        assert!(!g.check_text("%2527%2520OR%25201%253D1"));
    }

    #[test]
    fn test_inspect_request_returns_reason() {
        let g = guard();
        let result = g.inspect_request("/api/test", "", "", "Mozilla/5.0");
        assert!(result.is_none());

        // SQL injection in query parameter
        let result = g.inspect_request("/api/test", "id=1 UNION SELECT 1", "", "Mozilla/5.0");
        assert!(result.is_some());
        assert!(result.unwrap().contains("Query"));

        // SQL injection in path
        let result = g.inspect_request("/api/test?id=1 UNION SELECT 1", "", "", "Mozilla/5.0");
        assert!(result.is_some());
    }
}
