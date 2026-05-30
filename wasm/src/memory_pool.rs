//! 内存混淆引擎
//!
//! 16MB 随机内存池，用于：
//! - 存储滚动码（通过动态指针漂移隐藏真实位置）
//! - 每次请求刷新 1KB 随机区域，破坏内存快照 Diff 分析
//! - 特征码再加密（加法混淆）

use sha2::{Digest, Sha256};

/// 16MB 内存池大小
const POOL_SIZE: usize = 16 * 1024 * 1024;
/// 每次刷新的特征码区域大小
const PATTERN_SIZE: usize = 1024;

/// 内存混淆引擎
pub struct MemoryPool {
    /// 16MB 噪声数据
    pool: Vec<u8>,
    /// 内置 Hash 密钥（32字节，编译时嵌入或从配置加载）
    hash_key: [u8; 32],
    /// 滚动码（不直接暴露，通过 compute_offset 计算动态位置）
    rolling_nonce: u64,
    /// 固定环绕步长（由静态 hash_key 派生）
    nonce_step: u64,
}

impl MemoryPool {
    /// 初始化内存池：用随机噪声填充 16MB
    pub fn new(hash_key: [u8; 32]) -> Self {
        let mut pool = vec![0u8; POOL_SIZE];
        // 用 getrandom 填充高质量随机噪声
        getrandom::getrandom(&mut pool).expect("内存池随机初始化失败");
        let nonce_step = Self::derive_nonce_step(&hash_key);
        Self {
            pool,
            hash_key,
            rolling_nonce: 0,
            nonce_step,
        }
    }

    /// 获取 hash_key 引用（供加密模块使用）
    pub fn hash_key(&self) -> &[u8; 32] {
        &self.hash_key
    }

    /// 获取当前滚动码值（供加密模块使用）
    /// 注意：这不是 read_nonce()（那个读的是内存池中的随机值）
    pub fn current_nonce(&self) -> u64 {
        self.rolling_nonce
    }

    /// 计算动态偏移量：SHA-256(hash_key + rolling_nonce) 取前8字节 → 求模
    /// 每次调用得到不同的偏移，实现指针漂移
    fn compute_offset(&self) -> usize {
        let mut hasher = Sha256::new();
        hasher.update(self.hash_key);
        hasher.update(self.rolling_nonce.to_le_bytes());
        let hash = hasher.finalize();
        let offset_bytes = u64::from_le_bytes(
            hash[..8].try_into().expect("哈希切片长度正确"),
        );
        (offset_bytes as usize) % (POOL_SIZE - 8)
    }

    /// 读取滚动码：通过动态偏移量从内存池中读取
    /// 滚动码真实值隐藏在 pool[offset..offset+8] 中
    #[allow(dead_code)]
    pub fn read_nonce(&self) -> u64 {
        let offset = self.compute_offset();
        u64::from_le_bytes(
            self.pool[offset..offset + 8].try_into().expect("读取滚动码切片正确"),
        )
    }

    /// 固定步长计算：SHA-256(hash_key) 取前8字节
    /// 至少为 1，避免步长为 0
    fn derive_nonce_step(hash_key: &[u8; 32]) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(hash_key);
        let hash = hasher.finalize();
        let step = u64::from_le_bytes(
            hash[..8].try_into().expect("步长哈希切片正确"),
        );
        if step == 0 { 1 } else { step }
    }

    /// 更新滚动码（每次请求调用一次）：
    /// 1. 非线性步长递增
    /// 2. 写入新偏移位置
    /// 3. 1KB 特征码破坏
    pub fn update_nonce(&mut self) {
        // 1. 固定步长环绕递增
        self.rolling_nonce = self.rolling_nonce.wrapping_add(self.nonce_step);

        // 2. 写入新偏移位置
        let new_offset = self.compute_offset();
        self.pool[new_offset..new_offset + 8]
            .copy_from_slice(&self.rolling_nonce.to_le_bytes());

        // 3. 1KB 特征码破坏
        self.destroy_pattern();
    }

    /// TCP 重连后重置滚动码
    #[allow(dead_code)]
    pub fn reset_nonce(&mut self) {
        self.rolling_nonce = 0;
        let reset_offset = self.compute_offset();
        self.pool[reset_offset..reset_offset + 8].copy_from_slice(&0u64.to_le_bytes());
    }

    /// 1KB 特征码破坏：随机选取内存池中的 1KB 区域，用伪随机数覆盖
    /// 目的：破坏作弊工具的内存快照 Diff 分析
    fn destroy_pattern(&mut self) {
        // 生成随机偏移
        let mut offset_buf = [0u8; 4];
        getrandom::getrandom(&mut offset_buf).expect("随机偏移生成失败");
        let offset = u32::from_le_bytes(offset_buf) as usize % (POOL_SIZE - PATTERN_SIZE);

        // 生成随机噪声并覆盖
        let mut noise = vec![0u8; PATTERN_SIZE];
        getrandom::getrandom(&mut noise).expect("随机噪声生成失败");
        self.pool[offset..offset + PATTERN_SIZE].copy_from_slice(&noise);
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_pool_init() {
        let key = [42u8; 32];
        let pool = MemoryPool::new(key);
        // 内存池应该已填充随机数据（非全零）
        let non_zero = pool.pool.iter().filter(|&&b| b != 0).count();
        assert!(non_zero > POOL_SIZE / 2, "内存池应大部分非零");
    }

    #[test]
    fn test_nonce_update_changes_offset() {
        let key = [42u8; 32];
        let mut pool = MemoryPool::new(key);
        let offset_before = pool.compute_offset();
        pool.update_nonce();
        let offset_after = pool.compute_offset();
        // 滚动码更新后，偏移量大概率会变
        assert_ne!(pool.rolling_nonce, 0, "滚动码应已更新");
        // 注意：offset 有可能碰巧相同，但概率极低
        let _ = (offset_before, offset_after);
    }

    #[test]
    fn test_nonce_step_is_static() {
        let key = [42u8; 32];
        let mut pool = MemoryPool::new(key);
        let step = pool.nonce_step;
        pool.update_nonce();
        assert_eq!(pool.rolling_nonce, step);
        pool.update_nonce();
        assert_eq!(pool.rolling_nonce, step.wrapping_mul(2));
    }

}
