import * as bg from 'http://localhost:3000/gateway/watchdogheader';

const statusEl = document.getElementById('status');
const initStatus = document.getElementById('init-status');
const BASE = 'http://localhost:3000';
let watchdogReady = false;

// ============================================================
// Watchdog 初始化
// ============================================================

async function loadWatchdog() {
  initStatus.textContent = '加载中...';
  try {
    const wasmUrl = `${BASE}/gateway/watchdogbody`;
    const imports = { "./openatomic_watchdog_bg.js": bg };
    const { instance } = await WebAssembly.instantiateStreaming(fetch(wasmUrl), imports);
    bg.__wbg_set_wasm(instance.exports);
    await bg.initialize('http://localhost:3000');
    watchdogReady = true;
    initStatus.textContent = '✓ 已激活';
    initStatus.className = 'ok';
  } catch (e) {
    initStatus.textContent = `✗ ${e.message}`;
    initStatus.className = 'err';
  }
}

document.getElementById('btn-load').onclick = () => loadWatchdog();

// ============================================================
// 测试用例定义
// ============================================================
// 每个测试用例：{ name, method, path, desc }
// 通过 watchdog 加密后发到 Rgateway，由服务器解密校验

const tests = {
  // === 正常请求 ===
  'normal-get': {
    name: '正常 GET',
    method: 'GET',
    path: '/api/sites?category=tech&page=1',
    expect: '200 或后端响应',
  },
  'normal-post': {
    name: '正常 POST',
    method: 'POST',
    path: '/api/test',
    body: JSON.stringify({ hello: 'world' }),
    expect: '200 或后端响应',
  },

  // === SQL 注入 ===
  'sql-or': {
    name: "SQL: OR '1'='1",
    method: 'GET',
    path: "/api/sites?category=tech'+OR+'1'%3D'1",
    expect: '403 Forbidden（注入检测）',
  },
  'sql-union': {
    name: 'SQL: UNION SELECT',
    method: 'GET',
    path: '/api/sites?category=tech%20UNION%20SELECT%20*%20FROM%20users',
    expect: '403 Forbidden（注入检测）',
  },
  'sql-drop': {
    name: 'SQL: DROP TABLE',
    method: 'GET',
    path: '/api/sites?category=tech;DROP%20TABLE%20users',
    expect: '403 Forbidden（注入检测）',
  },
  'sql-sleep': {
    name: 'SQL: SLEEP() 时间盲注',
    method: 'GET',
    path: '/api/sites?category=tech%20AND%20SLEEP(5)',
    expect: '403 Forbidden（注入检测）',
  },
  'sql-comment': {
    name: 'SQL: 注释符 --',
    method: 'GET',
    path: '/api/sites?category=tech--',
    expect: '403 Forbidden（注入检测）',
  },
  'sql-semicolon': {
    name: 'SQL: 分号链式攻击',
    method: 'GET',
    path: '/api/sites?category=tech;select%20*%20from%20users',
    expect: '403 Forbidden（注入检测）',
  },

  // === XSS ===
  'xss-script': {
    name: 'XSS: <script> 标签',
    method: 'GET',
    path: '/api/sites?category=<script>alert(1)</script>',
    expect: '403 Forbidden（注入检测）',
  },
  'xss-event': {
    name: 'XSS: onclick 事件',
    method: 'GET',
    path: '/api/sites?category=test%20onclick=alert(1)',
    expect: '403 Forbidden（注入检测）',
  },
  'xss-jsproto': {
    name: 'XSS: javascript: 协议',
    method: 'GET',
    path: '/api/sites?category=javascript:alert(1)',
    expect: '403 Forbidden（注入检测）',
  },

  // === 路径攻击 ===
  'path-traversal': {
    name: '路径遍历 ../',
    method: 'GET',
    path: '/api/../../../etc/passwd',
    expect: '400 路径不合法',
  },
  'null-byte': {
    name: '空字节 %00',
    method: 'GET',
    path: '/api/sites%00.json',
    expect: '403 Forbidden（注入检测）',
  },

  // === 参数校验 ===
  'wrong-type': {
    name: '类型错误 page=abc',
    method: 'GET',
    path: '/api/sites?page=abc',
    expect: '400 参数校验失败（不是有效数字）',
  },
  'too-long': {
    name: '超长 category (51字符)',
    method: 'GET',
    path: '/api/sites?category=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    expect: '400 长度超限',
  },
  'wrong-method': {
    name: 'DELETE /api/sites (方法不允许)',
    method: 'DELETE',
    path: '/api/sites',
    expect: '405 Method Not Allowed',
  },
  'no-rule': {
    name: '未注册端点 /api/unknown',
    method: 'GET',
    path: '/api/unknown',
    expect: '403 Forbidden（未注册端点）',
  },
};

// ============================================================
// 执行测试
// ============================================================

function log(msg, cls = '') {
  const span = document.createElement('span');
  span.className = cls;
  span.textContent = msg + '\n';
  statusEl.appendChild(span);
  statusEl.scrollTop = statusEl.scrollHeight;
}

async function runTest(key) {
  const t = tests[key];
  if (!t) return;

  if (!watchdogReady) {
    log('✗ 请先加载 Watchdog', 'err');
    return;
  }

  log(`▶ ${t.name}`, 'info');
  log(`  ${t.method} ${t.path}`, 'info');
  log(`  期望: ${t.expect}`, 'info');

  try {
    const res = await fetch(`http://localhost:8080${t.path}`, {
      method: t.method,
      headers: t.body ? { 'Content-Type': 'application/json' } : {},
      body: t.body || undefined,
    });

    const text = await res.text();
    const status = `${res.status} ${res.statusText}`;
    const cls = res.ok ? 'ok' : 'err';
    log(`  结果: ${status}`, cls);
    if (text) log(`  响应: ${text.slice(0, 200)}`, cls);
  } catch (e) {
    log(`  错误: ${e.message}`, 'err');
  }
  log('');
}

// ============================================================
// 绑定所有测试按钮
// ============================================================

document.querySelectorAll('[data-test]').forEach(btn => {
  btn.onclick = () => {
    statusEl.textContent = '';
    runTest(btn.dataset.test);
  };
});
