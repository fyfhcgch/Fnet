/* Fnet WebUI - vanilla JS, no external dependencies. */
(() => {
  "use strict";

  const TOKEN = window.FNET_TOKEN;
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const esc = (value) => String(value ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");

  const state = {
    meta: null,
    pcap: "",
    fileName: "",
    jobId: null,
    cursor: 0,
    logs: [],
    artifacts: [],
    findings: [],
    findingsVisible: [],
    findingsJob: null,
    findingsKinds: {},
    findingsDerived: false,
    findingsTruncated: false,
    // null = 默认排序（时间倒序、seq 倒序）；表头点击排序后由点击逻辑改写。
    findingsSort: null,
    findingsPage: 1,
    findingsPageSize: 100,
    findingsSelected: new Set(),
    findingsHidden: new Set(),
    history: [],
    features: [],
    recentFeatures: [],
    reportSections: [],
    pollTimer: null,
    decodeText: "",
    localSeq: 0,
    featureCount: 0,
    inputKind: "",
    batch: { ids: [], jobs: [], timer: null, active: false, summary: null, drag: null },
    viz: { timeline: null, hierarchy: null, talkers: null, topology: null, topologyApi: null, zoom: null, svg: "", log: false },
    tlsKeyKind: "keylog",
    language: "zh",
    featureSearch: "",
    upload: null,
    paused: false,
    liveTimer: null,
    crack: { timer: null, id: "", password: "" },
    ntlm: { timer: null, id: "", password: "" },
  };

  const TERMINAL = new Set(["done", "error", "cancelled", "paused"]);

  // UI chrome is translated in place; capture logs and reports stay Chinese so
  // the evidence reads the same regardless of the interface language.
  const I18N = {
    zh: {
      tab_log: "分析日志", tab_findings: "分析结果", tab_artifacts: "产出文件",
      tab_batch: "批量队列", tab_viz: "统计图表", tab_history: "任务历史",
      tab_text: "文本工具", tab_about: "关于",
      menu_file: "文件", menu_stats: "统计", menu_settings: "设置",
      menu_tools: "工具", menu_special: "专项功能", menu_help: "帮助",
      search: "搜索功能 / 分类 / handler", select_all: "全选",
      features_title: "自动分析功能",
      drop_title: "拖拽流量包或日志到此处",
      drop_hint: "支持一次拖入多个文件并进入批量队列（pcap / pcapng / cap / dmp / etl，或 log / txt / jsonl / csv）",
      use_path: "使用", start: "开始分析", pause: "暂停", cancel: "取消",
      live: "实时抓包", compare: "对比两个任务",
      settings_webshell: "Webshell 解密设置", settings_shiro: "Shiro 解密设置",
      settings_winrm: "WinRM 解密设置", settings_sql: "SQL 盲注设置",
      settings_log: "日志关联设置",
      settings_general: "通用分析设置",
      status_idle: "空闲", status_running: "运行中", status_paused: "已暂停",
      status_done: "完成", status_cancelled: "已取消", status_error: "错误",
      ann_status: "标注状态", ann_none: "无标注",
      ann_confirmed: "已确认", ann_false_positive: "误报", ann_starred: "星标",
      ann_note: "备注", ann_save: "保存标注", ann_saved: "标注已保存",
      decode_panel_title: "检测到疑似编码串", decode_run: "一键解码",
      decode_copy: "复制结果", decode_cyberchef: "在 CyberChef 中打开",
      decode_cyberchef_opened: "已在浏览器中打开 CyberChef",
      decode_running: "解码中…", decode_failed: "解码失败",
      decode_no_result: "没有找到可读的解码结果。",
      decode_copied: "解码结果已复制",
      decode_copy_failed: "复制失败，请手动选择文本",
      decode_chars: "字符",
      replay_button: "生成重放脚本", replay_title: "攻击重放脚本",
      replay_running: "正在生成重放脚本…", replay_copied: "重放脚本已复制到剪贴板",
      replay_close: "关闭",
      crack_button: "用 hashcat 破解", crack_title: "hashcat 破解",
      crack_wordlist: "字典路径", crack_workload: "加速档位 (-w)",
      crack_optimized: "优化内核 -O（更快，密码长度 ≤ 31）",
      crack_force: "强制模式 --force（无 GPU / OpenCL 报错时勾选）",
      crack_timeout: "超时（秒）", crack_extra: "附加参数",
      crack_start: "开始破解", crack_stop: "停止", crack_close: "关闭",
      crack_running: "破解中…", crack_cracked: "已破解",
      crack_exhausted: "字典已跑完，未找到", crack_error: "破解失败",
      crack_cancelled: "已取消",
      crack_no_hashcat: "未找到 hashcat，请先安装或在设置中指定路径",
      crack_password: "密码", crack_copied: "密码已复制",
      ntlmcrack_button: "用 NTLM 离线破解", ntlmcrack_title: "NetNTLMv2 离线破解",
      ntlmcrack_hint: "纯 Python 本地计算（hashcat 的离线回退），速度较慢；"
        + "建议填入候选口令列表，或把尝试上限设低。大量候选请改用 hashcat -m 5600。",
      ntlmcrack_candidates: "候选口令（可选，逗号/分号分隔）",
      ntlmcrack_min_len: "最小长度", ntlmcrack_max_len: "最大长度",
      ntlmcrack_alphabet: "字母表（如 ascii_letters+digits 或 abc123）",
      ntlmcrack_max_attempts: "尝试上限（次）", ntlmcrack_timeout: "超时（秒）",
      ntlmcrack_start: "开始破解", ntlmcrack_stop: "停止", ntlmcrack_close: "关闭",
      ntlmcrack_running: "破解中…", ntlmcrack_cracked: "已破解",
      ntlmcrack_exhausted: "候选已验证完毕，未找到", ntlmcrack_error: "破解失败",
      ntlmcrack_cancelled: "已取消", ntlmcrack_attempts: "已尝试",
      ntlmcrack_password: "密码", ntlmcrack_copied: "密码已复制",
      smb_decrypt_button: "解密 SMB3", smb_decrypt_title: "SMB3 解密",
      smb_decrypt_hint: "用 NT 哈希、明文密码或会话密钥还原 SMB3 加密流量。"
        + "NetNTLMv2 哈希需要先破解成密码，或直接填入 NT 哈希（32 位十六进制）。",
      smb_password: "明文密码", smb_nt_hash: "NT 哈希（32 位十六进制）",
      smb_session_key: "会话密钥（可选，十六进制）",
      smb_user: "账号（可选）", smb_domain: "域（可选）",
      smb_stream: "TCP 流（可选，留空自动）", smb_start: "开始解密",
      smb_close: "关闭", smb_running: "解密中…", smb_no_tshark: "未找到 tshark，无法解密",
      smb_need_job: "还没有可解密的分析任务",
      smb_need_secret: "请填写 NT 哈希、密码或会话密钥",
      smb_hints_recheck: "重新检测", smb_hints_prefill: "已自动填入：",
      smb_hints_saved: "线索已更新：",
      smb_hints_none: "未发现可自动填入的线索，可先运行 NTLM 验证 / SMB 密码候选，"
        + "或手工填入。",
      smb_hints_failed: "读取自动填入线索失败",
      smb_hints_from_finding: "本条结果",
      smb_hint_password: "明文密码", smb_hint_nt_hash: "NT 哈希",
      smb_hint_session_key: "会话密钥", smb_hint_user: "账号",
      smb_hint_domain: "域", smb_hint_stream: "TCP 流",
      smb_stream_short: "流", smb_keys: "会话密钥",
      smb_account_pick: "选择账号（填入其凭据与 TCP 流）",
      smb_account_none: "不选择",
      smb_ok: "SMB3 解密完成", smb_failed: "SMB3 解密失败",
      smb_result_title: "SMB3 解密结果", smb_no_result: "没有解密出任何消息",
      smb_detail_title: "SMB 分析详情", smb_detail_extra: "协议字段",
      smb_flags: "flag", smb_files: "还原文件",
      smb_field_protocol: "协议", smb_field_smb: "类型", smb_field_stream: "TCP 流",
      smb_field_client: "客户端", smb_field_server: "服务端",
      smb_field_dialect: "方言", smb_field_session_id: "会话 ID",
      smb_field_nonce: "Nonce", smb_field_transforms: "加密消息",
      smb_field_encrypted_bytes: "加密字节", smb_field_first_frame: "首个帧",
      smb_field_account: "账号", smb_field_user: "用户", smb_field_domain: "域",
      smb_field_workstation: "主机", smb_field_auth: "认证包",
      smb_field_hash: "哈希", smb_field_mode: "hashcat 模式",
      smb_field_share: "共享", smb_field_encrypted: "要求加密",
      smb_field_share_flags: "共享标志", smb_field_path: "路径",
      smb_field_name: "文件名", smb_field_size: "大小", smb_field_md5: "MD5",
      smb_field_pipe: "命名管道", smb_field_algorithm: "压缩算法",
      smb_field_original_size: "原始大小", smb_field_security_mode: "签名策略",
      smb_field_capabilities: "能力标志", smb_field_artifact: "产出文件",
      smb_encrypted_hint: "该结果来自加密流量；填入凭据后可还原明文、文件与 flag。",
      flag_bar_title: "发现 {count} 个 Flag", flag_copy: "复制",
      flag_copied: "Flag 已复制", flag_copy_failed: "复制失败，请手动选择文本",
      flag_banner_title: "Flag", flag_banner_label: "Flag：",
      payload_title: "载荷", payload_download: "下载载荷",
      payload_preview_title: "载荷预览",
      payload_preview_empty: "载荷为二进制，无文本预览",
      payload_copied: "载荷预览已复制",
      payload_crack: "破解", payload_crack_hide: "收起",
      payload_password: "口令",
      payload_password_ph: "题目给出的口令（留空则自动尝试常见口令）",
      payload_passwords: "候选口令",
      payload_passwords_ph: "候选口令，每行一个（可选）",
      payload_cipher: "算法", payload_digest: "摘要", payload_salted: "盐",
      payload_auto: "自动",
      payload_salted_auto: "自动",
      payload_salted_yes: "有盐（Salted__）",
      payload_salted_no: "无盐（-nosalt）",
      payload_base64: "载荷是 Base64 文本",
      payload_run: "开始破解", payload_running: "破解中…",
      payload_hit: "解密成功", payload_password_hit: "口令",
      payload_recipe: "配方", payload_saved: "已保存",
      payload_copy_plain: "复制明文",
      payload_plain_copied: "明文已复制",
      payload_download_decoded: "下载解密文件",
      payload_plaintext: "明文预览",
      payload_miss: "已尝试 {count} 种配方，未找到可读明文",
      payload_failed: "破解失败",
      payload_need_job: "还没有可破解的分析任务",
      topo_hint: "点击节点可按该端点过滤分析结果；连线按协议着色。",
    },
    en: {
      tab_log: "Log", tab_findings: "Findings", tab_artifacts: "Artifacts",
      tab_batch: "Batch queue", tab_viz: "Charts", tab_history: "History",
      tab_text: "Text tools", tab_about: "About",
      menu_file: "File", menu_stats: "Statistics", menu_settings: "Settings",
      menu_tools: "Tools", menu_special: "One-click", menu_help: "Help",
      search: "Search features / categories / handlers", select_all: "Select all",
      features_title: "Analysis features",
      drop_title: "Drop a capture or log here",
      drop_hint: "Multiple files are queued for a batch run (pcap / pcapng / cap / dmp / etl, or log / txt / jsonl / csv)",
      use_path: "Use", start: "Start", pause: "Pause", cancel: "Cancel",
      live: "Live capture", compare: "Compare jobs",
      settings_webshell: "Webshell decryption", settings_shiro: "Shiro decryption",
      settings_winrm: "WinRM decryption", settings_sql: "Blind SQL injection",
      settings_log: "Log correlation",
      settings_general: "General analysis",
      status_idle: "Idle", status_running: "Running", status_paused: "Paused",
      status_done: "Done", status_cancelled: "Cancelled", status_error: "Error",
      ann_status: "Annotation", ann_none: "None",
      ann_confirmed: "Confirmed", ann_false_positive: "False positive",
      ann_starred: "Starred",
      ann_note: "Note", ann_save: "Save annotation", ann_saved: "Annotation saved",
      decode_panel_title: "Suspected encoded strings", decode_run: "Decode",
      decode_copy: "Copy result", decode_cyberchef: "Open in CyberChef",
      decode_cyberchef_opened: "CyberChef opened in the browser",
      decode_running: "Decoding…", decode_failed: "Decode failed",
      decode_no_result: "No readable decoded result.",
      decode_copied: "Decoded result copied",
      decode_copy_failed: "Copy failed; select the text manually",
      decode_chars: "chars",
      replay_button: "Replay script", replay_title: "Replay script",
      replay_running: "Generating replay script…",
      replay_copied: "Replay script copied to clipboard",
      replay_close: "Close",
      crack_button: "Crack with hashcat", crack_title: "hashcat cracking",
      crack_wordlist: "Wordlist path", crack_workload: "Workload profile (-w)",
      crack_optimized: "Optimized kernels -O (faster, passwords ≤ 31)",
      crack_force: "Force --force (for GPU / OpenCL warnings)",
      crack_timeout: "Timeout (seconds)", crack_extra: "Extra arguments",
      crack_start: "Start cracking", crack_stop: "Stop", crack_close: "Close",
      crack_running: "Cracking…", crack_cracked: "Cracked",
      crack_exhausted: "Wordlist exhausted, not found", crack_error: "Cracking failed",
      crack_cancelled: "Cancelled",
      crack_no_hashcat: "hashcat not found; install it or set its path in Settings",
      crack_password: "Password", crack_copied: "Password copied",
      ntlmcrack_button: "Crack NTLM locally",
      ntlmcrack_title: "NetNTLMv2 offline cracking",
      ntlmcrack_hint: "Pure-Python local computation (hashcat fallback) is slow; "
        + "prefer a candidate list or keep the attempt cap low. Use hashcat "
        + "-m 5600 for large runs.",
      ntlmcrack_candidates: "Candidates (optional, comma/semicolon separated)",
      ntlmcrack_min_len: "Min length", ntlmcrack_max_len: "Max length",
      ntlmcrack_alphabet: "Alphabet (e.g. ascii_letters+digits or abc123)",
      ntlmcrack_max_attempts: "Attempt cap", ntlmcrack_timeout: "Timeout (seconds)",
      ntlmcrack_start: "Start cracking", ntlmcrack_stop: "Stop",
      ntlmcrack_close: "Close",
      ntlmcrack_running: "Cracking…", ntlmcrack_cracked: "Cracked",
      ntlmcrack_exhausted: "Candidates exhausted, not found",
      ntlmcrack_error: "Cracking failed", ntlmcrack_cancelled: "Cancelled",
      ntlmcrack_attempts: "Attempted", ntlmcrack_password: "Password",
      ntlmcrack_copied: "Password copied",
      smb_decrypt_button: "Decrypt SMB3", smb_decrypt_title: "SMB3 decryption",
      smb_decrypt_hint: "Recover SMB3 encrypted traffic with an NT hash, plaintext "
        + "password or session key. NetNTLMv2 hashes must be cracked first, or "
        + "paste the NT hash (32 hex digits) directly.",
      smb_password: "Plaintext password", smb_nt_hash: "NT hash (32 hex digits)",
      smb_session_key: "Session key (optional, hex)",
      smb_user: "Account (optional)", smb_domain: "Domain (optional)",
      smb_stream: "TCP stream (optional, auto)", smb_start: "Decrypt",
      smb_close: "Close", smb_running: "Decrypting…", smb_no_tshark: "tshark not found; cannot decrypt",
      smb_need_job: "No analysis job available",
      smb_need_secret: "Enter an NT hash, password or session key",
      smb_hints_recheck: "Re-check hints", smb_hints_prefill: "Auto-filled: ",
      smb_hints_saved: "Hints updated: ",
      smb_hints_none: "Nothing could be auto-filled; run the NTLM verification or "
        + "the SMB password candidates first, or type the credentials in.",
      smb_hints_failed: "Could not read the auto-fill hints",
      smb_hints_from_finding: "this finding",
      smb_hint_password: "password", smb_hint_nt_hash: "NT hash",
      smb_hint_session_key: "session key", smb_hint_user: "account",
      smb_hint_domain: "domain", smb_hint_stream: "TCP stream",
      smb_stream_short: "stream", smb_keys: "Session keys",
      smb_account_pick: "Pick an account (fills its credentials and stream)",
      smb_account_none: "Don't pick one",
      smb_ok: "SMB3 decrypted", smb_failed: "SMB3 decryption failed",
      smb_result_title: "SMB3 decryption result", smb_no_result: "Nothing was decrypted",
      smb_detail_title: "SMB analysis detail", smb_detail_extra: "Protocol fields",
      smb_flags: "Flags", smb_files: "Recovered files",
      smb_field_protocol: "Protocol", smb_field_smb: "Type", smb_field_stream: "TCP stream",
      smb_field_client: "Client", smb_field_server: "Server",
      smb_field_dialect: "Dialect", smb_field_session_id: "Session ID",
      smb_field_nonce: "Nonce", smb_field_transforms: "Encrypted messages",
      smb_field_encrypted_bytes: "Encrypted bytes", smb_field_first_frame: "First frame",
      smb_field_account: "Account", smb_field_user: "User", smb_field_domain: "Domain",
      smb_field_workstation: "Workstation", smb_field_auth: "Auth package",
      smb_field_hash: "Hash", smb_field_mode: "hashcat mode",
      smb_field_share: "Share", smb_field_encrypted: "Encryption required",
      smb_field_share_flags: "Share flags", smb_field_path: "Path",
      smb_field_name: "File name", smb_field_size: "Size", smb_field_md5: "MD5",
      smb_field_pipe: "Named pipe", smb_field_algorithm: "Compression",
      smb_field_original_size: "Original size", smb_field_security_mode: "Signing policy",
      smb_field_capabilities: "Capabilities", smb_field_artifact: "Artifact",
      smb_encrypted_hint: "This finding comes from encrypted traffic; supply credentials to recover plaintext, files and flags.",
      flag_bar_title: "Found {count} flag(s)", flag_copy: "Copy",
      flag_copied: "Flag copied", flag_copy_failed: "Copy failed; select the text manually",
      flag_banner_title: "Flag", flag_banner_label: "Flag: ",
      payload_title: "Payload", payload_download: "Download payload",
      payload_preview_title: "Payload preview",
      payload_preview_empty: "Binary payload; no text preview",
      payload_copied: "Payload preview copied",
      payload_crack: "Crack", payload_crack_hide: "Hide",
      payload_password: "Password",
      payload_password_ph: "Password from the challenge (leave empty to try common ones)",
      payload_passwords: "Candidate passwords",
      payload_passwords_ph: "Candidate passwords, one per line (optional)",
      payload_cipher: "Cipher", payload_digest: "Digest", payload_salted: "Salt",
      payload_auto: "Auto",
      payload_salted_auto: "Auto",
      payload_salted_yes: "Salted (Salted__)",
      payload_salted_no: "Unsalted (-nosalt)",
      payload_base64: "Payload is Base64 text",
      payload_run: "Start cracking", payload_running: "Cracking…",
      payload_hit: "Decrypted", payload_password_hit: "Password",
      payload_recipe: "Recipe", payload_saved: "Saved",
      payload_copy_plain: "Copy plaintext",
      payload_plain_copied: "Plaintext copied",
      payload_download_decoded: "Download decrypted file",
      payload_plaintext: "Plaintext preview",
      payload_miss: "Tried {count} recipe(s), no readable plaintext found",
      payload_failed: "Crack failed",
      payload_need_job: "No analysis job available",
      topo_hint: "Click a node to filter findings by that endpoint; links are colored by protocol.",
    },
  };

  function t(key, fallback = "") {
    const dict = I18N[state.language] || I18N.zh;
    return dict[key] || (I18N.zh[key] ?? fallback ?? key);
  }

  function applyLanguage(lang, persist = false) {
    state.language = lang === "en" ? "en" : "zh";
    document.documentElement.lang = state.language === "en" ? "en" : "zh-CN";
    $$("[data-i18n]").forEach((node) => {
      const value = t(node.dataset.i18n);
      if (value) node.textContent = value;
    });
    $$("[data-i18n-placeholder]").forEach((node) => {
      const value = t(node.dataset.i18nPlaceholder);
      if (value) node.placeholder = value;
    });
    const selector = $("#lang-select");
    if (selector) selector.value = state.language;
    if (state.meta) renderFeatures();
    if (persist) {
      saveConfig("config", { language: state.language }).catch(() => {});
      localStorage.setItem("fnet.lang", state.language);
    }
  }

  /* ------------------------------------------------------------ helpers */
  async function api(path, options = {}) {
    const opts = { ...options };
    const headers = { "X-Fnet-Token": TOKEN, ...(opts.headers || {}) };
    if (opts.body && typeof opts.body !== "string" &&
        !(opts.body instanceof FormData)) {
      headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.body);
    }
    const response = await fetch(path, { ...opts, headers });
    let data = null;
    const type = response.headers.get("content-type") || "";
    if (type.includes("application/json")) {
      data = await response.json();
    } else {
      const text = await response.text();
      data = { ok: response.ok, text };
    }
    if (!response.ok || data.ok === false) {
      throw new Error(data.error || data.text || `HTTP ${response.status}`);
    }
    return data;
  }

  function toast(message, kind = "info", timeout = 4200) {
    const node = $("#toast");
    node.textContent = message;
    node.className = `toast ${kind}`;
    clearTimeout(node._timer);
    node._timer = setTimeout(() => node.classList.add("hidden"), timeout);
  }

  function val(id) { const el = $("#" + id); return el ? el.value.trim() : ""; }
  function checked(id) { const el = $("#" + id); return !!(el && el.checked); }
  function setVal(id, value) { const el = $("#" + id); if (el) el.value = value ?? ""; }
  function setChecked(id, value) { const el = $("#" + id); if (el) el.checked = !!value; }
  function setText(sel, value) { const el = $(sel); if (el) el.textContent = value ?? ""; }

  function fmtSize(bytes) {
    if (!bytes && bytes !== 0) return "";
    const units = ["B", "KB", "MB", "GB"];
    let value = bytes, unit = 0;
    while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
    return `${value.toFixed(unit ? 1 : 0)} ${units[unit]}`;
  }

  // Line icons keep the sidebar readable without loading an icon font.
  const CATEGORY_ICONS = {
    text: '<path d="M4 6h16M4 12h16M4 18h10"/>',
    http: '<circle cx="12" cy="12" r="8"/><path d="M4 12h16M12 4c2.2 2.3 3.3 5 3.3 8S14.2 17.7 12 20M12 4c-2.2 2.3-3.3 5-3.3 8S9.8 17.7 12 20"/>',
    webshell: '<path d="m8 8-4 4 4 4M16 8l4 4-4 4M13.5 6l-3 12"/>',
    sql: '<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/>',
    c2: '<path d="M12 3v6M12 15v6M3 12h6M15 12h6"/><circle cx="12" cy="12" r="3"/>',
    auth: '<rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v2"/>',
    flow: '<path d="M4 7h11l-3-3M20 17H9l3 3"/>',
    ics: '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M8 9h8M8 13h8M8 17h4"/>',
    usb: '<path d="M12 21V5m0 0 3 3m-3-3L9 8"/><path d="M8 13h8M8 13l-2-2m2 2v3M16 13l2-2m-2 2v3"/>',
    wireless: '<path d="M4 9a12 12 0 0 1 16 0M7 12.5a8 8 0 0 1 10 0M10 16a4 4 0 0 1 4 0"/><circle cx="12" cy="19" r="1"/>',
    tls: '<path d="M12 3.5 19 6v5c0 4-3 7-7 9-4-2-7-5-7-9V6z"/><path d="M9.5 11.5 11 13l3.5-3.5"/>',
    misc: '<path d="M12 3.5 14 9l5.5 2-5.5 2-2 5.5-2-5.5L4.5 11 10 9z"/>',
    rdp: '<rect x="3.5" y="5" width="17" height="11" rx="2"/><path d="M8 20h8M12 16v4"/>',
  };

  function nowTime() {
    return new Date().toLocaleTimeString("zh-CN", { hour12: false });
  }

  /* --------------------------------------------------------------- init */
  async function init() {
    state.meta = await api("/api/meta");
    restoreRecentFeatures();
    restoreReportSections();
    applyMeta(state.meta);
    applyLanguage(state.meta.language
      || localStorage.getItem("fnet.lang") || "zh");
    bindEvents();
    restoreLocalSettings();
    restoreFindingsColumns();
    applyTheme(state.meta.theme || "dark");
    applyInitial(state.meta.initial);
    refreshSelected();
    setText("#version", state.meta.version);
    setText("#about-version", state.meta.version);
    setText("#user-dir", state.meta.paths.user);
    renderTools(state.meta.tools);
    renderRuntime();
    loadHistory().catch(() => {});
    if (!state.meta.tools.tshark?.available && state.inputKind !== "log") {
      toast("未找到 tshark，依赖 tshark 的分析功能不可用。\nDebian/Ubuntu: sudo apt install tshark",
        "warn", 9000);
    }
  }

  function applyMeta(meta) {
    // Theme selector
    const select = $("#theme-select");
    select.innerHTML = "";
    meta.themes.forEach((theme) => {
      const option = document.createElement("option");
      option.value = theme.key;
      option.textContent = theme.name;
      select.appendChild(option);
    });
    select.value = meta.theme || "dark";

    // Structured finding kinds for the result table filter.
    const kinds = (meta.findings && meta.findings.kinds) || [];
    state.findingsKinds = Object.fromEntries(
      kinds.map((kind) => [kind.key, kind.name]));
    const kindSelect = $("#findings-kind");
    kindSelect.innerHTML = '<option value="all">全部类别</option>' +
      kinds.map((kind) =>
        `<option value="${esc(kind.key)}">${esc(kind.name)}</option>`).join("");

    // Feature list grouped by category.
    state.features = meta.features || [];
    renderFeatures();
    setText("#feature-total", `${meta.features.length} 个功能`);

    // Config derived defaults.
    const cfg = (meta.config && meta.config.config) || {};
    const paths = (meta.config && meta.config.paths) || {};
    setVal("wordlist", cfg.passwddir || meta.paths.wordlist);
    setVal("sql_success", cfg.sql_success || "");
    setVal("sql_time_threshold", cfg.sql_time_threshold || "1.0");
    setVal("webshell_password", cfg.webshell_password || "");
    setVal("shiro_key", cfg.shiro_key || "");
    setVal("winrm_port", cfg.winrm_port || "5985");

    const badge = $("#tshark-badge");
    const tool = meta.tools.tshark;
    badge.textContent = tool && tool.available ? "tshark 就绪" : "tshark 缺失";
    badge.className = `badge ${tool && tool.available ? "ok" : "bad"}`;
    badge.title = tool && tool.path ? tool.path : "未找到 tshark";
  }

  function renderFeatures() {
    const meta = state.meta || {};
    const english = (state.language || "zh") === "en";
    const previous = new Set($$("#features input[type=checkbox]:checked")
      .map((box) => box.value));
    const hadList = $$("#features input[type=checkbox]").length > 0;
    const container = $("#features");
    if (!container) return;
    container.innerHTML = "";
    (meta.categories || []).forEach((category) => {
      const features = (meta.features || [])
        .filter((f) => f.category === category.key);
      if (!features.length) return;
      const label = english
        ? (category.name_en || category.name) : category.name;
      const details = document.createElement("details");
      details.className = "feature-group";
      details.dataset.category = category.key;
      details.open = ["text", "http", "webshell", "sql", "c2", "auth"]
        .includes(category.key) || (state.featureSearch
          ? features.some((f) => matchesSearch(f, category))
          : false);
      const count = features.filter((f) => f.default).length;
      const icon = CATEGORY_ICONS[category.key] || CATEGORY_ICONS.misc;
      details.innerHTML = `<summary>
        <span class="group-icon" aria-hidden="true"><svg viewBox="0 0 24 24"
          fill="none" stroke="currentColor" stroke-width="1.8"
          stroke-linecap="round" stroke-linejoin="round">${icon}</svg></span>
        <span class="group-name">${esc(label)}</span>
        <span class="muted small">${features.length} ${
          english ? "items" : "项"}${count
            ? (english ? ` · ${count} default` : ` · 默认 ${count}`) : ""}</span>
      </summary>`;
      const list = document.createElement("div");
      list.className = "feature-list";
      features.forEach((feature) => {
        const title = english && feature.title_en
          ? feature.title_en : feature.title;
        const description = english && feature.description_en
          ? feature.description_en : (feature.description || feature.title);
        const item = document.createElement("label");
        item.className = "feature-item";
        item.title = description;
        item.dataset.search = [feature.title, feature.title_en || "",
          feature.description || "", feature.description_en || "",
          feature.handler, category.name, label, feature.checkbox]
          .join(" ").toLowerCase();
        const input = document.createElement("input");
        input.type = "checkbox";
        input.value = feature.checkbox;
        input.dataset.handler = feature.handler;
        input.checked = hadList ? previous.has(feature.checkbox)
          : !!feature.default;
        item.classList.toggle("checked", input.checked);
        input.addEventListener("change", () => {
          item.classList.toggle("checked", input.checked);
          refreshSelected();
          renderRecentFeatures();
        });
        const span = document.createElement("span");
        span.innerHTML = `<span class="ftitle">${esc(title)}</span>` +
          (feature.needs && feature.needs.length
            ? ` <span class="muted small">[${feature.needs.join(", ")}]</span>`
            : "");
        item.appendChild(input);
        item.appendChild(span);
        list.appendChild(item);
      });
      details.appendChild(list);
      container.appendChild(details);
    });
    state.featureCount = (meta.features || []).length;
    setText("#feature-total", english
      ? `${state.featureCount} features`
      : `${state.featureCount} 个功能`);
    filterFeatures();
  }

  function matchesSearch(feature, category) {
    const query = (state.featureSearch || "").toLowerCase();
    if (!query) return true;
    return [feature.title, feature.title_en || "",
      feature.description || "", feature.description_en || "",
      feature.handler, category.name, category.name_en || "",
      feature.checkbox].join(" ").toLowerCase().includes(query);
  }


  function renderPlugins(plugins) {
    state.plugins = plugins || [];
    const about = $("#about-tools");
    if (!about) return;
    // User tools are also shown in the tools menu via the manage dialog.
  }

  function renderTools(tools) {
    const box = $("#about-tools");
    if (!box) return;
    const names = {
      tshark: "tshark", wireshark: "Wireshark", java: "Java",
      aircrack: "aircrack-ng", hashcat: "hashcat", john: "John",
      foremost: "foremost", binwalk: "binwalk", pcapfix: "pcapfix",
      etl2pcapng: "etl2pcapng", pyrdp_player: "pyrdp-player",
      openssl: "openssl",
    };
    box.innerHTML = Object.entries(tools).map(([key, info]) => `
      <div class="tool-item" title="${esc(info.path || "未找到")}">
        <span class="dot ${info.available ? "ok" : ""}"></span>
        <span>${esc(names[key] || key)}</span>
        <span class="muted small">${info.available ? "可用" : "未安装"}</span>
      </div>`).join("");
  }

  function renderRuntime() {
    const box = $("#about-runtime");
    if (!box) return;
    const p = state.meta.paths;
    const features = (state.meta.features || []).length;
    const categories = (state.meta.categories || []).length;
    box.innerHTML = `
      <dt>版本</dt><dd>${esc(state.meta.version)}</dd>
      <dt>功能</dt><dd>${features} 项 · ${categories} 类</dd>
      <dt>用户目录</dt><dd>${esc(p.user)}</dd>
      <dt>日志目录</dt><dd>${esc(p.logs)}</dd>
      <dt>缓存目录</dt><dd>${esc(p.cache)}</dd>
      <dt>内置字典</dt><dd>${esc(p.wordlist)}</dd>`;
  }

  /* -------------------------------------------------------------- theme */
  function applyTheme(key, persist = false) {
    const theme = (state.meta.themes || []).find((t) => t.key === key)
      || (state.meta.themes || [])[0];
    if (!theme) return;
    Object.entries(theme.colors || {}).forEach(([name, value]) => {
      document.documentElement.style.setProperty(`--${name}`, value);
    });
    document.documentElement.dataset.theme = theme.key;
    $("#theme-select").value = theme.key;
    if (persist) {
      saveConfig("config", { theme: theme.key }).catch(() => {});
      localStorage.setItem("fnet.theme", theme.key);
    }
  }

  /* ------------------------------------------------------------ logging */
  function parseQuery() {
    const query = val("log-search");
    if (!query) return null;
    try { return new RegExp(query, "i"); }
    catch (error) { return { test: (text) => text.toLowerCase().includes(query.toLowerCase()), literal: query }; }
  }

  function recordMatches(record) {
    const level = val("log-level") || "all";
    if (level !== "all" && record.level !== level) return false;
    const query = parseQuery();
    if (!query) return true;
    const matched = query.test(record.text) || query.test(record.line || "");
    if (checked("log-filter")) return matched;
    return true;
  }

  function highlight(text) {
    const query = val("log-search");
    if (!query) return esc(text);
    try {
      const rx = new RegExp(`(${query})`, "gi");
      return String(text).split(rx).map((part, index) =>
        index % 2 ? `<mark>${esc(part)}</mark>` : esc(part)).join("");
    } catch (error) {
      return esc(text);
    }
  }

  function frameLinks(html) {
    // Log lines use "帧 123" or a leading "[123]"; make the number clickable.
    return String(html).replace(
      /^\[(?:<mark>)?(\d+)(?:<\/mark>)?\]|帧(\s*)(?:<mark>)?(\d+)(?:<\/mark>)?/g,
      (match, bracket, space, frame) => {
        const number = bracket || frame;
        return `<button type="button" class="frame-link" data-frame="${number}" ` +
          `title="查看数据包 ${number}">帧${space || " "}${number}</button>`;
      });
  }

  function logLineHtml(record) {
    return `<span class="log-time">${esc(record.time || nowTime())}</span> ` +
      `<span class="log-tag">${esc(record.tag || "[*]")}</span> ` +
      `<span class="log-text">${frameLinks(highlight(record.text || ""))}</span>`;
  }

  function appendRecord(record) {
    if (!recordMatches(record)) return;
    const log = $("#log");
    const empty = $(".log-empty", log);
    if (empty) empty.remove();
    const line = document.createElement("div");
    line.className = `log-line ${record.level || "info"}`;
    line.innerHTML = logLineHtml(record);
    log.appendChild(line);
    while (log.childElementCount > 6000) log.removeChild(log.firstElementChild);
    if (checked("auto-scroll")) log.scrollTop = log.scrollHeight;
  }

  function reRenderLog() {
    const log = $("#log");
    log.innerHTML = "";
    const visible = state.logs.filter(recordMatches);
    visible.slice(-4000).forEach((record) => {
      // Bypass the filter check again (already filtered).
      const line = document.createElement("div");
      line.className = `log-line ${record.level || "info"}`;
      line.innerHTML = logLineHtml(record);
      log.appendChild(line);
    });
    if (!visible.length) {
      log.innerHTML = '<div class="log-empty">暂无日志。选择一个输入文件和功能后点击“开始分析”。</div>';
    }
    if (checked("auto-scroll")) log.scrollTop = log.scrollHeight;
  }

  function appendLogs(records) {
    (records || []).forEach((record) => {
      state.logs.push(record);
      appendRecord(record);
    });
    if (state.logs.length > 30000) state.logs.splice(0, state.logs.length - 30000);
  }

  function appendSystem(text, level = "info") {
    String(text || "").split("\n").forEach((line) => {
      if (!line.trim()) return;
      const record = {
        seq: `local-${++state.localSeq}`, time: nowTime(),
        level, tag: level === "error" ? "[-]" : level === "warn" ? "[!]" :
          level === "good" ? "[+]" : "[*]", text: line,
      };
      state.logs.push(record);
      appendRecord(record);
    });
  }

  /* --------------------------------------------------------------- jobs */
  function collectParams() {
    return {
      keywords: val("keywords"),
      auto_regex: checked("auto_regex"),
      post_only: checked("post_only"),
      decode: checked("decode_aux"),
      webshell_mode: val("webshell_mode") || "off",
      webshell_password: val("webshell_password"),
      webshell_filter: val("webshell_filter"),
      shiro_mode: val("shiro_mode"),
      shiro_remember: val("shiro_remember") || "rememberMe",
      shiro_key: val("shiro_key"),
      shiro_enctype: val("shiro_enctype"),
      winrm_auth: val("winrm_auth"),
      winrm_ntlm: val("winrm_ntlm"),
      winrm_password: val("winrm_password"),
      winrm_port: val("winrm_port"),
      sql_regex: val("sql_regex"),
      sql_success: val("sql_success"),
      sql_compare: val("sql_compare"),
      sql_time_threshold: val("sql_time_threshold"),
      sql_char: checked("sql_char"),
      sql_reverse: checked("sql_reverse"),
      sql_log: val("sql_log"),
      log_extra_paths: val("log_extra_paths"),
      log_correlate_window: val("log_correlate_window"),
      log_cluster_gap: val("log_cluster_gap"),
      log_risk_threshold: val("log_risk_threshold"),
      wordlist: val("wordlist"),
    };
  }

  function selectedFeatures() {
    return $$("#features input[type=checkbox]:checked").map((el) => el.value);
  }

  function refreshSelected() {
    const count = selectedFeatures().length;
    setText("#selected-count", `${count} / ${state.featureCount} 项`);
    $("#start-btn").disabled = !state.pcap || count === 0;
    $("#toggle-all").textContent = count === state.featureCount ? "全不选" : "全选";
    $$("#features .feature-item").forEach((item) => {
      const box = item.querySelector("input[type=checkbox]");
      item.classList.toggle("checked", !!(box && box.checked));
    });
  }

  /* --------------------------------------------------- feature finder */
  function filterFeatures() {
    const query = (state.featureSearch || "").toLowerCase();
    const english = state.language === "en";
    let visible = 0;
    $$("#features .feature-group").forEach((group) => {
      let groupVisible = 0;
      $$(".feature-item", group).forEach((item) => {
        const match = !query || item.dataset.search.includes(query);
        item.classList.toggle("hidden", !match);
        if (match) groupVisible += 1;
      });
      group.classList.toggle("hidden", groupVisible === 0);
      if (query && groupVisible) group.open = true;
      visible += groupVisible;
    });
    $("#feature-empty").classList.toggle("hidden", !query || visible > 0);
    setText("#feature-total", query
      ? `${visible} / ${state.featureCount} ${english ? "matched" : "匹配"}`
      : `${state.featureCount} ${english ? "features" : "个功能"}`);
  }

  function restoreRecentFeatures() {
    try {
      const raw = JSON.parse(localStorage.getItem("fnet.recentFeatures") || "[]");
      state.recentFeatures = Array.isArray(raw)
        ? raw.filter((item) => typeof item === "string" && item).slice(0, 8) : [];
    } catch (error) {
      state.recentFeatures = [];
    }
  }

  function rememberFeatures(features) {
    const known = new Set(state.features.map((feature) => feature.checkbox));
    const next = features.filter((item) => known.has(item));
    state.recentFeatures = [...new Set([...next, ...state.recentFeatures])].slice(0, 8);
    try {
      localStorage.setItem("fnet.recentFeatures",
        JSON.stringify(state.recentFeatures));
    } catch (error) {}
    renderRecentFeatures();
  }

  function renderRecentFeatures() {
    const box = $("#recent-features");
    if (!box) return;
    const byCheckbox = new Map(state.features.map((feature) =>
      [feature.checkbox, feature]));
    const items = state.recentFeatures
      .map((checkbox) => byCheckbox.get(checkbox))
      .filter(Boolean);
    box.innerHTML = "";
    box.classList.toggle("hidden", !items.length);
    if (!items.length) return;
    const title = document.createElement("span");
    title.className = "recent-label";
    title.textContent = "最近使用";
    box.appendChild(title);
    items.forEach((feature) => {
      const input = $$("#features input[type=checkbox]")
        .find((el) => el.value === feature.checkbox);
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = `recent-chip${input && input.checked ? " active" : ""}`;
      chip.textContent = feature.title;
      chip.title = feature.description || feature.handler;
      chip.addEventListener("click", () => {
        const box2 = $$("#features input[type=checkbox]")
          .find((el) => el.value === feature.checkbox);
        if (!box2) return;
        box2.checked = !box2.checked;
        box2.dispatchEvent(new Event("change"));
      });
      box.appendChild(chip);
    });
  }

  /* ------------------------------------------------------- report export */
  function reportCatalog() {
    return (state.meta.report && state.meta.report.sections) || [];
  }

  function restoreReportSections() {
    const keys = new Set(reportCatalog().map((item) => item.key));
    const fallback = (state.meta.report && state.meta.report.default_sections) || [];
    let saved = [];
    try {
      saved = JSON.parse(localStorage.getItem("fnet.reportSections") || "[]");
    } catch (error) {
      saved = [];
    }
    if (!Array.isArray(saved)) saved = [];
    saved = saved.filter((key) => keys.has(key));
    state.reportSections = saved.length ? saved : fallback.filter((key) => keys.has(key));
  }

  function saveReportSections(sections) {
    state.reportSections = sections;
    try {
      localStorage.setItem("fnet.reportSections", JSON.stringify(sections));
    } catch (error) {}
  }

  function reportUrl(jobId, format = "html", inline = false) {
    const params = new URLSearchParams({
      job: jobId, format, token: TOKEN,
    });
    if (state.reportSections.length) {
      params.set("sections", state.reportSections.join(","));
    }
    if (inline) params.set("inline", "1");
    return `/api/report?${params.toString()}`;
  }


  function statusLabel(status) {
    const keys = {
      running: "status_running", paused: "status_paused", done: "status_done",
      cancelled: "status_cancelled", error: "status_error",
    };
    if (keys[status]) return t(keys[status]);
    return { queued: state.language === "en" ? "Queued" : "排队",
      interrupted: state.language === "en" ? "Interrupted" : "已中断" }[status]
      || status;
  }

  async function loadHistory() {
    const data = await api("/api/history");
    state.history = data.jobs || [];
    setText("#history-count", String(state.history.length));
    renderHistory();
  }

  function renderHistory() {
    const box = $("#history");
    if (!box) return;
    if (!state.history.length) {
      box.innerHTML = '<div class="muted">还没有历史任务。完成一次分析后会自动记录。</div>';
      return;
    }
    box.innerHTML = "";
    state.history.forEach((job) => {
      const row = document.createElement("div");
      row.className = "history-item";
      const status = job.status || "";
      const titles = (job.feature_titles || []).join("、");
      const when = job.finished || job.started || job.created || "";
      row.innerHTML = `
        <div class="history-main">
          <div class="history-title">
            <span class="badge ${status === "done" ? "ok" : status === "running" ? "running" : status === "error" ? "bad" : ""}">${esc(statusLabel(status))}</span>
            <strong>${esc(job.pcap_name || job.pcap || "未知文件")}</strong>
          </div>
          <div class="muted small">${esc(when)} · ${(job.features || []).length} 个功能 · 任务 ${esc(String(job.id).slice(0, 8))}</div>
          <div class="muted small history-features">${esc(titles)}</div>
        </div>
        <div class="history-actions">
          <a class="ghost small" href="${esc(reportUrl(job.id))}" download title="下载 HTML 报告">HTML</a>
          <button class="ghost small" data-history="view" data-id="${esc(job.id)}">查看报告</button>
          <button class="ghost small" data-history="rerun" data-id="${esc(job.id)}">重跑</button>
          <button class="ghost small danger-text" data-history="delete" data-id="${esc(job.id)}">删除</button>
        </div>`;
      box.appendChild(row);
    });
  }

  async function viewHistory(jobId) {
    const data = await api(`/api/history/${encodeURIComponent(jobId)}`);
    const job = data.job || {};
    const params = Object.entries(job.params || {})
      .filter(([, value]) => value !== "" && value !== null && value !== undefined)
      .map(([key, value]) => `${key}=${value}`).join("  ") || "（无）";
    const files = (data.artifacts || []).map((item) => item.name).join("、") || "（无）";
    const report = data.report || "（该任务没有报告文本）";
    let findingsLine = "（无）";
    try {
      const found = await api(`/api/findings?job=${encodeURIComponent(jobId)}&limit=1`);
      const kinds = Object.entries(found.kinds || {}).map(([key, count]) =>
        `${state.findingsKinds[key] || key}×${count}`).join(" · ");
      findingsLine = `${found.total} 条${kinds ? `（${kinds}）` : ""}` +
        (found.derived ? " · 由日志推断" : "");
    } catch (error) {}
    await openModal({
      title: `任务报告 · ${String(jobId).slice(0, 8)}`,
      text: `参数: ${params}\n结构化结果: ${findingsLine}\n产出: ${files}\n\n${report}` +
        (data.report_truncated ? "\n\n… 报告过长，已截断。" : ""),
      hideCancel: true, okText: "关闭",
    });
  }

  async function rerunHistory(jobId) {
    const job = state.history.find((item) => item.id === jobId);
    if (!job) { toast("找不到历史任务", "warn"); return; }
    setPcap(job.pcap, job.pcap_name);
    const wanted = new Set(job.features || []);
    $$("#features input[type=checkbox]").forEach((input) => {
      input.checked = wanted.has(input.value) || wanted.has(input.dataset.handler);
    });
    refreshSelected();
    renderRecentFeatures();
    rememberFeatures(job.features || []);
    await startJob(job.features || [], job.params || {}, "重跑历史任务");
  }

  async function deleteHistory(jobId) {
    if (!confirm("确定删除该历史任务及其产出文件吗？")) return;
    await api(`/api/history/${encodeURIComponent(jobId)}/delete`, {
      method: "POST", body: {},
    });
    toast("历史任务已删除", "good");
    if (state.jobId === jobId) {
      state.jobId = null;
      state.logs = [];
      state.artifacts = [];
      $("#log").innerHTML = "";
      $("#artifacts").innerHTML = "";
      setText("#artifact-count", "0");
      resetFindings();
      setText("#job-state", "空闲");
      $("#job-state").className = "badge muted";
      setProgress(0);
      const zip = $("#download-zip");
      zip.classList.add("disabled");
      zip.removeAttribute("href");
      $("#start-btn").disabled = selectedFeatures().length === 0 || !state.pcap;
    }
    await loadHistory();
  }

  function applyInitial(initial) {
    // ``fnet capture.pcapng --features ...`` preselects both the capture and
    // the feature checkboxes; without it the WebUI simply uses the defaults.
    if (!initial) return;
    if (initial.pcap) {
      setPcap(initial.pcap);
      toast(`已预选${inputKindOf(initial.pcap) === "log" ? "日志" : "流量包"}: `
        + `${initial.pcap.split(/[\\/]/).pop()}`, "good");
    }
    const boxes = $$("#features input[type=checkbox]");
    if (Array.isArray(initial.features) && initial.features.length) {
      const wanted = new Set(initial.features);
      boxes.forEach((box) => {
        box.checked = wanted.has(box.value);
        box.dispatchEvent(new Event("change"));
      });
    }
    renderRecentFeatures();
  }

  const LOG_FILE_RE = /\.(log|txt|out|jsonl|ndjson|json|csv|tsv)$/i;

  function inputKindOf(path) {
    return LOG_FILE_RE.test(String(path || "")) ? "log" : "pcap";
  }

  function applyInputKindDefaults(path) {
    const kind = inputKindOf(path);
    if (state.inputKind === kind) return;
    const previous = state.inputKind;
    state.inputKind = kind;
    // Keep the historical pcap workflow intact: a user may tick extra
    // features before dropping the first capture.  Log inputs are a new path
    // and always start from every ``log``-category feature.
    if (kind !== "log" && !previous) return;
    const boxes = $$("#features input[type=checkbox]");
    if (!boxes.length) return;
    const byValue = new Map((state.features || []).map((feature) =>
      [feature.checkbox, feature]));
    boxes.forEach((box) => {
      const feature = byValue.get(box.value);
      box.checked = kind === "log"
        ? !!(feature && feature.category === "log")
        : !!(feature && feature.default);
      box.dispatchEvent(new Event("change"));
    });
    toast(kind === "log"
      ? "已按日志文件勾选日志分析功能（.log / .txt / .jsonl / .csv）"
      : "已恢复抓包的默认功能", "good", 5000);
  }

  function setPcap(path, name, size) {
    state.pcap = path || "";
    state.fileName = name || (path ? path.split(/[\\/]/).pop() : "");
    applyInputKindDefaults(state.pcap);
    setText("#file-name", state.fileName || "未选择输入文件");
    setText("#file-meta", state.pcap
      ? `${state.pcap}${size ? ` · ${fmtSize(size)}` : ""}`
      : "选择或上传一个抓包或日志文件开始");
    setVal("pcap-path", state.pcap);
    refreshSelected();
  }

  function uploadFile(file, options = {}) {
    if (!file) return Promise.resolve(null);
    const { kind = "", onProgress = null } = options;
    return new Promise((resolve, reject) => {
      const form = new FormData();
      form.append("file", file, file.name);
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/upload");
      xhr.setRequestHeader("X-Fnet-Token", TOKEN);
      if (kind) xhr.setRequestHeader("X-Kind", kind);
      state.upload = { xhr, name: file.name };
      if (onProgress && xhr.upload) {
        xhr.upload.onprogress = (event) => {
          if (event.lengthComputable) onProgress(event.loaded / event.total);
        };
      }
      xhr.onload = () => {
        state.upload = null;
        let data = null;
        try { data = JSON.parse(xhr.responseText || "{}"); }
        catch (error) { data = { ok: false, error: xhr.responseText }; }
        if (xhr.status >= 200 && xhr.status < 300 && data.ok !== false) {
          resolve(data);
        } else {
          reject(new Error(data.error || `HTTP ${xhr.status}`));
        }
      };
      xhr.onerror = () => {
        state.upload = null;
        reject(new Error("上传连接失败"));
      };
      xhr.onabort = () => {
        state.upload = null;
        reject(new Error("上传已取消"));
      };
      xhr.send(form);
    });
  }

  function cancelUpload() {
    if (!state.upload) return false;
    state.upload.xhr.abort();
    state.upload = null;
    setProgress(0);
    return true;
  }

  function uploadProgress(frac, name) {
    const pct = Math.max(0, Math.min(100, Math.round(frac * 100)));
    setProgress(pct);
    setText("#file-meta", `上传 ${name} · ${pct}%（Esc 取消）`);
  }

  async function uploadFiles(files) {
    const list = Array.from(files || []).filter(Boolean);
    if (!list.length) return;
    if (list.length === 1) {
      toast(`正在上传 ${list[0].name}…`, "info");
      try {
        const data = await uploadFile(list[0], {
          onProgress: (frac) => uploadProgress(frac, list[0].name),
        });
        setPcap(data.path, data.name, data.size);
        setProgress(100);
        toast(`已加载 ${data.name}`, "good");
      } catch (error) {
        setProgress(0);
        toast(error.message, "error", 7000);
      }
      return;
    }
    toast(`正在上传 ${list.length} 个文件…`, "info", 6000);
    const uploaded = [];
    try {
      for (const [index, file] of list.entries()) {
        uploaded.push(await uploadFile(file, {
          onProgress: (frac) => uploadProgress(
            (index + frac) / list.length, `${file.name} (${index + 1}/${list.length})`),
        }));
      }
      setProgress(100);
      setPcap(uploaded[0].path, uploaded[0].name, uploaded[0].size);
      toast(`已上传 ${uploaded.length} 个文件，开始批量排队`, "good", 5000);
      await startBatch(uploaded.map((item) => item.path));
    } catch (error) {
      setProgress(0);
      toast(error.message, "error", 8000);
    }
  }

  async function startBatch(paths) {
    if (!paths || !paths.length) { toast("请先选择输入文件", "warn"); return; }
    const features = selectedFeatures();
    if (!features.length) { toast("请至少选择一个分析功能", "warn"); return; }
    const concurrency = Number(val("batch-concurrency")) || 1;
    try {
      const data = await api("/api/batch", {
        method: "POST",
        body: {
          pcaps: paths, features, params: collectParams(), concurrency,
        },
      });
      state.batch.ids = (data.jobs || []).map((job) => job.id);
      state.batch.jobs = data.jobs || [];
      state.batch.summary = data.summary || null;
      state.batch.active = state.batch.jobs.length > 0;
      rememberFeatures(features);
      renderBatch();
      switchTab("batch");
      toast(`已提交 ${state.batch.jobs.length} 个任务（并发 ${concurrency}）`,
        "good", 4000);
      pollBatch();
    } catch (error) {
      toast(error.message, "error", 8000);
    }
  }

  async function pollBatch() {
    if (!state.batch.ids.length) { renderBatch(); return; }
    clearTimeout(state.batch.timer);
    state.batch.timer = null;
    try {
      const [data, batch] = await Promise.all([
        api("/api/jobs"), api("/api/batch"),
      ]);
      const wanted = new Set(state.batch.ids);
      const jobs = (data.jobs || []).filter((job) => wanted.has(job.id));
      if (jobs.length) state.batch.jobs = jobs;
      state.batch.summary = batch.summary || state.batch.summary;
      state.batch.active = jobs.some((job) => !TERMINAL.has(job.status));
      renderBatch();
      if (state.batch.active) {
        state.batch.timer = setTimeout(pollBatch, 1500);
      } else {
        loadHistory().catch(() => {});
        state.batch.active = false;
      }
    } catch (error) {
      toast(`批量队列刷新失败：${error.message}`, "error", 7000);
      state.batch.timer = setTimeout(pollBatch, 5000);
    }
  }

  function orderedBatchJobs(jobs) {
    const pending = (state.batch.summary && state.batch.summary.pending) || [];
    const rank = new Map(pending.map((id, index) => [id, index]));
    const weight = (job) => job.status === "running" ? 0
      : job.status === "queued" ? 1 : 2;
    return [...jobs].sort((left, right) => {
      const diff = weight(left) - weight(right);
      if (diff) return diff;
      if (left.status === "queued" && right.status === "queued") {
        return (rank.get(left.id) ?? 1e9) - (rank.get(right.id) ?? 1e9);
      }
      return String(left.created || "").localeCompare(String(right.created || ""));
    });
  }

  function renderBatch() {
    const box = $("#batch");
    if (!box) return;
    const jobs = state.batch.jobs || [];
    const snapshot = state.batch.summary || {};
    setText("#batch-count", String(snapshot.total ?? jobs.length));
    const counted = jobs.reduce((acc, job) => {
      acc[job.status] = (acc[job.status] || 0) + 1;
      return acc;
    }, {});
    const paused = snapshot.paused ? " · 已暂停" : "";
    const summary = jobs.length
      ? `共 ${jobs.length} 个 · 运行 ${counted.running || 0} · 排队 ${counted.queued || 0} · 完成 ${counted.done || 0} · 失败 ${counted.error || 0} · 并发 ${snapshot.concurrency || val("batch-concurrency") || 1}${paused}`
      : "";
    setText("#batch-summary", summary);
    const pause = $("#batch-pause");
    if (pause) pause.textContent = snapshot.paused ? "继续队列" : "暂停队列";
    const merge = $("#batch-merge");
    if (merge) merge.disabled = !jobs.some((job) => job.status === "done");
    if (!jobs.length) {
      box.innerHTML = '<div class="muted">还没有批量任务。一次选择多个文件后会自动开始排队。</div>';
      return;
    }
    const rows = orderedBatchJobs(jobs).map((job) => {
      const done = TERMINAL.has(job.status);
      const pct = Math.max(0, Math.min(100, Number(job.progress) || 0));
      const badge = job.status === "done" ? "ok"
        : job.status === "error" ? "bad"
          : job.status === "running" ? "running" : "";
      const report = done && job.status === "done"
        ? `<a class="ghost small" href="${esc(reportUrl(job.id))}" download>报告</a>`
        : "";
      const cancel = done ? ""
        : `<button class="ghost small danger-text" data-batch="cancel" data-id="${esc(job.id)}">取消</button>`;
      const draggable = job.status === "queued";
      const grip = draggable
        ? '<span class="batch-grip" title="拖拽调整排队顺序">⋮⋮</span>' : "";
      return `
        <tr data-id="${esc(job.id)}" draggable="${draggable ? "true" : "false"}"
          class="${draggable ? "batch-queued" : ""}">
          <td class="batch-grip-cell">${grip}</td>
          <td><span class="badge ${badge}">${esc(statusLabel(job.status))}</span></td>
          <td class="batch-name">${esc(job.pcap_name || job.pcap || "未知文件")}</td>
          <td>
            <div class="batch-progress">
              <div class="batch-bar"><div style="width:${pct}%"></div></div>
              <span class="muted small">${pct}%${job.current ? ` · ${esc(job.current)}` : ""}</span>
            </div>
          </td>
          <td>
            <div class="batch-actions">
              <button class="ghost small" data-batch="view" data-id="${esc(job.id)}">日志</button>
              ${report}${cancel}
            </div>
          </td>
        </tr>`;
    }).join("");
    box.innerHTML = `
      <table class="batch-table">
        <thead><tr><th></th><th>状态</th><th>文件</th><th>进度</th><th>操作</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }

  async function batchControl(action, body = {}) {
    try {
      const data = await api(`/api/batch/${action}`, {
        method: "POST", body,
      });
      if (data.summary) state.batch.summary = data.summary;
      renderBatch();
      if (data.summary) state.batch.active = data.summary.active > 0;
      if (state.batch.active) pollBatch();
      return data;
    } catch (error) {
      toast(error.message, "error", 7000);
      return null;
    }
  }

  async function toggleBatchPause() {
    const paused = !!(state.batch.summary && state.batch.summary.paused);
    const data = await batchControl(paused ? "resume" : "pause");
    if (data) toast(paused ? "队列已继续" : "队列已暂停", "good", 1800);
  }

  async function reorderBatch(ids) {
    const data = await batchControl("reorder", { ids });
    if (data) toast("排队顺序已更新", "good", 1600);
  }

  async function mergeBatchReport() {
    const ids = (state.batch.jobs || [])
      .filter((job) => job.status === "done").map((job) => job.id);
    if (!ids.length) { toast("还没有已完成的任务可合并", "warn"); return; }
    const values = await openModal({
      title: `合并 ${ids.length} 个任务的报告`,
      fields: [{
        name: "format", label: "格式", type: "select", value: "html",
        options: [
          { value: "html", label: "HTML（可直接打印为 PDF）" },
          { value: "markdown", label: "Markdown" },
        ],
      }],
      okText: "下载",
    });
    if (!values) return;
    const url = `/api/batch/report?jobs=${encodeURIComponent(ids.join(","))}` +
      `&format=${encodeURIComponent(values.format || "html")}` +
      `&token=${encodeURIComponent(TOKEN)}`;
    window.location.href = url;
    toast(`已开始下载 ${ids.length} 个任务的合并报告`, "good", 2400);
  }

  function viewBatchJob(jobId) {
    const job = (state.batch.jobs || []).find((item) => item.id === jobId);
    if (!job) { toast("找不到该批量任务", "warn"); return; }
    setPcap(job.pcap, job.pcap_name);
    attachJob(job, `批量任务 · ${statusLabel(job.status)}`);
  }

  async function cancelBatchJob(jobId) {
    try {
      await api(`/api/jobs/${encodeURIComponent(jobId)}/cancel`, {
        method: "POST", body: {},
      });
      toast("已发送取消请求", "warn", 2200);
      pollBatch();
    } catch (error) {
      toast(error.message, "error", 7000);
    }
  }

  function clearBatch() {
    const before = (state.batch.jobs || []).length;
    state.batch.jobs = (state.batch.jobs || [])
      .filter((job) => !TERMINAL.has(job.status));
    state.batch.ids = state.batch.jobs.map((job) => job.id);
    renderBatch();
    if (before !== state.batch.jobs.length) toast("已清空完成的任务", "good", 1800);
  }

  /* ------------------------------------------------------ visualization */
  function parseHierarchy(text) {
    const skip = new Set(["frame", "eth", "ip", "ipv6", "tcp", "udp"]);
    const items = [];
    String(text || "").split("\n").forEach((line) => {
      const match = line.match(/^\s*([\w.-]+)\s+frames:(\d+)\s+bytes:(\d+)\s*$/);
      if (!match || skip.has(match[1])) return;
      items.push({
        label: match[1], frames: Number(match[2]) || 0,
        bytes: Number(match[3]) || 0,
      });
    });
    return items.sort((a, b) => b.bytes - a.bytes).slice(0, 10);
  }

  function parseConversations(text) {
    const items = [];
    String(text || "").split("\n").forEach((line) => {
      if (!line.includes("<->")) return;
      const [left, rest] = line.split("<->");
      const match = rest.match(
        /([\d,]+)\s+([\d,]+) bytes\s+([\d,]+)\s+([\d,]+) bytes\s+([\d,]+)\s+([\d,]+) bytes/);
      if (!match) return;
      const peer = rest.trim().split(/\s+/)[0] || "?";
      items.push({
        label: `${left.trim()} ↔ ${peer}`,
        frames: Number(match[5].replace(/,/g, "")) || 0,
        bytes: Number(match[6].replace(/,/g, "")) || 0,
      });
    });
    return items.sort((a, b) => b.bytes - a.bytes).slice(0, 8);
  }

  function renderBars(selector, items, metric, emptyText) {
    const box = $(selector);
    if (!box) return;
    if (!items || !items.length) {
      box.classList.add("muted");
      box.textContent = emptyText || "没有可用于图表的数据";
      return;
    }
    const value = (item) => Math.max(0, Number(item[metric]) || 0);
    const max = Math.max(...items.map(value), 1);
    box.classList.remove("muted");
    const clickable = selector === "#viz-protocols";
    const unit = state.viz.log ? "条" : "帧";
    box.innerHTML = items.map((item) => {
      const width = Math.max(1, Math.round(value(item) / max * 100));
      const label = metric === "frames"
        ? `${item.frames} ${unit}` : fmtSize(item.bytes);
      return `
        <div class="viz-bar-row${clickable ? " drillable" : ""}"
          title="${esc(item.label)} · ${esc(label)}${clickable ? " · 点击下钻" : ""}"
          ${clickable ? `data-protocol="${esc(item.label)}" role="button" tabindex="0"` : ""}>
          <span class="viz-bar-label">${esc(item.label)}</span>
          <span class="viz-bar-track"><span style="width:${width}%"></span></span>
          <span class="viz-bar-value">${esc(label)}</span>
        </div>`;
    }).join("");
  }

  function timelineVisible() {
    const points = (state.viz.timeline && state.viz.timeline.points) || [];
    if (!state.viz.zoom || !points.length) return { points, start: 0, end: points.length - 1 };
    const start = Math.max(0, Math.min(state.viz.zoom[0], points.length - 1));
    const end = Math.max(start, Math.min(state.viz.zoom[1], points.length - 1));
    return { points: points.slice(start, end + 1), start, end };
  }

  function renderTimeline() {
    const box = $("#viz-timeline");
    if (!box) return;
    const data = state.viz.timeline;
    const all = (data && data.points) || [];
    if (!all.length) {
      box.classList.add("muted");
      box.textContent = (data && data.text) || "没有时间线数据";
      state.viz.svg = "";
      return;
    }
    const { points, start, end } = timelineVisible();
    const isLog = !!(data && data.kind === "log");
    const metric = isLog || val("viz-metric") === "frames" ? "frames" : "bytes";
    const unit = isLog ? "条" : "帧";
    const max = Math.max(...points.map((point) => Number(point[metric]) || 0), 1);
    box.classList.remove("muted");
    const width = 1000, height = 260, left = 42, right = 12, top = 12, bottom = 34;
    const plotW = width - left - right, plotH = height - top - bottom;
    const slot = plotW / Math.max(points.length, 1);
    const gap = Math.max(0.5, slot * 0.12);
    const bars = points.map((point, index) => {
      const amount = Number(point[metric]) || 0;
      const barH = amount ? Math.max(2, Math.round(amount / max * plotH)) : 1;
      const x = left + index * slot + gap / 2;
      const y = top + plotH - barH;
      const label = `${(point.time - (data.start || 0)).toFixed(2)}s · ${point.frames} ${unit} · ${fmtSize(point.bytes)}`;
      return `<rect class="tl-bar" x="${x.toFixed(2)}" y="${y.toFixed(2)}"
        width="${Math.max(1, slot - gap).toFixed(2)}" height="${barH}"
        data-index="${start + index}" data-start="${point.time}"
        data-end="${point.time + ((data.duration || 0) / Math.max(all.length, 1))}">
        <title>${esc(label)}</title></rect>`;
    }).join("");
    const span = data.duration || 0;
    const lowTime = points.length ? points[0].time - (data.start || 0) : 0;
    const highTime = points.length ? points[points.length - 1].time - (data.start || 0) : span;
    const grid = [0, 0.25, 0.5, 0.75, 1].map((ratio) => {
      const x = left + plotW * ratio;
      const stamp = lowTime + (highTime - lowTime) * ratio;
      return `<line class="tl-grid" x1="${x}" y1="${top}" x2="${x}" y2="${top + plotH}"></line>
        <text class="tl-label" x="${x}" y="${height - 10}" text-anchor="middle">${stamp.toFixed(1)}s</text>`;
    }).join("");
    const svg = `<svg id="viz-timeline-svg" viewBox="0 0 ${width} ${height}"
      role="img" aria-label="流量时间线" xmlns="http://www.w3.org/2000/svg">
      <rect class="tl-bg" x="0" y="0" width="${width}" height="${height}"></rect>
      ${grid}
      <line class="tl-axis" x1="${left}" y1="${top + plotH}" x2="${left + plotW}" y2="${top + plotH}"></line>
      ${bars}
      <rect id="tl-select" class="tl-select hidden" x="0" y="${top}" width="0" height="${plotH}"></rect>
    </svg>
    <div class="muted small">${esc(data.text || "")} · 当前显示 ${points.length}/${all.length} 个时间桶（滚轮缩放，拖拽框选，双击重置）</div>`;
    box.innerHTML = svg;
    state.viz.svg = box.querySelector("svg").outerHTML;
    bindTimeline(box.querySelector("svg"), data, all);
  }

  function bindTimeline(svg, data, all) {
    if (!svg) return;
    const left = 42, right = 12, width = 1000;
    const plotW = width - left - right;
    let drag = null;
    const indexAt = (event) => {
      const rect = svg.getBoundingClientRect();
      const x = (event.clientX - rect.left) / rect.width * width;
      const ratio = Math.max(0, Math.min(1, (x - left) / plotW));
      return Math.round(ratio * (all.length - 1));
    };
    svg.addEventListener("wheel", (event) => {
      event.preventDefault();
      const center = indexAt(event);
      const current = state.viz.zoom || [0, all.length - 1];
      const span = Math.max(2, current[1] - current[0]);
      const factor = event.deltaY < 0 ? 0.7 : 1.4;
      const next = Math.max(2, Math.round(span * factor));
      const low = Math.max(0, Math.min(center - Math.round(next / 2),
        Math.max(0, all.length - 1 - next)));
      state.viz.zoom = [low, Math.min(all.length - 1, low + next)];
      renderTimeline();
    }, { passive: false });
    svg.addEventListener("mousedown", (event) => {
      if (event.button !== 0) return;
      drag = { start: indexAt(event), current: indexAt(event) };
      const box = svg.querySelector("#tl-select");
      box.classList.remove("hidden");
    });
    svg.addEventListener("mousemove", (event) => {
      if (!drag) return;
      drag.current = indexAt(event);
      const low = Math.min(drag.start, drag.current);
      const high = Math.max(drag.start, drag.current);
      if (high - low < 1) return;
      const slot = plotW / Math.max(all.length, 1);
      const box = svg.querySelector("#tl-select");
      box.setAttribute("x", (left + low * slot).toFixed(2));
      box.setAttribute("width", (Math.max(1, (high - low + 1) * slot)).toFixed(2));
    });
    svg.addEventListener("mouseup", () => {
      if (!drag) return;
      const low = Math.min(drag.start, drag.current);
      const high = Math.max(drag.start, drag.current);
      drag = null;
      if (high - low >= 2) {
        state.viz.zoom = [low, high];
        renderTimeline();
      } else {
        const box = svg.querySelector("#tl-select");
        if (box) box.classList.add("hidden");
      }
    });
    svg.addEventListener("dblclick", () => {
      state.viz.zoom = null;
      renderTimeline();
    });
    svg.addEventListener("click", (event) => {
      const bar = event.target.closest(".tl-bar");
      if (!bar) return;
      openTimelineBucket(Number(bar.dataset.start), Number(bar.dataset.end));
    });
  }

  async function openTimelineBucket(start, end) {
    if (!state.pcap) return;
    try {
      const data = await api("/api/action", {
        method: "POST",
        body: {
          action: "stats", sub: "timeline_packets", pcap: state.pcap,
          start, end, limit: 200,
        },
      });
      const lines = (data.packets || []).map((item) =>
        `#${item.frame}  ${item.time}s  ${item.protocol || ""}  ` +
        `${item.src || ""} → ${item.dst || ""}  ${item.info || ""}`);
      await openModal({
        title: data.text || "时间线数据包",
        text: lines.join("\n") || "（无数据包）", hideCancel: true,
        okText: "关闭",
      });
    } catch (error) {
      toast(error.message, "error", 7000);
    }
  }

  async function openProtocolDetail(protocol) {
    if (!state.pcap) { toast("请先选择输入文件", "warn"); return; }
    try {
      const data = await api("/api/action", {
        method: "POST",
        body: {
          action: "stats", sub: "protocol", pcap: state.pcap,
          protocol, limit: 300,
        },
      });
      const lines = (data.packets || []).map((item) =>
        `#${item.frame}  ${item.time}s  ${item.protocol || ""}  ` +
        `${item.src || ""} → ${item.dst || ""}  ${item.info || ""}`);
      await openModal({
        title: `${protocol} 协议下钻 · ${lines.length} 个数据包`,
        text: lines.join("\n") || "（无数据包）", hideCancel: true,
        okText: "关闭",
      });
    } catch (error) {
      toast(error.message, "error", 7000);
    }
  }

  function renderTopology() {
    const box = $("#viz-topology");
    if (!box) return;
    const data = state.viz.topologyApi || state.viz.topology;
    const nodes = (data && data.nodes) || [];
    const edges = (data && (data.links || data.edges)) || [];
    if (!nodes.length) {
      box.classList.add("muted");
      box.textContent = (data && data.text) || "没有可用的会话拓扑";
      return;
    }
    box.classList.remove("muted");
    const width = 1000, height = 420, cx = width / 2, cy = height / 2;
    // Log topology carries no byte counts; size nodes/edges by event count.
    const topoLog = !!(data && data.kind === "log");
    const weightOf = (item) => topoLog
      ? Math.max(0, Number(item.frames) || 0)
      : Math.max(0, Number(item.bytes) || 0);
    const maxBytes = Math.max(...nodes.map(weightOf), 1);
    const positions = {};
    nodes.forEach((node, index) => {
      const ratio = index / Math.max(nodes.length, 1);
      const ring = index < 8 ? 105 : 185;
      const angle = ratio * Math.PI * 2 - Math.PI / 2;
      positions[node.id] = {
        x: cx + Math.cos(angle) * ring,
        y: cy + Math.sin(angle) * ring,
        radius: 5 + Math.sqrt(weightOf(node) / maxBytes) * 17,
      };
    });
    const edgeSvg = edges.map((edge) => {
      const a = positions[edge.source], b = positions[edge.target];
      if (!a || !b) return "";
      const weight = 1 + Math.min(7, Math.sqrt(weightOf(edge) /
        Math.max((topoLog ? data.max_frames : data.max_bytes) || maxBytes, 1)) * 9);
      const color = protoColor(edge.protocol);
      return `<line class="topo-edge" x1="${a.x.toFixed(1)}" y1="${a.y.toFixed(1)}"
        x2="${b.x.toFixed(1)}" y2="${b.y.toFixed(1)}"
        stroke="${color}" stroke-width="${weight.toFixed(2)}"><title>${esc(edge.protocol)} · ${edge.frames} 帧 · ${fmtSize(edge.bytes)} · 帧 ${esc(edge.first_frame ?? "")}-${esc(edge.last_frame ?? "")}</title></line>`;
    }).join("");
    const nodeSvg = nodes.map((node) => {
      const pos = positions[node.id];
      const label = node.label || (node.port ? `${node.ip}:${node.port}` : node.ip);
      return `<g class="topo-node" data-node="${esc(node.id)}" tabindex="0" role="button"
        aria-label="按 ${esc(label)} 过滤结果">
        <circle cx="${pos.x.toFixed(1)}" cy="${pos.y.toFixed(1)}" r="${pos.radius.toFixed(1)}"
          fill="${protoColor((node.protocols || [])[0])}"><title>${esc(label)} · ${node.count ?? node.frames ?? 0} ${state.viz.log ? "条" : "帧"} · ${fmtSize(node.bytes)} · ${esc((node.protocols || []).join(", "))}</title></circle>
        <text x="${pos.x.toFixed(1)}" y="${(pos.y + pos.radius + 13).toFixed(1)}"
          text-anchor="middle">${esc(label.length > 24 ? label.slice(0, 23) + "…" : label)}</text>
      </g>`;
    }).join("");
    const protocols = [...new Set(edges.map((edge) => edge.protocol))].slice(0, 8);
    const legend = protocols.map((name) =>
      `<span class="topo-legend-item"><span class="dot" style="background:${protoColor(name)}"></span>${esc(name)}</span>`).join("");
    box.innerHTML = `<svg id="viz-topology-svg" viewBox="0 0 ${width} ${height}"
      role="img" aria-label="会话拓扑" xmlns="http://www.w3.org/2000/svg">
      <rect class="tl-bg" x="0" y="0" width="${width}" height="${height}"></rect>
      ${edgeSvg}${nodeSvg}</svg>
      ${legend ? `<div class="topo-legend">${legend}</div>` : ""}
      <div class="muted small">${esc(data.text || "")} · ${esc(t("topo_hint"))}</div>`;
  }

  const PROTO_COLORS = {
    HTTP: "#4ea1ff", HTTPS: "#4ea1ff", TLS: "#7ad97a", SSL: "#7ad97a",
    DNS: "#ffd166", TCP: "#c792ea", UDP: "#67d8ef", SSH: "#ff7b72",
    HTTP2: "#a3e635", QUIC: "#f78c6c", SMB: "#e0a3ff", ARP: "#9aa4b0",
  };

  function protoColor(name) {
    const key = String(name || "").toUpperCase();
    if (PROTO_COLORS[key]) return PROTO_COLORS[key];
    let hash = 0;
    for (let i = 0; i < key.length; i++) hash = (hash * 31 + key.charCodeAt(i)) | 0;
    const palette = ["#4ea1ff", "#7ad97a", "#ffd166", "#ff7b72", "#c792ea",
      "#67d8ef", "#f78c6c", "#a3e635"];
    return palette[Math.abs(hash) % palette.length];
  }

  function filterFindingsByEndpoint(endpoint) {
    // Nodes are "ip:port"; findings search matches summary/detail/frame/
    // feature text, so filter on the endpoint string itself.
    const target = String(endpoint || "").trim();
    if (!target) return;
    switchTab("findings");
    setVal("findings-search", target);
    state.findingsPage = 1;
    const job = packetJob();
    if (job) loadFindings(job, { quiet: true });
    else renderFindings();
  }

  async function loadViz() {
    if (!state.pcap) { toast("请先选择输入文件", "warn"); return; }
    const buckets = Number(val("viz-buckets")) || 60;
    setText("#viz-summary", "正在统计…");
    const calls = [
      { sub: "timeline", buckets },
      { sub: "hierarchy" },
      { sub: "ip" },
      { sub: "topology" },
    ].map((body) => api("/api/action", {
      method: "POST", body: { action: "stats", pcap: state.pcap, ...body },
    }).catch((error) => ({ ok: false, text: error.message })));
    const [timeline, hierarchy, talkers, topology] = await Promise.all(calls);
    // Log inputs answer with kind:"log" and structured items; failed
    // responses are kept so their reason text can be shown in the panel.
    state.viz.log = [timeline, hierarchy, talkers, topology]
      .some((data) => data && data.kind === "log");
    state.viz.timeline = timeline;
    state.viz.hierarchy = hierarchy.ok
      ? ((hierarchy.items && hierarchy.items.length)
        ? hierarchy.items : parseHierarchy(hierarchy.text)) : null;
    state.viz.talkers = talkers.ok
      ? ((talkers.items && talkers.items.length)
        ? talkers.items.slice(0, 8) : parseConversations(talkers.text)) : null;
    state.viz.topology = topology;
    state.viz.zoom = null;
    // Log jobs get the extra 实体统计 card (loaded in the background).
    if (state.viz.log) loadEntityStats().catch(() => {});
    // Prefer the job-scoped topology API when a task is attached; it keeps
    // historical jobs replottable even after the pcap picker moves on.
    state.viz.topologyApi = null;
    const jobId = packetJob();
    if (jobId) {
      try {
        const data = await api(`/api/topology?job=${encodeURIComponent(jobId)}`);
        if (data.ok && (data.nodes || []).length) state.viz.topologyApi = data;
      } catch (error) { /* fall back to the pcap-based stats above */ }
    }
    const talkersTitle = document.querySelector("#viz-talkers")
      ?.closest(".viz-card")?.querySelector("h4");
    if (talkersTitle) talkersTitle.textContent = state.viz.log ? "Top 实体" : "Top 会话";
    setText("#viz-summary", timeline.ok
      ? (timeline.text || "") : (timeline.text || "统计失败"));
    renderViz();
  }

  function renderViz() {
    const metric = state.viz.log || val("viz-metric") === "frames"
      ? "frames" : "bytes";
    renderTimeline();
    renderTopology();
    renderBars("#viz-protocols", state.viz.hierarchy, metric,
      state.viz.log ? "日志任务：协议分层显示日志级别统计" : undefined);
    renderBars("#viz-talkers", state.viz.talkers, metric,
      state.viz.log ? "日志任务：Top 实体基于 client_id/user/IP 统计" : undefined);
    if (!state.viz.log) removeEntityCard();
  }

  /* ------------------------------------------------------ entity stats --
   * Log jobs only: a card showing the full per-entity statistics table
   * (the same shape as the feature report's 实体统计 table), driven by
   * POST /api/action {action:"stats", sub:"entities"} on the log input. */
  function ensureEntityCard() {
    const existing = $("#viz-entities-card");
    if (existing) return existing;
    const grid = document.querySelector("#tab-viz .viz-grid");
    if (!grid) return null;
    const card = document.createElement("div");
    card.className = "viz-card wide";
    card.id = "viz-entities-card";
    card.innerHTML = `
      <h4>实体统计
        <select id="viz-entity-dim" class="ghost small"
          title="实体维度（来自当前日志的可用字段）"></select>
        <button id="viz-entity-refresh" class="ghost small">刷新</button>
      </h4>
      <div id="viz-entity-bars" class="viz-bars muted">尚无数据</div>
      <div id="viz-entity-table" class="entity-table-wrap muted">尚无数据</div>
      <div id="viz-entity-note" class="muted small"></div>`;
    grid.appendChild(card);
    $("#viz-entity-refresh").addEventListener("click", () => {
      loadEntityStats().catch((error) => setEntityError(error.message));
    });
    $("#viz-entity-dim").addEventListener("change", () => {
      state.viz.entityDimension = val("viz-entity-dim");
      loadEntityStats().catch((error) => setEntityError(error.message));
    });
    return card;
  }

  function removeEntityCard() {
    const card = $("#viz-entities-card");
    if (card) card.remove();
  }

  function setEntityError(text) {
    const box = $("#viz-entity-table");
    if (box) {
      box.classList.add("muted");
      box.textContent = text || "统计失败";
    }
  }

  // Like api() but keeps ok:false payloads (with dimensions) instead of
  // throwing, so the card can render server-side reasons and fall back to
  // an available dimension itself.
  async function postActionRaw(body) {
    const response = await fetch("/api/action", {
      method: "POST",
      headers: { "X-Fnet-Token": TOKEN, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const type = response.headers.get("content-type") || "";
    if (type.includes("application/json")) return response.json();
    return { ok: false, text: await response.text() };
  }

  async function loadEntityStats(dimension) {
    if (!state.viz.log || !state.pcap) return;
    if (!ensureEntityCard()) return;
    const dim = dimension || state.viz.entityDimension || "client_id";
    setEntityError("正在统计…");
    let data;
    try {
      data = await postActionRaw({
        action: "stats", sub: "entities", pcap: state.pcap,
        dimension: dim, limit: 50,
        ...(state.viz.entityParams || {}),
      });
    } catch (error) {
      data = { ok: false, text: error.message, dimensions: [] };
    }
    // The default dimension may not exist in this log; retry once with the
    // first dimension the server offers instead of leaving an error.
    const dims = data.dimensions || [];
    if (!data.ok && dims.length && !dims.includes(dim)) {
      state.viz.entityDimension = dims[0];
      return loadEntityStats(dims[0]);
    }
    state.viz.entityDimension = data.ok ? data.dimension : dim;
    renderEntityStats(data);
  }

  function renderEntityStats(data) {
    if (!ensureEntityCard()) return;
    const dims = data.dimensions || [];
    const select = $("#viz-entity-dim");
    if (select && dims.length) {
      const current = state.viz.entityDimension || "client_id";
      select.innerHTML = dims.map((name) =>
        `<option value="${esc(name)}"${name === current ? " selected" : ""}>${esc(name)}</option>`).join("");
    }
    const note = $("#viz-entity-note");
    const items = (data.ok && data.items) || [];
    renderBars("#viz-entity-bars",
      items.slice(0, 10).map((item) => ({
        label: String(item.value ?? ""), frames: Number(item.count) || 0,
        bytes: 0,
      })),
      "frames", data.ok ? "没有实体统计数据" : "");
    if (!data.ok) {
      setEntityError(data.text || "统计失败");
      if (note) note.textContent = "";
      return;
    }
    if (!items.length) {
      setEntityError("没有实体统计数据");
      if (note) note.textContent = "";
      return;
    }
    const table = $("#viz-entity-table");
    table.classList.remove("muted");
    const pct = (ratio) => `${(Number(ratio) * 100).toFixed(1)}%`;
    table.innerHTML = `<table class="entity-table"><thead><tr>
        <th>值</th><th>次数</th><th>占比</th><th>失败次数</th><th>失败率</th>
        <th>成功次数</th><th>成功率</th><th>首次</th><th>末次</th></tr></thead>
      <tbody>${items.map((item) => `<tr>
        <td class="mono" title="${esc(item.sample || "")}">${esc(item.value)}</td>
        <td>${esc(item.count)}</td>
        <td>${pct(item.share)}</td>
        <td>${esc(item.fail)}</td>
        <td>${pct(item.fail_rate)}</td>
        <td>${esc(item.success)}</td>
        <td>${pct(item.success_rate)}</td>
        <td class="mono">${esc(item.first || "-")}</td>
        <td class="mono">${esc(item.last || "-")}</td>
      </tr>`).join("")}</tbody></table>`;
    if (note) {
      note.textContent = data.truncated
        ? `仅显示前 ${items.length} 条（共 ${data.total} 条），完整数据见 log_entities.csv`
        : (data.text || "");
    }
  }

  function downloadSvg() {
    if (!state.viz.svg) { toast("请先刷新图表", "warn"); return; }
    downloadText(`fnet-timeline-${Date.now()}.svg`, state.viz.svg);
  }

  async function downloadPng() {
    if (!state.viz.svg) { toast("请先刷新图表", "warn"); return; }
    try {
      const svg = state.viz.svg.replace("<svg ", '<svg style="background:#12161c" ');
      const url = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
      const image = new Image();
      await new Promise((resolve, reject) => {
        image.onload = resolve;
        image.onerror = () => reject(new Error("SVG 渲染失败"));
        image.src = url;
      });
      const canvas = document.createElement("canvas");
      canvas.width = 1600;
      canvas.height = 416;
      const ctx = canvas.getContext("2d");
      ctx.fillStyle = "#12161c";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(image, 0, 0, canvas.width, canvas.height);
      const link = document.createElement("a");
      link.href = canvas.toDataURL("image/png");
      link.download = `fnet-timeline-${Date.now()}.png`;
      link.click();
      toast("PNG 已导出", "good", 1800);
    } catch (error) {
      toast(`PNG 导出失败：${error.message}`, "error", 7000);
    }
  }

  async function uploadTlsKey(file) {
    if (!file) return;
    const kind = state.tlsKeyKind === "key" ? "key" : "keylog";
    try {
      const data = await uploadFile(file, { kind });
      toast(data.text || "TLS 密钥已上传", "good", 6000);
      await refreshMeta();
    } catch (error) {
      toast(error.message, "error", 8000);
    }
  }

  async function startJob(features, params, label) {
    if (!state.pcap) { toast("请先选择输入文件", "warn"); return; }
    if (!features.length) { toast("请至少选择一个分析功能", "warn"); return; }
    try {
      const data = await api("/api/analyze", {
        method: "POST",
        body: { pcap: state.pcap, features, params },
      });
      attachJob(data.job, label);
      rememberFeatures(features);
    } catch (error) {
      toast(error.message, "error", 8000);
    }
  }

  function attachJob(job, label) {
    if (!job) return;
    state.jobId = job.id;
    state.cursor = 0;
    state.logs = [];
    state.artifacts = [];
    $("#log").innerHTML = "";
    $("#artifacts").innerHTML = "";
    setText("#artifact-count", "0");
    resetFindings();
    const zip = $("#download-zip");
    zip.classList.add("disabled");
    zip.removeAttribute("href");
    $("#start-btn").disabled = true;
    $("#cancel-btn").disabled = false;
    $("#pause-btn").disabled = false;
    state.paused = false;
    setPauseButton();
    setText("#job-state", label || t("status_running"));
    $("#job-state").className = "badge running";
    setProgress(0);
    switchTab("log");
    pollJob(job.id);
  }

  function setPauseButton() {
    const button = $("#pause-btn");
    if (!button) return;
    button.textContent = state.paused
      ? (state.language === "en" ? "Resume" : "继续")
      : t("pause");
    button.classList.toggle("primary", state.paused);
  }

  async function togglePause() {
    if (!state.jobId) return;
    try {
      if (state.paused) {
        const data = await api(`/api/jobs/${state.jobId}/resume`,
          { method: "POST", body: {} });
        attachJob(data.job, t("status_running"));
        toast(state.language === "en" ? "Job resumed" : "任务已继续", "good");
      } else {
        await api(`/api/jobs/${state.jobId}/pause`,
          { method: "POST", body: {} });
        toast(state.language === "en"
          ? "Pausing after the current feature"
          : "将在当前功能结束后暂停", "warn");
      }
    } catch (error) {
      toast(error.message, "error", 7000);
    }
  }

  function setProgress(value) {
    const pct = Math.max(0, Math.min(100, Number(value) || 0));
    $("#progress-bar").style.width = `${pct}%`;
    setText("#progress-text", `${Math.round(pct)}%`);
  }

  async function pollJob(jobId) {
    if (state.jobId !== jobId) return;
    try {
      const data = await api(`/api/jobs/${jobId}?cursor=${state.cursor}`);
      if (state.jobId !== jobId) return;
      appendLogs(data.logs);
      state.cursor = data.cursor || state.cursor;
      updateJob(data.job, data.artifacts);
      if (TERMINAL.has(data.job.status)) {
        $("#cancel-btn").disabled = true;
        $("#start-btn").disabled = selectedFeatures().length === 0 || !state.pcap;
        if (data.job.status !== "paused") {
          state.paused = false;
          setPauseButton();
        }
        if (data.job.status === "done") {
          $("#pause-btn").disabled = true;
          toast(`分析完成：${data.job.feature_titles.length} 个功能`, "good");
        } else if (data.job.status === "cancelled") {
          $("#pause-btn").disabled = true;
          toast("分析已取消", "warn");
        } else if (data.job.status === "paused") {
          state.paused = true;
          $("#pause-btn").disabled = false;
          setPauseButton();
          toast(state.language === "en"
            ? "Job paused — click Resume to continue"
            : "任务已暂停，点击“继续”恢复", "warn", 6000);
        } else {
          $("#pause-btn").disabled = true;
          toast(`分析结束（${data.job.status}）${data.job.error ? "：" + data.job.error : ""}`,
            "error", 8000);
        }
        loadHistory().catch(() => {});
        loadFindings(jobId, { quiet: true });
        return;
      }
      $("#pause-btn").disabled = false;
      state.pollTimer = setTimeout(() => pollJob(jobId), 450);
    } catch (error) {
      toast(`获取任务状态失败：${error.message}`, "error", 7000);
      state.pollTimer = setTimeout(() => pollJob(jobId), 1200);
    }
  }

  function updateJob(job, artifacts) {
    setProgress(job.progress);
    const base = statusLabel(job.status);
    setText("#job-state", job.status === "running"
      ? (job.current
        ? `${base} · ${job.current}` : base)
      : job.status === "paused"
        ? `${base} · ${job.completed ? job.completed.length : 0}/${job.feature_titles?.length || ""}`
        : base);
    $("#job-state").className = `badge ${
      job.status === "done" ? "ok" : job.status === "running" ? "running" :
        job.status === "error" ? "bad" : ""}`;
    if (job.feature_titles) {
      setText("#file-meta", `${job.pcap} · ${job.feature_titles.length} 个功能 · 任务 ${job.id.slice(0, 6)}`);
    }
    if (typeof job.findings_count === "number" && !state.findingsJob) {
      setText("#findings-count", String(job.findings_count));
    }
    if (artifacts && artifacts.length) renderArtifacts(job, artifacts);
  }

  async function cancelJob() {
    if (!state.jobId) return;
    try {
      await api(`/api/jobs/${state.jobId}/cancel`, { method: "POST", body: {} });
      toast("已发送取消请求", "warn");
    } catch (error) {
      toast(error.message, "error");
    }
  }

  /* ----------------------------------------------------------- artifacts */
  function renderArtifacts(job, artifacts) {
    state.artifacts = artifacts || [];
    setText("#artifact-count", String(state.artifacts.length));
    const box = $("#artifacts");
    if (!state.artifacts.length) {
      box.innerHTML = '<div class="muted">当前任务还没有产出文件。</div>';
      return;
    }
    box.innerHTML = "";
    state.artifacts.forEach((artifact) => {
      const row = document.createElement("div");
      row.className = "artifact";
      const url = `/api/download?job=${encodeURIComponent(job.id)}&path=${
        encodeURIComponent(artifact.name)}&token=${encodeURIComponent(TOKEN)}`;
      row.innerHTML = `<span class="name">${esc(artifact.name)}</span>
        <span class="size">${fmtSize(artifact.size)}</span>
        <a class="dl" href="${url}" download>下载</a>`;
      box.appendChild(row);
    });
    const zip = $("#download-zip");
    zip.href = `/api/download?job=${encodeURIComponent(job.id)}&token=${encodeURIComponent(TOKEN)}`;
    zip.classList.remove("disabled");
  }

  /* ------------------------------------------------------------ findings */
  const LEVEL_NAMES = {
    debug: "调试", info: "信息", good: "成功", warn: "警告", error: "错误",
  };
  // 默认排序：时间倒序（capture 优先于 wall-clock time），相同时间按 seq 倒序。
  const FINDINGS_DEFAULT_SORT = { key: "time", dir: -1 };
  const FINDING_COLUMNS = [
    ["kind", "类别"], ["level", "级别"], ["frame", "帧"], ["time", "时间"],
    ["feature", "功能"], ["summary", "摘要"], ["detail", "详情"],
  ];

  function findingValue(item, key) {
    if (key === "kind") return state.findingsKinds[item.kind] || item.kind || "";
    if (key === "level") return LEVEL_NAMES[item.level] || item.level || "";
    return String(item[key] ?? "");
  }

  function findingTime(item) {
    return String(item.capture || item.time || "");
  }

  function findingMatches(item) {
    const kind = val("findings-kind") || "all";
    if (kind !== "all" && item.kind !== kind) return false;
    const level = val("findings-level") || "all";
    if (level !== "all" && item.level !== level) return false;
    const query = val("findings-search").toLowerCase();
    if (!query) return true;
    return FINDING_COLUMNS.some(([key]) =>
      findingValue(item, key).toLowerCase().includes(query));
  }

  function sortedFindings() {
    const { key, dir } = state.findingsSort || FINDINGS_DEFAULT_SORT;
    return [...state.findings].sort((left, right) => {
      if (key === "time") {
        // 时间列按显示时间字符串比较（%H:%M:%S / 抓包时间戳都可用字典序），
        // 相同时间回退到 seq，保持发现顺序稳定。
        const a = findingTime(left);
        const b = findingTime(right);
        if (a !== b) return (a < b ? -1 : a > b ? 1 : 0) * dir;
        return ((Number(left.seq) || 0) - (Number(right.seq) || 0)) * dir;
      }
      if (key === "seq" || key === "frame") {
        return ((Number(left[key]) || 0) - (Number(right[key]) || 0)) * dir;
      }
      const a = findingValue(left, key).toLowerCase();
      const b = findingValue(right, key).toLowerCase();
      return (a < b ? -1 : a > b ? 1 : 0) * dir;
    });
  }

  function clip(text, limit = 140) {
    const value = String(text ?? "").replace(/\s+/g, " ").trim();
    return value.length > limit ? `${value.slice(0, limit)}…` : value;
  }

  function visibleFindingColumns() {
    return FINDING_COLUMNS.filter(([key]) => !state.findingsHidden.has(key));
  }

  function findingCell(item, key) {
    if (key === "frame") {
      const frame = Number(item.frame) || 0;
      return frame
        ? `<button type="button" class="frame-link" data-frame="${frame}" title="查看数据包 ${frame}">${esc(frame)}</button>`
        : "";
    }
    if (key === "time") {
      const when = findingTime(item);
      return `<span class="mono">${esc(when || "-")}</span>`;
    }
    if (key === "level") {
      const level = LEVEL_NAMES[item.level] ? item.level : "info";
      return `<span class="finding-level ${level}">${esc(findingValue(item, "level"))}</span>`;
    }
    if (key === "summary") {
      return `<span class="finding-summary">${highlightFlags(esc(clip(item.summary, 180)))}</span>`;
    }
    if (key === "detail") {
      return `<span class="mono muted finding-detail">${esc(clip(item.detail, 160))}</span>`;
    }
    if (key === "kind") {
      return `<span class="finding-kind">${esc(clip(findingValue(item, key), 80))}</span>`;
    }
    return esc(clip(findingValue(item, key), 80));
  }

  function pageSlice(items) {
    const size = Math.max(1, Number(state.findingsPageSize) || 100);
    const pages = Math.max(1, Math.ceil(items.length / size));
    state.findingsPage = Math.min(Math.max(1, state.findingsPage), pages);
    const start = (state.findingsPage - 1) * size;
    return { items: items.slice(start, start + size), pages, start, size };
  }

  function renderFindingsColumns() {
    const panel = $("#findings-columns");
    if (!panel) return;
    panel.innerHTML = FINDING_COLUMNS.map(([key, label]) => `
      <label class="inline"><input type="checkbox" data-column="${esc(key)}"
        ${state.findingsHidden.has(key) ? "" : "checked"}> ${esc(label)}</label>`).join("");
  }

  function renderFindingsPager(page) {
    const box = $("#findings-pager");
    if (!box) return;
    if (!state.findingsVisible.length) { box.innerHTML = ""; return; }
    box.innerHTML = `
      <button class="ghost small" data-page="1" ${page.pages <= 1 || state.findingsPage === 1 ? "disabled" : ""}>首页</button>
      <button class="ghost small" data-page="${state.findingsPage - 1}" ${state.findingsPage <= 1 ? "disabled" : ""}>上一页</button>
      <span class="muted small">第 ${state.findingsPage} / ${page.pages} 页 · 本页 ${page.items.length} 条</span>
      <button class="ghost small" data-page="${state.findingsPage + 1}" ${state.findingsPage >= page.pages ? "disabled" : ""}>下一页</button>
      <button class="ghost small" data-page="${page.pages}" ${state.findingsPage >= page.pages ? "disabled" : ""}>末页</button>`;
  }

  function renderFindings() {
    const box = $("#findings");
    if (!box) return;
    renderFlagBar();
    state.findingsVisible = sortedFindings().filter(findingMatches);
    const total = state.findings.length;
    const page = pageSlice(state.findingsVisible);
    setText("#findings-visible",
      total ? `匹配 ${state.findingsVisible.length} / ${total} 条 · 本页 ${page.items.length} 条` : "");
    let summary = "";
    if (state.findingsDerived) summary = "（旧任务：结果由日志推断）";
    else if (total) {
      const kinds = Object.entries(state.findings.reduce((acc, item) => {
        acc[item.kind] = (acc[item.kind] || 0) + 1;
        return acc;
      }, {})).map(([key, count]) =>
        `${state.findingsKinds[key] || key}×${count}`).join(" · ");
      summary = kinds;
    }
    setText("#findings-summary", summary);
    if (state.findingsTruncated) {
      setText("#findings-visible",
        `匹配 ${state.findingsVisible.length} / ${total} 条（已截断，可导出 CSV 查看全部）`);
    }
    renderFindingsColumns();
    if (!total) {
      box.innerHTML = state.jobId
        ? '<div class="muted">当前任务没有结构化结果。启用 HTTP 提取、NTLM、关键字或 Webshell 等功能后会显示在这里。</div>'
        : '<div class="muted">任务结束后，凭据、哈希、flag、导出文件等会汇总在这里。</div>';
      renderFindingsPager(page);
      return;
    }
    if (!state.findingsVisible.length) {
      box.innerHTML = '<div class="muted">没有匹配的结果，试试调整关键字或筛选条件。</div>';
      renderFindingsPager(page);
      return;
    }
    const sort = state.findingsSort || FINDINGS_DEFAULT_SORT;
    const columns = visibleFindingColumns();
    const pageSelected = page.items.every((item) => state.findingsSelected.has(String(item.seq)));
    const head = columns.map(([key, label]) => {
      const active = sort.key === key;
      const mark = active ? (sort.dir > 0 ? " ▲" : " ▼") : "";
      return `<th data-sort="${key}" class="${active ? "sorted" : ""}"
        title="点击排序">${esc(label)}${mark}</th>`;
    }).join("");
    const body = page.items.map((item) => {
      const level = LEVEL_NAMES[item.level] ? item.level : "info";
      const seq = String(item.seq);
      const cells = columns.map(([key]) => `<td class="${key === "frame" ? "mono" : ""}">${findingCell(item, key)}</td>`).join("");
      return `<tr data-seq="${esc(seq)}" tabindex="0" class="lvl-${level}${state.findingsSelected.has(seq) ? " selected" : ""}">
        <td class="select-cell"><input type="checkbox" class="finding-select" data-seq="${esc(seq)}"
          ${state.findingsSelected.has(seq) ? "checked" : ""} aria-label="选择结果 ${esc(seq)}"></td>
        ${cells}</tr>`;
    }).join("");
    box.innerHTML = `<table class="findings-table">
      <thead><tr><th class="select-cell"><input type="checkbox" id="findings-select-page"
        ${pageSelected ? "checked" : ""} aria-label="选择本页"></th>${head}</tr></thead>
      <tbody>${body}</tbody></table>`;
    renderFindingsPager(page);
  }

  function highlightFlags(escaped) {
    return String(escaped).replace(/flag\{[^}\s]{1,200}\}/gi,
      (match) => `<mark>${match}</mark>`);
  }

  /* ------------------------------------------------------- flags & payload */
  // findings.make() 会把 extra 的值统一 str()，列表会变成 "['flag{a}']" 这种
  // Python repr；这里同时接受数组、`、`/`,` 分隔串和带引号的 repr。
  function parseFlagValue(value) {
    if (Array.isArray(value)) {
      return value.map((entry) => String(entry ?? "").trim()).filter(Boolean);
    }
    let text = String(value ?? "").trim();
    if (!text) return [];
    if (/^[\[(].*[\])]$/.test(text)) text = text.slice(1, -1);
    return text.split(/[、,，]/)
      .map((entry) => entry.trim().replace(/^['"]+|['"]+$/g, "").trim())
      .filter(Boolean);
  }

  function findingFlagList(item) {
    const out = [];
    const seen = new Set();
    const push = (flag) => {
      const text = String(flag ?? "").trim();
      if (!text || seen.has(text)) return;
      seen.add(text);
      out.push(text);
    };
    if (item && item.kind === "flag") push(item.summary);
    parseFlagValue(item && item.extra && item.extra.flags).forEach(push);
    return out;
  }

  // 汇总条：kind=flag 的 summary 优先，extra.flags 兜底；去重保序，
  // 有 seq 的 chip 可以打开对应结果，没有 seq 的只提供复制。
  function collectFindingFlags() {
    const seen = new Set();
    const out = [];
    const push = (flag, seq) => {
      const text = String(flag ?? "").trim();
      if (!text || seen.has(text)) return;
      seen.add(text);
      out.push({ flag: text, seq: seq == null ? "" : String(seq) });
    };
    const items = state.findings || [];
    // kind=flag 的条目优先，保证同名 flag 的 chip 仍能打开对应结果。
    items.forEach((item) => {
      if (item.kind !== "flag") return;
      const seq = item.seq == null ? "" : String(item.seq);
      push(item.summary, seq);
    });
    items.forEach((item) => {
      parseFlagValue(item.extra && item.extra.flags)
        .forEach((flag) => push(flag, ""));
    });
    return out;
  }

  async function copyFlagText(text) {
    try {
      await navigator.clipboard.writeText(String(text || ""));
      toast(t("flag_copied"), "good", 1600);
    } catch (error) {
      toast(t("flag_copy_failed"), "warn");
    }
  }

  function renderFlagBar() {
    const bar = $("#flag-bar");
    if (!bar) return;
    const flags = collectFindingFlags();
    if (!flags.length) {
      bar.classList.add("hidden");
      bar.innerHTML = "";
      return;
    }
    bar.classList.remove("hidden");
    const title = t("flag_bar_title").replace("{count}", String(flags.length));
    const items = flags.map((entry) => {
      const seqAttr = entry.seq ? ` data-flag-seq="${esc(entry.seq)}"` : "";
      return `<span class="flag-chip"${seqAttr}>${esc(entry.flag)}</span>`
        + `<button type="button" class="ghost small flag-copy"`
        + ` data-flag-copy="${esc(entry.flag)}">${esc(t("flag_copy"))}</button>`;
    }).join("");
    bar.innerHTML = `<div class="flag-bar-head">${esc(title)}</div>`
      + `<div class="flag-bar-items">${items}</div>`;
  }

  function flagBannerHtml(flags) {
    if (!flags || !flags.length) return "";
    const rows = flags.map((flag) => `
      <div class="flag-banner-row">
        <span class="flag-banner-title">${esc(t("flag_banner_label"))}</span>
        <code class="mono flag-banner-code">${highlightFlags(esc(flag))}</code>
        <button type="button" class="ghost small" data-flag-copy="${esc(flag)}">${esc(t("flag_copy"))}</button>
      </div>`).join("");
    return `<div class="flag-banner">${rows}</div>`;
  }

  const SMB_FIELD_ORDER = [
    "smb", "stream", "client", "server", "dialect", "session_id",
    "account", "user", "domain", "workstation", "auth", "hash", "mode",
    "share", "path", "name", "size", "md5", "artifact", "pipe",
    "encrypted", "share_flags", "transforms", "encrypted_bytes",
    "original_size", "algorithm", "nonce", "first_frame",
    "security_mode", "capabilities",
  ];

  function smbFieldLabel(key) {
    return t(`smb_field_${key}`, key);
  }

  function smbDetailHtml(item) {
    const extra = item.extra || {};
    const rows = [];
    SMB_FIELD_ORDER.forEach((key) => {
      if (extra[key] === undefined || extra[key] === null || extra[key] === "") return;
      rows.push([key, extra[key]]);
    });
    Object.entries(extra).forEach(([key, value]) => {
      if (key === "protocol" || SMB_FIELD_ORDER.includes(key)) return;
      if (value === undefined || value === null || value === "") return;
      rows.push([key, value]);
    });
    if (!rows.length) return "";
    const body = rows.map(([key, value]) => {
      const text = clip(String(value), 400);
      const display = key === "hash"
        ? `<code class="mono">${esc(text)}</code>`
        : esc(text);
      return `<tr><th>${esc(smbFieldLabel(key))}</th><td>${display}</td></tr>`;
    }).join("");
    const hint = extra.smb === "encrypted"
      ? `<p class="muted small">${esc(t("smb_encrypted_hint"))}</p>` : "";
    return `<h4>${esc(t("smb_detail_title"))}</h4>
      <table class="smb-detail">${body}</table>${hint}`;
  }

  function isSmbFinding(item) {
    return Boolean(item && item.extra && item.extra.protocol === "smb2");
  }

  /* ------------------------------------------------- encoded string probe */
  // 从 finding 自由文本里找出疑似 Base64 / Hex / URL 编码的串，供结果详情
  // 弹窗的“一键解码”使用。这里只做格式与可解码性判断，不发请求。
  const DECODE_PROBE_TEXT_LIMIT = 8192; // 超过 8KB 的文本只取第一个命中
  const DECODE_PROBE_MAX_HITS = 6;      // 弹窗里最多展示几组解码按钮
  const DECODE_PROBE_MIN_TOKEN = 6;     // 短于 6 字符不值得出一个按钮

  // 按字符集取“最大连续段”：天然排除两侧标点、中文括号等分隔符。
  // 不用 lookbehind（老 Safari 会在解析阶段直接抛错），用捕获组 + 前瞻。
  function decodeProbeRuns(source, charset, minLen) {
    const re = new RegExp(
      `(^|[^${charset}])([${charset}]{${minLen},})(?=[^${charset}]|$)`, "g");
    const out = [];
    let match;
    while ((match = re.exec(source)) !== null) {
      out.push(match[2]);
    }
    return out;
  }

  // Hex：≥16 位纯十六进制（charset 由 run 提取保证，这里补全量校验以供
  // Base64 分支复用）且长度为偶数；要求至少出现一个 a-f，
  // 否则一串手机号 / 快递单号也会被当成密文。
  function decodeProbeHexLooksValid(token) {
    return /^[0-9a-fA-F]+$/.test(token) && token.length % 2 === 0
      && /[a-fA-F]/.test(token);
  }

  // Base64（含 URL-safe 变体）：必须真的能解出文本才算命中。两条标准：
  // 1) 解码字节基本是合法 UTF-8（乱码表现为 U+FFFD，以此滤掉恰好落在
  //    Base64 字符集里的普通长单词）；
  // 2) 或 ≥85% 为可打印 ASCII（hexdump / 纯文本式二进制载荷）。
  function decodeProbeBase64LooksValid(token) {
    if (decodeProbeHexLooksValid(token)) return false; // 纯 hex 交给 Hex 分支
    const body = token.replace(/=+$/, "");
    if (body.length % 4 === 1) return false; // 去掉补位后长度不可能成立
    let raw = "";
    try {
      const normalized = body.replace(/-/g, "+").replace(/_/g, "/");
      raw = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
    } catch (error) {
      return false;
    }
    if (raw.length < 6) return false;
    try {
      const bytes = Uint8Array.from(raw, (ch) => ch.charCodeAt(0) & 0xff);
      let printable = 0;
      for (let i = 0; i < bytes.length; i += 1) {
        const b = bytes[i];
        if (b === 0x09 || b === 0x0a || b === 0x0d
          || (b >= 0x20 && b < 0x7f)) printable += 1;
      }
      if (printable / bytes.length >= 0.85) return true;
      const decoded = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      const bad = (decoded.match(/\uFFFD/g) || []).length;
      return decoded.length > 0 && bad / decoded.length <= 0.05;
    } catch (error) {
      return false;
    }
  }

  // 对一段文本扫描，返回去重后的 { kind, token } 命中。
  function decodeProbeScan(text) {
    const source = String(text || "");
    const hits = [];
    const seen = new Set();
    const consider = (kind, token) => {
      if (token.length < DECODE_PROBE_MIN_TOKEN || seen.has(token)) return;
      seen.add(token);
      hits.push({ kind, token });
    };
    // URL 编码：连续非空白片段里出现 ≥2 个 %xx（单个 %20 多半只是空格转义）。
    // 无 %xx 时直接跳过，避免对超长文本做昂贵的回溯匹配。
    if ((source.match(/%[0-9a-fA-F]{2}/g) || []).length >= 2) {
      (source.match(/(?:\S*%[0-9a-fA-F]{2}){2,}\S*/g) || [])
        .forEach((token) => consider("url", token));
    }
    // Hex：≥16 位且为偶数长度（判偶交由 validator）。
    decodeProbeRuns(source, "0-9a-fA-F", 16).forEach((token) => {
      if (decodeProbeHexLooksValid(token)) consider("hex", token);
    });
    // Base64（含 URL-safe）：≥16 字符且能解出可读文本。run 里可能有
    // "data=<base64>" 这类内嵌 '='，先按 '=' 切段再逐段尝试。
    decodeProbeRuns(source, "A-Za-z0-9+/=_-", 16).forEach((run) => {
      const parts = run.split(/=+/).filter((part) => part.length >= 16);
      const tokens = parts.length ? parts : [run];
      tokens.forEach((token) => {
        if (decodeProbeBase64LooksValid(token)) consider("base64", token);
      });
    });
    return hits;
  }

  function decodeKindLabel(kind) {
    const labels = state.language === "en"
      ? { base64: "Base64", hex: "Hex", url: "URL-encoded" }
      : { base64: "Base64", hex: "Hex", url: "URL 编码" };
    return labels[kind] || kind;
  }

  // 汇总一条 finding 的疑似编码串：只扫字符串类型的 summary/detail/extra
  // （数组值逐项看），非字符串值一律跳过；任一文本超过 8KB 时只取第一个命中。
  function findEncodedStrings(item) {
    const texts = [];
    if (item && typeof item === "object") {
      [item.summary, item.detail].forEach((value) => {
        if (typeof value === "string" && value) texts.push(value);
      });
      const extra = item.extra;
      if (extra && typeof extra === "object" && !Array.isArray(extra)) {
        Object.values(extra).forEach((value) => {
          if (typeof value === "string" && value) texts.push(value);
          else if (Array.isArray(value)) {
            value.forEach((entry) => {
              if (typeof entry === "string" && entry) texts.push(entry);
            });
          }
        });
      }
    }
    let overLimit = false;
    const hits = [];
    texts.forEach((text) => {
      if (text.length > DECODE_PROBE_TEXT_LIMIT) overLimit = true;
      decodeProbeScan(text).forEach((hit) => {
        if (!hits.some((entry) => entry.token === hit.token)) hits.push(hit);
      });
    });
    return overLimit ? hits.slice(0, 1) : hits.slice(0, DECODE_PROBE_MAX_HITS);
  }

  // 序号圈号 ①②③…超过 20 个回退成 "1."（正常最多 DECODE_PROBE_MAX_HITS 组）。
  function decodeHitMark(index) {
    return index < 20 ? String.fromCharCode(0x2460 + index) : `${index + 1}.`;
  }

  /* ------------------------------------------- finding decode（一键解码） */
  // 结果详情弹窗里的编码串动作面板；命中列表在 showFinding 打开弹窗前写入。
  let findingDecodeHits = [];
  const findingDecodeResults = new Map();

  function decodePanelHtml(hits) {
    const groups = hits.map((hit, index) => `
      <div class="decode-group">
        <div class="decode-group-head">
          <span class="decode-group-title">${esc(decodeHitMark(index))}
            ${esc(decodeKindLabel(hit.kind))} · ${hit.token.length}
            ${esc(t("decode_chars"))}</span>
          <button type="button" class="ghost small" data-decode-action="run"
            data-decode-index="${index}">${esc(t("decode_run"))}</button>
        </div>
        <pre class="decode-token">${esc(clip(hit.token, 300))}</pre>
        <div class="decode-result-area" data-decode-result="${index}"></div>
      </div>`).join("");
    return `<div class="decode-panel">
      <div class="decode-panel-head">
        <h4>${esc(t("decode_panel_title"))}（${hits.length}）</h4>
        <button type="button" class="ghost small" data-decode-action="cyberchef">
          ${esc(t("decode_cyberchef"))}</button>
      </div>
      ${groups}
    </div>`;
  }

  // /api/decode 返回 {ok, candidates:[{label,value}], flags}；“原始文本
  // （未识别编码）”是服务端识别失败时的兜底项，按失败处理。
  const DECODE_FALLBACK_LABEL = "原始文本（未识别编码）";

  async function runFindingDecode(index) {
    const hit = findingDecodeHits[index];
    const area = $(`[data-decode-result="${index}"]`);
    if (!hit || !area) return;
    area.innerHTML = `<div class="muted small">${esc(t("decode_running"))}</div>`;
    let data = null;
    try {
      data = await api("/api/decode", { method: "POST", body: { text: hit.token } });
    } catch (error) {
      area.innerHTML = `<div class="decode-error">${esc(t("decode_failed"))}：`
        + `${esc(clip(String(error.message || error), 200))}</div>`;
      return;
    }
    if (!data || data.ok === false) {
      area.innerHTML = `<div class="decode-error">${esc(t("decode_failed"))}：`
        + `${esc(clip(String((data && data.error) || ""), 200))}</div>`;
      return;
    }
    const candidates = (Array.isArray(data.candidates)) ? data.candidates : [];
    const real = candidates.filter((item) => item && item.value
      && item.label !== DECODE_FALLBACK_LABEL);
    if (!real.length) {
      area.innerHTML = `<div class="decode-error">${esc(t("decode_no_result"))}</div>`;
      return;
    }
    findingDecodeResults.set(index,
      real.map((item) => `[${item.label}]\n${item.value}`).join("\n\n"));
    area.innerHTML = `<div class="decode-result">`
      + real.map((item) => `
        <div class="decode-item">
          <div class="decode-label">${esc(item.label)}</div>
          <div class="decode-value">${highlightFlags(esc(String(item.value)))}</div>
        </div>`).join("")
      + `</div>
      <button type="button" class="ghost small" data-decode-action="copy"
        data-decode-index="${index}">${esc(t("decode_copy"))}</button>`;
  }

  async function copyFindingDecode(index) {
    const text = findingDecodeResults.get(index) || "";
    try {
      await navigator.clipboard.writeText(text);
      toast(t("decode_copied"), "good", 1600);
    } catch (error) {
      toast(t("decode_copy_failed"), "warn");
    }
  }

  // CyberChef 是整页跳转（plugin_run 通道），无法携带载荷；行为与工具菜单一致。
  async function openCyberChef() {
    try {
      await api("/api/action", {
        method: "POST",
        body: { action: "plugin_run", key: "cyberchef", target: state.pcap || "" },
      });
      toast(t("decode_cyberchef_opened"), "good", 1800);
    } catch (error) {
      toast(error.message, "error", 7000);
    }
  }

  async function handleDecodeAction(button) {
    const action = button.dataset.decodeAction;
    if (action === "cyberchef") return openCyberChef();
    const index = Number(button.dataset.decodeIndex) || 0;
    if (action === "copy") return copyFindingDecode(index);
    if (action === "run") return runFindingDecode(index);
  }

  /* ---------------------------------------- finding payload（载荷 / 破解） */
  // 隧道类 finding 的 extra 带 artifact/bin（载荷文件）与 payload_preview
  // （重组后的原始文本）。载荷面板内联在详情弹窗里，破解走
  // POST /api/payload/crack，命中后服务端把明文写回任务目录。
  let findingPayloadPlain = "";

  function payloadArtifactName(item) {
    const extra = (item && item.extra) || {};
    const name = String(extra.artifact || extra.bin || "").trim();
    if (!name) return "";
    const encrypted = String(extra.encrypted ?? "").trim().toLowerCase();
    if (!/\.bin$/i.test(name) && encrypted !== "true") return "";
    return name;
  }

  function payloadOptions(pairs) {
    return pairs.map(([value, label]) =>
      `<option value="${esc(value)}">${esc(label)}</option>`).join("");
  }

  function payloadPanelHtml(item) {
    const name = payloadArtifactName(item);
    if (!name) return "";
    const preview = String((item.extra && item.extra.payload_preview) || "");
    const previewHtml = preview
      ? `<pre class="payload-preview">${esc(preview)}</pre>
        <button type="button" class="ghost small" data-payload-action="copy-preview">${esc(t("payload_copy"))}</button>`
      : `<div class="payload-empty">${esc(t("payload_preview_empty"))}</div>`;
    const ciphers = payloadOptions([
      ["", t("payload_auto")],
      ["aes-128-cbc", "aes-128-cbc"], ["aes-128-ctr", "aes-128-ctr"],
      ["aes-128-ecb", "aes-128-ecb"], ["aes-256-cbc", "aes-256-cbc"],
      ["aes-256-ctr", "aes-256-ctr"], ["aes-256-ecb", "aes-256-ecb"],
    ]);
    const digests = payloadOptions([
      ["", t("payload_auto")], ["md5", "md5"], ["sha256", "sha256"],
    ]);
    const salts = payloadOptions([
      ["auto", t("payload_salted_auto")],
      ["true", t("payload_salted_yes")],
      ["false", t("payload_salted_no")],
    ]);
    return `<div class="payload-panel" data-payload-artifact="${esc(name)}">
      <div class="payload-head">
        <h4>${esc(t("payload_title"))} <code class="mono">${esc(name)}</code></h4>
        <div class="payload-actions">
          <button type="button" class="ghost small" data-payload-action="download">${esc(t("payload_download"))}</button>
          <button type="button" class="ghost small" data-payload-action="toggle">${esc(t("payload_crack"))}</button>
        </div>
      </div>
      <div class="payload-preview-block">
        <div class="payload-preview-title">${esc(t("payload_preview_title"))}</div>
        ${previewHtml}
      </div>
      <div class="payload-crack-form hidden">
        <div class="field full">
          <label for="payload-password">${esc(t("payload_password"))}</label>
          <input id="payload-password" type="text" spellcheck="false"
            placeholder="${esc(t("payload_password_ph"))}">
        </div>
        <div class="field full">
          <label for="payload-passwords">${esc(t("payload_passwords"))}</label>
          <textarea id="payload-passwords" rows="3" spellcheck="false"
            placeholder="${esc(t("payload_passwords_ph"))}"></textarea>
        </div>
        <div class="field">
          <label for="payload-cipher">${esc(t("payload_cipher"))}</label>
          <select id="payload-cipher">${ciphers}</select>
        </div>
        <div class="field">
          <label for="payload-digest">${esc(t("payload_digest"))}</label>
          <select id="payload-digest">${digests}</select>
        </div>
        <div class="field">
          <label for="payload-salted">${esc(t("payload_salted"))}</label>
          <select id="payload-salted">${salts}</select>
        </div>
        <div class="field">
          <label class="inline"><input id="payload-base64" type="checkbox">
            ${esc(t("payload_base64"))}</label>
        </div>
        <div class="field full payload-run-row">
          <button type="button" class="ghost small" data-payload-action="run">${esc(t("payload_run"))}</button>
        </div>
      </div>
      <div id="payload-result" class="payload-result hidden"></div>
    </div>`;
  }

  function downloadJobFile(name) {
    const job = state.findingsJob || state.jobId || "";
    if (!job || !name) {
      toast(t("payload_need_job"), "warn");
      return;
    }
    const url = `/api/download?job=${encodeURIComponent(job)}`
      + `&path=${encodeURIComponent(name)}&token=${encodeURIComponent(TOKEN)}`;
    window.open(url, "_blank", "noopener");
  }

  async function copyPayloadText(text, okKey) {
    try {
      await navigator.clipboard.writeText(String(text || ""));
      toast(t(okKey), "good", 1600);
    } catch (error) {
      toast(t("flag_copy_failed"), "warn");
    }
  }

  function renderPayloadResult(box, data) {
    if (!box) return;
    const flags = parseFlagValue(data && data.flags);
    if (data && data.hit) {
      const preview = String(data.preview || "");
      findingPayloadPlain = preview;
      const saved = String(data.saved || "");
      const password = String(data.password || "");
      const chips = flags.map((flag) =>
        `<span class="flag-chip">${highlightFlags(esc(flag))}</span>`).join(" ");
      box.innerHTML = `<div class="payload-result-ok">
        <div class="payload-result-head">${esc(t("payload_hit"))} ·
          <code class="mono">${esc(data.cipher || "?")} / ${esc(data.digest || "?")}</code></div>
        ${password ? `<div class="payload-result-line">${esc(t("payload_password_hit"))}:
          <code class="mono">${esc(password)}</code></div>` : ""}
        ${data.recipe ? `<div class="payload-result-line">${esc(t("payload_recipe"))}:
          <code class="mono">${esc(data.recipe)}</code></div>` : ""}
        ${chips ? `<div class="payload-result-flags">${chips}</div>` : ""}
        <pre class="payload-plain">${highlightFlags(esc(preview))}</pre>
        <div class="payload-result-actions">
          ${saved ? `<span class="muted small">${esc(t("payload_saved"))}:
            <code class="mono">${esc(saved)}</code></span>` : ""}
          <button type="button" class="ghost small" data-payload-action="copy-plain">${esc(t("payload_copy_plain"))}</button>
          ${saved ? `<button type="button" class="ghost small" data-payload-action="download-decoded"
            data-payload-saved="${esc(saved)}">${esc(t("payload_download_decoded"))}</button>` : ""}
        </div>
      </div>`;
      return;
    }
    const recipe = String((data && data.recipe) || "");
    const attempts = Number(data && data.attempts) || 0;
    box.innerHTML = `<div class="payload-result-miss">
      <div class="payload-result-head">${esc(t("payload_miss").replace("{count}", String(attempts)))}</div>
      ${recipe ? `<pre class="payload-recipe">${esc(recipe)}</pre>` : ""}
      ${data && data.error ? `<div class="payload-result-line">${esc(clip(String(data.error), 300))}</div>` : ""}
    </div>`;
  }

  async function runPayloadCrack(button) {
    const panel = button.closest(".payload-panel");
    const box = panel ? panel.querySelector("#payload-result") : null;
    if (!panel || !box) return;
    const job = state.findingsJob || state.jobId || "";
    if (!job) {
      box.classList.remove("hidden");
      box.innerHTML = `<div class="payload-result-fail">${esc(t("payload_need_job"))}</div>`;
      return;
    }
    const passwords = String(($("#payload-passwords") || {}).value || "")
      .split(/\r?\n/).map((entry) => entry.trim()).filter(Boolean);
    const saltedRaw = val("payload-salted");
    const body = {
      job,
      path: panel.dataset.payloadArtifact || "",
      password: String(($("#payload-password") || {}).value || ""),
      passwords,
      cipher: val("payload-cipher"),
      digest: val("payload-digest"),
      salted: saltedRaw === "true" ? true : saltedRaw === "false" ? false : "auto",
      base64: checked("payload-base64"),
    };
    const label = button.textContent;
    button.disabled = true;
    button.textContent = t("payload_running");
    box.classList.remove("hidden");
    box.innerHTML = `<div class="muted small">${esc(t("payload_running"))}</div>`;
    try {
      const data = await api("/api/payload/crack", { method: "POST", body });
      renderPayloadResult(box, data);
    } catch (error) {
      box.innerHTML = `<div class="payload-result-fail">${esc(t("payload_failed"))}：
        ${esc(clip(String(error.message || error), 300))}</div>`;
    } finally {
      button.disabled = false;
      button.textContent = label || t("payload_run");
    }
  }

  async function handlePayloadAction(button) {
    const action = button.dataset.payloadAction;
    const panel = button.closest(".payload-panel");
    if (action === "download") {
      return downloadJobFile(panel && panel.dataset.payloadArtifact);
    }
    if (action === "copy-preview") {
      const pre = panel && panel.querySelector(".payload-preview");
      return copyPayloadText(pre ? pre.textContent : "", "payload_copied");
    }
    if (action === "copy-plain") {
      const pre = panel && panel.querySelector(".payload-plain");
      return copyPayloadText(pre ? pre.textContent : findingPayloadPlain,
        "payload_plain_copied");
    }
    if (action === "download-decoded") {
      return downloadJobFile(button.dataset.payloadSaved);
    }
    if (action === "toggle") {
      const form = panel && panel.querySelector(".payload-crack-form");
      if (!form) return;
      const hidden = form.classList.toggle("hidden");
      button.textContent = hidden ? t("payload_crack") : t("payload_crack_hide");
      return;
    }
    if (action === "run") return runPayloadCrack(button);
  }

  async function showFinding(seq) {
    const item = state.findings.find((entry) => String(entry.seq) === String(seq));
    if (!item) return;
    const lines = [
      `类别: ${findingValue(item, "kind")}`,
      `级别: ${findingValue(item, "level")}`,
      `功能: ${item.feature || "—"}`,
      `帧: ${item.frame || "—"}    时间: ${item.capture || item.time || "—"}`,
      "",
      item.summary || "",
    ];
    if (item.detail) lines.push("", item.detail);
    if (item.annotation && item.annotation.note) {
      lines.push("", `备注: ${item.annotation.note}`);
    }
    const ann = item.annotation || { status: "", note: "" };
    const crackable = Boolean(item.extra && item.extra.hash)
      && Boolean(state.meta && state.meta.crack && state.meta.crack.available);
    const smb = isSmbFinding(item);
    const ntlmcrackable = isNtlmCrackable(item);
    // 疑似编码串：命中时在详情区下方渲染“一键解码”面板（默认解码第一个）。
    // 载荷预览里已经原样展示的编码串不再重复渲染一份解码面板。
    findingDecodeHits = findEncodedStrings(item);
    if (payloadArtifactName(item)) {
      const payloadPreview = String((item.extra && item.extra.payload_preview) || "");
      if (payloadPreview) {
        findingDecodeHits = findingDecodeHits
          .filter((hit) => !payloadPreview.includes(hit.token));
      }
    }
    findingDecodeResults.clear();
    findingPayloadPlain = "";
    const flagBanner = flagBannerHtml(findingFlagList(item));
    const payloadPanel = payloadPanelHtml(item);
    const detailHtml = flagBanner + payloadPanel
      + (smb ? smbDetailHtml(item) : "")
      + (findingDecodeHits.length ? decodePanelHtml(findingDecodeHits) : "");
    const extraButtons = [];
    if (smb && state.meta && state.meta.smb && state.meta.smb.available) {
      extraButtons.push({ name: "smb", label: t("smb_decrypt_button") });
    }
    if (crackable) extraButtons.push({ name: "crack", label: t("crack_button") });
    if (ntlmcrackable) {
      extraButtons.push({ name: "ntlmcrack", label: t("ntlmcrack_button") });
    }
    const modalPromise = openModal({
      title: `结果详情 · ${findingValue(item, "kind")}`,
      text: lines.join("\n"),
      html: detailHtml,
      fields: [
        {
          name: "status", label: t("ann_status"), type: "select",
          value: ann.status || "",
          options: [
            { value: "", label: t("ann_none") },
            { value: "confirmed", label: t("ann_confirmed") },
            { value: "false_positive", label: t("ann_false_positive") },
            { value: "starred", label: t("ann_starred") },
          ],
        },
        { name: "note", label: t("ann_note"), type: "textarea", value: ann.note || "" },
      ],
      okText: t("ann_save"),
      extraButtons,
    });
    if (findingDecodeHits.length) {
      // 默认自动解码第一处命中；失败只写进面板，不影响弹窗其余交互。
      runFindingDecode(0).catch(() => {});
    }
    const values = await modalPromise;
    if (!values) return;
    if (values.__action === "crack") {
      await openCrackDialog(item);
      return;
    }
    if (values.__action === "ntlmcrack") {
      await openNtlmCrackDialog(item);
      return;
    }
    if (values.__action === "smb") {
      await openSmbDecryptDialog(item);
      return;
    }
    const job = packetJob();
    if (!job) { toast(state.language === "en"
      ? "No analysis job available" : "还没有可标注的分析任务", "warn"); return; }
    try {
      await api("/api/annotations", {
        method: "POST",
        body: { job, seq: item.seq, status: values.status || "",
                note: values.note || "" },
      });
      toast(t("ann_saved"), "good", 1800);
      await loadFindings(job, { quiet: true });
    } catch (error) {
      toast(error.message, "error", 7000);
    }
  }

  /* --------------------------------------------------------------- SMB3 */
  // Fields the SMB3 dialog can prefill; the server side resolver knows where
  // each value came from and reports it in `sources`.
  const SMB3_HINT_FIELDS = ["password", "nt_hash", "session_key",
                            "user", "domain", "stream"];
  const SMB3_SECRETS = ["password", "nt_hash", "session_key"];
  const SMB3_HINT_LABELS = {
    password: "smb_hint_password",
    nt_hash: "smb_hint_nt_hash",
    session_key: "smb_hint_session_key",
    user: "smb_hint_user",
    domain: "smb_hint_domain",
    stream: "smb_hint_stream",
  };

  function isNtHash(value) {
    return /^[0-9a-fA-F]{32}$/.test(String(value || "").trim());
  }

  // GET /api/smb/hints may be missing (old server), fail or answer junk; the
  // caller only needs to know whether usable hints came back.
  async function loadSmbHints(job, stream) {
    const query = `?job=${encodeURIComponent(job)}`
      + (stream ? `&stream=${encodeURIComponent(stream)}` : "");
    try {
      const data = await api(`/api/smb/hints${query}`);
      if (!data || data.ok === false || !data.hints
          || typeof data.hints !== "object" || Array.isArray(data.hints)) {
        return { payload: null, failed: true,
                 error: clip((data && (data.error || data.text)) || "") };
      }
      return { payload: data, failed: false, error: "" };
    } catch (error) {
      return { payload: null, failed: true, error: clip(error.message || error) };
    }
  }

  // The clicked finding wins over server hints, an empty string is not a
  // value, and a NetNTLMv2 line is never an NT hash — both sides are checked.
  function mergeSmbHints(extra, payload) {
    const sourceExtra = (typeof extra === "object" && extra
      && !Array.isArray(extra)) ? extra : {};
    const rawPayload = (typeof payload === "object" && payload) ? payload : {};
    const hints = (typeof rawPayload.hints === "object" && rawPayload.hints
      && !Array.isArray(rawPayload.hints)) ? rawPayload.hints : {};
    const sources = (typeof rawPayload.sources === "object" && rawPayload.sources
      && !Array.isArray(rawPayload.sources)) ? rawPayload.sources : {};
    const values = {};
    const filled = [];
    SMB3_HINT_FIELDS.forEach((name) => {
      const hashKey = name === "nt_hash" ? "hash" : name;
      let own = String(sourceExtra[hashKey] ?? "").trim();
      let hinted = String(hints[name] ?? "").trim();
      if (name === "nt_hash") {
        if (!isNtHash(own)) own = "";
        if (!isNtHash(hinted)) hinted = "";
      }
      if (name === "stream") {
        // 只发送纯数字的 TCP 流号，非数字（如 "0abc"）绝不发给解密接口。
        if (!/^\d+$/.test(own)) own = "";
        if (!/^\d+$/.test(hinted)) hinted = "";
      }
      const value = own || hinted;
      if (!value) return;
      values[name] = value;
      filled.push({ name, value, fromFinding: Boolean(own),
                    source: own ? "" : clip(String(sources[name] || "").trim(), 160) });
    });
    return { values, filled };
  }

  function smbFillSummary(filled, prefix) {
    if (!Array.isArray(filled) || !filled.length) return "";
    const zh = state.language !== "en";
    const parts = filled.map((entry) => {
      const label = t(SMB3_HINT_LABELS[entry.name] || entry.name);
      const source = entry.fromFinding
        ? t("smb_hints_from_finding") : entry.source;
      if (!source) return label;
      return zh ? `${label}（${source}）` : `${label} (${source})`;
    });
    return `${prefix}${parts.join(zh ? "、" : ", ")}`;
  }

  function smbDialogText(payload, failed, error, filled) {
    const lines = [t("smb_decrypt_hint")];
    const summary = smbFillSummary(filled, t("smb_hints_prefill"));
    if (summary) {
      lines.push("", summary);
      (Array.isArray(payload && payload.notes) ? payload.notes.slice(0, 3) : [])
        .forEach((note) => {
          const text = String(note || "").trim();
          if (text) lines.push(clip(text, 160));
        });
    } else if (failed) {
      lines.push("", error ? `${t("smb_hints_failed")}：${error}`
                           : t("smb_hints_failed"));
    } else {
      lines.push("", t("smb_hints_none"));
    }
    return lines.join("\n");
  }

  // A cracked account carries the plaintext password; its `hash` is a
  // NetNTLMv2 line and must be cracked before it can be used here.
  function smbAccountValues(account) {
    const values = {};
    if (!account || typeof account !== "object" || Array.isArray(account)) {
      return values;
    }
    ["user", "domain", "stream", "password", "nt_hash"].forEach((name) => {
      const raw = String(account[name] ?? "").trim();
      if (name === "stream" && !/^\d+$/.test(raw)) return;
      if (name === "nt_hash" && !isNtHash(raw)) return;
      if (raw) values[name] = raw;
    });
    return values;
  }

  function smbAccountLabel(account) {
    if (!account || typeof account !== "object") return "";
    const name = [String(account.domain || "").trim(),
                  String(account.user || "").trim()].filter(Boolean).join("\\");
    const stream = String(account.stream ?? "").trim();
    if (!name) return `${t("smb_stream_short")} ${stream}`;
    return stream ? `${name} · ${t("smb_stream_short")} ${stream}` : name;
  }

  function smbDecryptFields(values, accounts) {
    const fields = [];
    if (accounts.length > 1) {
      fields.push({
        name: "account", label: t("smb_account_pick"), type: "select",
        value: "",
        options: [{ value: "", label: t("smb_account_none") }].concat(
          accounts.map((account, index) => ({
            value: String(index), label: smbAccountLabel(account),
          }))),
      });
    }
    fields.push(
      { name: "password", label: t("smb_password"), type: "password",
        value: values.password || "", placeholder: "haha" },
      { name: "nt_hash", label: t("smb_nt_hash"), value: values.nt_hash || "",
        placeholder: "31d6cfe0d16ae931b73c59d7e0c089c0" },
      { name: "session_key", label: t("smb_session_key"),
        value: values.session_key || "",
        placeholder: "2e9dd1f6407acfad0ccfa0cee66c12da" },
      { name: "user", label: t("smb_user"), value: values.user || "" },
      { name: "domain", label: t("smb_domain"), value: values.domain || "" },
      { name: "stream", label: t("smb_stream"), value: values.stream || "" },
    );
    return fields;
  }

  // Write hint values into the live inputs, skipping what the user typed.
  function applySmbHintValues(values, touched) {
    const written = [];
    SMB3_HINT_FIELDS.forEach((name) => {
      const input = $(`#modal-field-${name}`);
      const value = String(values[name] || "").trim();
      if (!input || !value || touched.has(name)) return;
      input.value = value;
      written.push(name);
    });
    return written;
  }

  // openModal has no change callback, so the account dropdown is wired up by
  // hand once the body exists.
  function bindSmbAccountPicker(accounts, touched) {
    const select = $("#modal-field-account");
    if (!select || accounts.length < 2) return;
    select.addEventListener("change", () => {
      const index = Number(select.value);
      if (!select.value || index < 0 || index >= accounts.length) return;
      const account = accounts[index];
      const values = smbAccountValues(account);
      ["user", "domain", "stream", "password", "nt_hash"].forEach((name) => {
        const input = $(`#modal-field-${name}`);
        if (!input) return;
        const value = String(values[name] || "");
        // A stream the account does not name keeps whatever is in the field.
        if (!value && name === "stream") return;
        input.value = value;
        if (value) touched.add(name);
      });
    });
  }

  function smbKeyEntries(data) {
    const raw = Array.isArray(data.keys) && data.keys.length
      ? data.keys
      : (Array.isArray(data.sessions) ? data.sessions : []);
    const lines = [];
    const seen = new Set();
    raw.forEach((entry) => {
      const item = typeof entry === "string" ? { key: entry }
        : (typeof entry === "object" && entry ? entry : {});
      const hex = String(item.key || item.session_key || "").trim();
      if (!hex) return;
      const stream = String(item.stream ?? "").trim();
      const parts = [];
      if (stream) parts.push(`${t("smb_stream_short")} ${stream}`);
      if (item.cipher) parts.push(String(item.cipher));
      parts.push(hex);
      const line = parts.join(" · ");
      if (seen.has(line)) return;
      seen.add(line);
      lines.push(line);
    });
    return lines;
  }

  async function openSmbDecryptDialog(item) {
    const meta = state.meta && state.meta.smb;
    if (!meta || !meta.available) {
      toast(t("smb_no_tshark"), "warn", 6000);
      return;
    }
    const job = packetJob();
    if (!job) { toast(t("smb_need_job"), "warn"); return; }
    const extra = (item && item.extra) || {};
    const touched = new Set();
    let payload = null;
    let failed = false;
    let failure = "";
    let merged = mergeSmbHints(extra, null);
    // `meta.hints` is missing on an old server: open the dialog as before.
    if (meta.hints) {
      const result = await loadSmbHints(job, String(extra.stream ?? "").trim());
      payload = result.payload;
      failed = result.failed;
      failure = result.error;
      merged = mergeSmbHints(extra, payload);
    }
    const accounts = Array.isArray(payload && payload.accounts)
      ? payload.accounts.filter((account) => {
        if (!account || typeof account !== "object" || Array.isArray(account))
          return false;
        const user = String(account.user || "").trim();
        const domain = String(account.domain || "").trim();
        const stream = String(account.stream || "").trim();
        return Boolean(user || domain || stream);
      })
      : [];
    let secretSeen = SMB3_SECRETS.some((name) => merged.values[name]);

    async function recheckSmbHints(button) {
      if (button) button.disabled = true;
      try {
        const streamInput = $("#modal-field-stream");
        const stream = streamInput ? String(streamInput.value || "").trim()
          : String(extra.stream ?? "").trim();
        const result = await loadSmbHints(job, stream);
        if (!alive()) return;
        payload = result.payload;
        failed = result.failed;
        failure = result.error;
        merged = mergeSmbHints(extra, payload);
        const written = applySmbHintValues(merged.values, touched);
        if (written.some((name) => SMB3_SECRETS.includes(name))) {
          secretSeen = true;
        }
        textBlock.textContent = smbDialogText(payload, failed, failure,
                                              merged.filled);
        const fresh = merged.filled.filter((entry) =>
          written.includes(entry.name));
        const summary = smbFillSummary(fresh, t("smb_hints_saved"));
        toast(summary || (failed ? t("smb_hints_failed") : t("smb_hints_none")),
              summary ? "good" : "warn", 5000);
      } finally {
        if (button) button.disabled = false;
      }
    }

    const options = {
      title: t("smb_decrypt_title"),
      text: smbDialogText(payload, failed, failure, merged.filled),
      fields: smbDecryptFields(merged.values, accounts),
      okText: t("smb_start"),
      extraButtons: meta.hints
        ? [{ name: "hints", label: t("smb_hints_recheck"),
             onClick: recheckSmbHints }]
        : [],
    };
    // openModal builds the body synchronously and only resolves on submit, so
    // the live behaviour is wired up before awaiting the returned promise.
    const pending = openModal(options);
    const textBlock = $("#modal-body pre");
    // A late answer must not touch a modal that the user already replaced.
    const alive = () => $("#modal-body pre") === textBlock && textBlock;
    $$("[id^=modal-field-]", $("#modal-body")).forEach((input) => {
      if (input.tagName === "SELECT") return;
      const name = input.id.replace("modal-field-", "");
      input.addEventListener("input", () => touched.add(name));
    });
    bindSmbAccountPicker(accounts, touched);
    const values = await pending;
    if (!values) return;
    if (!values.password && !values.nt_hash && !values.session_key
        && !secretSeen) {
      toast(t("smb_need_secret"), "warn", 5000);
      return;
    }
    openModal({
      title: `${t("smb_result_title")} · ${t("smb_running")}`,
      text: t("smb_running"),
      hideCancel: true,
      okText: t("smb_close"),
    });
    try {
      const data = await api("/api/smb/decrypt", {
        method: "POST",
        body: {
          job,
          password: values.password || "",
          nt_hash: values.nt_hash || "",
          session_key: values.session_key || "",
          user: values.user || "",
          domain: values.domain || "",
          // 只发送纯数字的 TCP 流号，用户手工输入的非数字流号丢弃。
          stream: /^\d+$/.test(String(values.stream || "")) ? values.stream : "",
        },
      });
      renderSmbResult(data, job);
    } catch (error) {
      renderSmbResult({ ok: false, error: error.message, log: [] }, job);
    }
  }

  function renderSmbResult(data, job) {
    const body = $("#modal-body");
    if (body) {
      body.innerHTML = "";
      const pre = document.createElement("pre");
      const lines = (data.log || []).slice();
      pre.textContent = lines.length
        ? lines.join("\n")
        : (data.text || data.error || t("smb_no_result"));
      body.appendChild(pre);
      const keys = smbKeyEntries(data);
      if (keys.length) {
        const title = document.createElement("h4");
        title.textContent = t("smb_keys");
        body.appendChild(title);
        const box = document.createElement("div");
        box.className = "smb-files";
        box.innerHTML = keys.map(
          (line) => `<div class="mono">${esc(line)}</div>`).join("");
        body.appendChild(box);
      }
      if (data.flags && data.flags.length) {
        const title = document.createElement("h4");
        title.textContent = t("smb_flags");
        body.appendChild(title);
        const flags = document.createElement("div");
        flags.className = "smb-flags";
        flags.innerHTML = data.flags
          .map((flag) => `<code class="mono">${esc(flag)}</code>`).join(" ");
        body.appendChild(flags);
      }
      if (data.files && data.files.length) {
        const title = document.createElement("h4");
        title.textContent = t("smb_files");
        body.appendChild(title);
        const files = document.createElement("div");
        files.className = "smb-files";
        files.innerHTML = data.files.map((file) => `<div class="mono">${esc(file.name)}
          <span class="muted">${fmtSize(file.size)}</span></div>`).join("");
        body.appendChild(files);
      }
    }
    setText("#modal-title",
      `${t("smb_result_title")} · ${data.ok ? t("smb_ok") : t("smb_failed")}`);
    if (data.ok) {
      toast(t("smb_ok"), "good", 3000);
      refreshJobArtifacts(job);
    } else {
      toast(data.error || t("smb_failed"), "error", 7000);
    }
  }

  async function refreshJobArtifacts(job) {
    if (!job) return;
    try {
      const data = await api(`/api/jobs/${encodeURIComponent(job)}?cursor=${state.cursor}`);
      if (data.job && data.artifacts) updateJob(data.job, data.artifacts);
      await loadFindings(job, { quiet: true });
    } catch (error) {
      /* artifact refresh is best-effort */
    }
  }
  /* ------------------------------------------------------------- hashcat */
  const CRACK_STATUS_KEYS = {
    running: "crack_running", cracked: "crack_cracked",
    exhausted: "crack_exhausted", error: "crack_error",
    cancelled: "crack_cancelled",
  };

  function crackStatusLabel(status) {
    return t(CRACK_STATUS_KEYS[status] || "crack_running");
  }

  function stopCrackPoll() {
    if (!state.crack) return;
    if (state.crack.timer) clearInterval(state.crack.timer);
    state.crack.timer = null;
    state.crack.id = "";
  }

  function workloadOptions() {
    const zh = ["1 - 低（桌面不卡顿）", "2 - 经济", "3 - 默认", "4 - 高（占满 GPU）"];
    const en = ["1 - Low (desktop stays usable)", "2 - Economic", "3 - Default", "4 - High (uses the whole GPU)"];
    const labels = state.language === "en" ? en : zh;
    return labels.map((label, index) => ({ value: String(index + 1), label }));
  }

  async function openCrackDialog(item) {
    const meta = state.meta && state.meta.crack;
    if (!meta || !meta.available) {
      toast(t("crack_no_hashcat"), "warn", 6000);
      return;
    }
    const job = packetJob();
    if (!job) {
      toast(state.language === "en"
        ? "No analysis job available" : "还没有可破解的分析任务", "warn");
      return;
    }
    const settings = meta.settings || {};
    const values = await openModal({
      title: `${t("crack_title")} · ${findingValue(item, "kind")}`,
      text: item.detail || "",
      fields: [
        {
          name: "wordlist", label: t("crack_wordlist"),
          value: settings.wordlist || "",
          placeholder: "/usr/share/wordlists/rockyou.txt",
        },
        {
          name: "workload", label: t("crack_workload"), type: "select",
          value: String(settings.workload || "3"),
          options: workloadOptions(),
        },
        {
          name: "optimized", label: t("crack_optimized"), type: "checkbox",
          value: settings.optimized !== false,
        },
        {
          name: "force", label: t("crack_force"), type: "checkbox",
          value: Boolean(settings.force),
        },
        {
          name: "timeout", label: t("crack_timeout"), type: "number",
          value: settings.timeout || 300,
        },
        {
          name: "extra", label: t("crack_extra"),
          value: settings.extra || "",
          placeholder: "--username -r rules/best64.rule",
        },
      ],
      okText: t("crack_start"),
    });
    if (!values) return;
    try {
      const data = await api("/api/crack", {
        method: "POST",
        body: {
          job, seq: item.seq,
          wordlist: values.wordlist,
          workload: values.workload,
          optimized: Boolean(values.optimized),
          force: Boolean(values.force),
          timeout: Number(values.timeout) || settings.timeout || 300,
          extra: values.extra || "",
        },
      });
      if (data.settings && state.meta.crack) {
        state.meta.crack.settings = data.settings;
      }
      showCrackProgress(data.task);
    } catch (error) {
      toast(error.message, "error", 7000);
    }
  }

  function showCrackProgress(task) {
    const running = !task.finished;
    openModal({
      title: `${t("crack_title")} · ${crackStatusLabel(task.status)}`,
      text: "",
      hideCancel: true,
      okText: t("crack_close"),
      extraButtons: running
        ? [{
            name: "stop", label: t("crack_stop"),
            onClick: (button) => { button.disabled = true; cancelCrack(task.id); },
          }]
        : [],
    });
    state.crack.id = task.id;
    state.crack.password = "";
    renderCrackProgress(task);
    if (!running) return;
    state.crack.timer = setInterval(async () => {
      if (state.crack.id !== task.id) return;
      try {
        const data = await api(`/api/crack?id=${encodeURIComponent(task.id)}`);
        if (state.crack.id !== task.id) return;
        renderCrackProgress(data.task);
      } catch (error) {
        stopCrackPoll();
        renderCrackProgress({ ...task, status: "error", error: error.message,
                              finished: true });
      }
    }, 1000);
  }

  function renderCrackProgress(task) {
    const body = $("#modal-body");
    const nearBottom = !body
      || body.scrollHeight - body.scrollTop - body.clientHeight < 60;
    let pre = $("#modal-body pre");
    if (!pre) {
      pre = document.createElement("pre");
      $("#modal-body").appendChild(pre);
    }
    const parts = [];
    if (task.log) parts.push(task.log.trim());
    if (task.password) parts.push(`${t("crack_password")}: ${task.password}`);
    if (task.error) parts.push(task.error);
    if (!parts.length) parts.push(crackStatusLabel(task.status));
    pre.textContent = parts.join("\n\n");
    if (nearBottom && body) body.scrollTop = body.scrollHeight;
    setText("#modal-title",
      `${t("crack_title")} · ${crackStatusLabel(task.status)}`);
    const foot = $("#modal-ok").parentElement;
    const stop = foot && foot.querySelector(".modal-extra");
    if (stop) {
      stop.disabled = Boolean(task.finished);
      stop.style.display = task.finished ? "none" : "";
    }
    if (task.password && foot && !foot.querySelector(".modal-crack-copy")) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "ghost modal-extra modal-crack-copy";
      button.textContent = `${t("crack_password")} ⧉`;
      button.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(task.password);
          toast(t("crack_copied"), "good", 1800);
        } catch (error) {
          toast(task.password, "info", 8000);
        }
      });
      foot.insertBefore(button, $("#modal-cancel"));
    }
    if (task.password && state.crack.password !== task.password) {
      state.crack.password = task.password;
      toast(`${t("crack_cracked")}: ${task.password}`, "good", 10000);
    }
    if (task.finished) stopCrackPoll();
  }

  async function cancelCrack(id) {
    try {
      const data = await api("/api/crack/cancel", {
        method: "POST", body: { id },
      });
      toast(data.text || t("crack_cancelled"), "good", 2000);
    } catch (error) {
      toast(error.message, "error", 6000);
    }
  }

  /* -------------------------------------------- NetNTLMv2 local cracking */
  const NTLMCRACK_STATUS_KEYS = {
    running: "ntlmcrack_running", cracked: "ntlmcrack_cracked",
    exhausted: "ntlmcrack_exhausted", error: "ntlmcrack_error",
    cancelled: "ntlmcrack_cancelled",
  };

  function ntlmcrackStatusLabel(status) {
    return t(NTLMCRACK_STATUS_KEYS[status] || "ntlmcrack_running");
  }

  function stopNtlmCrackPoll() {
    if (!state.ntlm) return;
    if (state.ntlm.timer) clearInterval(state.ntlm.timer);
    state.ntlm.timer = null;
    state.ntlm.id = "";
  }

  function isNtlmCrackable(item) {
    const extra = (item && item.extra) || {};
    const protocol = String(extra.protocol || "").toLowerCase();
    // NTLM/SMB 协议结果，或任何携带 NetNTLMv2 哈希行的 kind=hash 结果
    if (!["ntlm", "smb2"].includes(protocol) && item?.kind !== "hash") {
      return false;
    }
    return Boolean(ntlmTargetFields(extra));
  }

  function ntlmTargetFields(extra) {
    // hashcat -m 5600 行（user::domain:challenge:proof:blob）；响应长度
    // 下限 25 字节可挡掉 NetNTLMv1 行（lm+nt 恒为 24 字节）。
    const line = String(extra.hash || "").trim();
    const parts = line.includes("::") ? line.split("::", 2)[1].split(":") : [];
    if (parts.length === 4 && /^[0-9a-fA-F]{16}$/.test(parts[1])
        && /^[0-9a-fA-F]{32}$/.test(parts[2])
        && /^[0-9a-fA-F]{18,}$/.test(parts[3])
        && (parts[2] + parts[3]).length >= 50) {
      return { user: (line.split("::", 1)[0] || "").trim(),
               domain: parts[0], challenge: parts[1],
               nt_response: parts[2] + parts[3] };
    }
    // 结构化字段（user + challenge + ntproofstr/blob 或 nt_response）
    const user = String(extra.user || extra.account || "").trim()
      .split("\\").pop().split("@")[0].trim();
    const proof = String(extra.ntproofstr || extra.proof || "").trim();
    const blob = String(extra.blob || "").trim();
    const response = String(extra.nt_response || "").trim() || proof + blob;
    if (user && /^[0-9a-fA-F]{16}$/.test(String(extra.challenge || "").trim())
        && /^[0-9a-fA-F]{50,}$/.test(response)) {
      return { user, domain: String(extra.domain || ""),
               challenge: String(extra.challenge).trim(), nt_response: response };
    }
    return null;
  }

  async function openNtlmCrackDialog(item) {
    const job = packetJob();
    if (!job) {
      toast(state.language === "en"
        ? "No analysis job available" : "还没有可破解的分析任务", "warn");
      return;
    }
    const target = ntlmTargetFields((item && item.extra) || {});
    if (!target) {
      toast(t("ntlmcrack_error"), "warn", 6000);
      return;
    }
    const values = await openModal({
      title: `${t("ntlmcrack_title")} · ${target.user || "?"}`,
      text: t("ntlmcrack_hint"),
      fields: [
        { name: "candidates", label: t("ntlmcrack_candidates"), type: "textarea",
          value: "", placeholder: "Password123, admin, 123456" },
        { name: "min_len", label: t("ntlmcrack_min_len"), type: "number",
          value: 1, placeholder: "1" },
        { name: "max_len", label: t("ntlmcrack_max_len"), type: "number",
          value: 4, placeholder: "4" },
        {
          name: "alphabet", label: t("ntlmcrack_alphabet"),
          value: "ascii_letters+digits",
          placeholder: "ascii_letters+digits / digits / abc123",
        },
        { name: "max_attempts", label: t("ntlmcrack_max_attempts"), type: "number",
          value: 200000 },
        { name: "timeout", label: t("ntlmcrack_timeout"), type: "number",
          value: 300 },
      ],
      okText: t("ntlmcrack_start"),
    });
    if (!values) return;
    try {
      const data = await api("/api/ntlmcrack", {
        method: "POST",
        body: {
          job,
          seq: item.seq,
          candidates: values.candidates || "",
          min_len: Number(values.min_len) || 1,
          max_len: Number(values.max_len) || 4,
          alphabet: values.alphabet || "",
          max_attempts: Number(values.max_attempts) || 200000,
          timeout: Number(values.timeout) || 300,
        },
      });
      showNtlmCrackProgress(data.task);
    } catch (error) {
      toast(error.message, "error", 7000);
    }
  }

  function showNtlmCrackProgress(task) {
    const running = !task.finished;
    openModal({
      title: `${t("ntlmcrack_title")} · ${ntlmcrackStatusLabel(task.status)}`,
      text: "",
      hideCancel: true,
      okText: t("ntlmcrack_close"),
      extraButtons: running
        ? [{
            name: "stop", label: t("ntlmcrack_stop"),
            onClick: (button) => { button.disabled = true; cancelNtlmCrack(task.id); },
          }]
        : [],
    });
    state.ntlm.id = task.id;
    state.ntlm.password = "";
    renderNtlmCrackProgress(task);
    if (!running) return;
    state.ntlm.timer = setInterval(async () => {
      if (state.ntlm.id !== task.id) return;
      try {
        const data = await api(`/api/ntlmcrack?id=${encodeURIComponent(task.id)}`);
        if (state.ntlm.id !== task.id) return;
        renderNtlmCrackProgress(data.task);
      } catch (error) {
        stopNtlmCrackPoll();
        renderNtlmCrackProgress({ ...task, status: "error", error: error.message,
                                  finished: true });
      }
    }, 1000);
  }

  function renderNtlmCrackProgress(task) {
    const body = $("#modal-body");
    const nearBottom = !body
      || body.scrollHeight - body.scrollTop - body.clientHeight < 60;
    let pre = $("#modal-body pre");
    if (!pre) {
      pre = document.createElement("pre");
      $("#modal-body").appendChild(pre);
    }
    const parts = [];
    if (task.log) parts.push(task.log.trim());
    parts.push(`${t("ntlmcrack_attempts")}: ${task.attempts ?? 0}`
      + ` / ${task.max_attempts ?? "?"}`);
    if (task.password) parts.push(`${t("ntlmcrack_password")}: ${task.password}`);
    if (task.error) parts.push(task.error);
    pre.textContent = parts.join("\n\n");
    if (nearBottom && body) body.scrollTop = body.scrollHeight;
    setText("#modal-title",
      `${t("ntlmcrack_title")} · ${ntlmcrackStatusLabel(task.status)}`);
    const foot = $("#modal-ok").parentElement;
    const stop = foot && foot.querySelector(".modal-extra");
    if (stop) {
      stop.disabled = Boolean(task.finished);
      stop.style.display = task.finished ? "none" : "";
    }
    if (task.password && foot && !foot.querySelector(".modal-ntlm-copy")) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "ghost modal-extra modal-ntlm-copy";
      button.textContent = `${t("ntlmcrack_password")} ⧉`;
      button.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(task.password);
          toast(t("ntlmcrack_copied"), "good", 1800);
        } catch (error) {
          toast(task.password, "info", 8000);
        }
      });
      foot.insertBefore(button, $("#modal-cancel"));
    }
    if (task.password && state.ntlm.password !== task.password) {
      state.ntlm.password = task.password;
      toast(`${t("ntlmcrack_cracked")}: ${task.password}`, "good", 10000);
    }
    if (task.finished) stopNtlmCrackPoll();
  }

  async function cancelNtlmCrack(id) {
    try {
      const data = await api("/api/ntlmcrack/cancel", {
        method: "POST", body: { id },
      });
      toast(data.text || t("ntlmcrack_cancelled"), "good", 2000);
    } catch (error) {
      toast(error.message, "error", 6000);
    }
  }

  /* ------------------------------------------------------------ packets */
  const packetState = { job: null, frame: 0, wireshark: false, range: [1, 1] };

  function packetJob() {
    return state.jobId || state.findingsJob || "";
  }

  function closePacket() {
    $("#packet-modal").classList.add("hidden");
  }

  async function openPacket(frame) {
    const job = packetJob();
    const number = Number(frame);
    if (!job) { toast("请先运行或选择一个分析任务", "warn"); return; }
    if (!number) return;
    try {
      const data = await api(
        `/api/packet?job=${encodeURIComponent(job)}&frame=${number}&context=2`);
      packetState.job = job;
      packetState.frame = number;
      packetState.range = data.range || [number, number];
      packetState.wireshark = !!(data.tools && data.tools.wireshark);
      const packet = data.packet || {};
      setText("#packet-title",
        `数据包 · 帧 ${number}${packet.protocol ? ` · ${packet.protocol}` : ""}`);
      const rows = (data.neighbors || []).map((item) => {
        const active = String(item.frame) === String(number) ? " class=\"active\"" : "";
        return `<tr${active}><td class="mono">${esc(item.frame)}</td>` +
          `<td class="mono">${esc(item.time)}</td><td>${esc(item.protocol)}</td>` +
          `<td>${esc(item.info)}</td><td class="mono">${esc(item.length)}</td></tr>`;
      }).join("");
      $("#packet-body").innerHTML = `
        <div class="packet-summary"><strong>${esc(packet.protocol || "")}</strong>
          ${esc(packet.info || "")}</div>
        <table class="packet-neighbors">
          <thead><tr><th>帧</th><th>时间</th><th>协议</th><th>摘要</th><th>长度</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="5" class="muted">没有上下文帧</td></tr>'}</tbody>
        </table>
        <pre class="packet-detail">${esc(data.detail || "（没有详细解码输出）")}</pre>`;
      const wireshark = $("#packet-wireshark");
      wireshark.disabled = !packetState.wireshark;
      wireshark.title = packetState.wireshark ? "" : "未检测到 Wireshark";
      $("#packet-modal").classList.remove("hidden");
    } catch (error) {
      toast(error.message, "error", 7000);
    }
  }

  async function downloadPacketClip() {
    if (!packetState.job || !packetState.frame) return;
    const url = `/api/packet?job=${encodeURIComponent(packetState.job)}` +
      `&frame=${packetState.frame}&context=2&format=pcap` +
      `&token=${encodeURIComponent(TOKEN)}`;
    try {
      const response = await fetch(url);
      const type = response.headers.get("content-type") || "";
      if (!response.ok) {
        let message = `HTTP ${response.status}`;
        if (type.includes("application/json")) {
          const data = await response.json();
          message = data.error || message;
        }
        throw new Error(message);
      }
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = href;
      link.download = `fnet-frame-${packetState.frame}.pcapng`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(href), 4000);
      toast(`已导出帧 ${packetState.range[0]}-${packetState.range[1]} 的抓包片段`, "good");
    } catch (error) {
      toast(error.message, "error", 7000);
    }
  }

  async function openInWireshark() {
    if (!packetState.job || !packetState.frame) return;
    try {
      const data = await api("/api/action", {
        method: "POST",
        body: {
          action: "open_wireshark", job: packetState.job,
          frame: packetState.frame,
        },
      });
      toast(data.text || "已交给 Wireshark 打开", "good");
    } catch (error) {
      toast(error.message, "error", 7000);
    }
  }

  async function replayPacketSession() {
    if (!packetState.job || !packetState.frame) return;
    toast(t("replay_running"), "info", 2400);
    try {
      const data = await api("/api/replay", {
        method: "POST",
        body: { job: packetState.job, frame: packetState.frame },
      });
      const script = data.script || "";
      try {
        await navigator.clipboard.writeText(script);
        toast(t("replay_copied"), "good", 2600);
      } catch (error) { /* clipboard denied; the script is still shown */ }
      closePacket();
      await openModal({
        title: `${t("replay_title")} · ${data.kind === "http" ? "requests" : "socket"}`,
        text: script || data.text || "", hideCancel: true,
        okText: t("replay_close"),
      });
    } catch (error) {
      toast(error.message, "error", 8000);
    }
  }

  function bindPacket() {
    $("#packet-close").addEventListener("click", closePacket);
    $("#packet-ok").addEventListener("click", closePacket);
    $("#packet-clip").addEventListener("click", downloadPacketClip);
    $("#packet-wireshark").addEventListener("click", openInWireshark);
    $("#packet-replay").addEventListener("click", () => {
      replayPacketSession().catch((error) => toast(error.message, "error", 8000));
    });
    $("#packet-modal").addEventListener("click", (event) => {
      if (event.target === $("#packet-modal")) closePacket();
    });
  }

  async function loadFindings(jobId, options = {}) {
    const id = jobId || state.jobId;
    if (!id) return;
    try {
      const data = await api(`/api/findings?job=${encodeURIComponent(id)}`);
      if (state.jobId !== id) return;
      state.findingsJob = id;
      state.findings = data.findings || [];
      state.findingsDerived = !!data.derived;
      state.findingsTruncated = !!data.truncated;
      state.findingsPage = 1;
      state.findingsSelected = new Set();
      setText("#findings-count", String(data.total ?? state.findings.length));
      const csv = $("#findings-csv");
      csv.href = `/api/findings?job=${encodeURIComponent(id)}&format=csv&token=${
        encodeURIComponent(TOKEN)}`;
      csv.classList.remove("disabled");
      renderFindings();
    } catch (error) {
      if (!options.quiet) toast(`获取分析结果失败：${error.message}`, "error", 7000);
    }
  }

  function resetFindings() {
    state.findings = [];
    state.findingsVisible = [];
    state.findingsJob = null;
    state.findingsDerived = false;
    state.findingsTruncated = false;
    state.findingsSort = null;
    state.findingsPage = 1;
    state.findingsSelected = new Set();
    setText("#findings-count", "0");
    setText("#findings-visible", "");
    setText("#findings-summary", "");
    const csv = $("#findings-csv");
    if (csv) {
      csv.classList.add("disabled");
      csv.href = "#";
    }
    const box = $("#findings");
    if (box) {
      box.innerHTML = '<div class="muted">任务结束后，凭据、哈希、flag、导出文件等会汇总在这里。</div>';
    }
    renderFlagBar();
  }

  function restoreFindingsColumns() {
    try {
      const saved = JSON.parse(localStorage.getItem("fnet.findings.columns") || "[]");
      state.findingsHidden = new Set(Array.isArray(saved) ? saved : []);
    } catch (error) {
      state.findingsHidden = new Set();
    }
  }

  function saveFindingsColumns() {
    try {
      localStorage.setItem("fnet.findings.columns",
        JSON.stringify(Array.from(state.findingsHidden)));
    } catch (error) {}
    renderFindings();
  }

  function selectedFindingItems() {
    return state.findings.filter((item) =>
      state.findingsSelected.has(String(item.seq)));
  }

  async function copyFindings(mode = "page") {
    const items = mode === "selected"
      ? selectedFindingItems()
      : pageSlice(state.findingsVisible).items;
    if (!items.length) {
      toast(mode === "selected" ? "请先勾选要复制的结果" : "当前没有可复制的结果", "warn");
      return;
    }
    const columns = visibleFindingColumns();
    const rows = [columns.map(([, label]) => label)];
    items.forEach((item) => {
      rows.push(columns.map(([key]) => findingValue(item, key)));
    });
    const text = rows.map((row) =>
      row.map((cell) => String(cell).replace(/\t/g, " ").replace(/\n/g, " ")).join("\t"))
      .join("\n");
    try {
      await navigator.clipboard.writeText(text);
      toast(`已复制 ${items.length} 条结果`, "good", 1800);
    } catch (error) {
      toast("复制失败，请改用“导出 CSV”", "warn");
    }
  }

  /* ------------------------------------------------------- compare / rules */
  async function openCompareDialog() {
    let jobs = state.history || [];
    if (jobs.length < 2) {
      try {
        const data = await api("/api/history");
        jobs = data.jobs || [];
      } catch (error) {
        jobs = [];
      }
    }
    if (jobs.length < 2) {
      toast(state.language === "en"
        ? "At least two history jobs are required"
        : "至少需要两个历史任务才能对比", "warn");
      return;
    }
    const options = jobs.slice(0, 50).map((job) => ({
      value: job.id,
      label: `${job.pcap_name || job.pcap || "capture"} · ${
        job.finished || job.started || job.created || ""} · ${
        String(job.id).slice(0, 8)}`,
    }));
    const values = await openModal({
      title: state.language === "en" ? "Compare jobs" : "对比两个任务",
      fields: [
        { name: "base", label: state.language === "en" ? "Baseline" : "基准任务",
          type: "select", options, value: options[1].value },
        { name: "target", label: state.language === "en" ? "Target" : "对比任务",
          type: "select", options, value: options[0].value },
      ],
    });
    if (!values) return;
    if (values.base === values.target) {
      toast(state.language === "en" ? "Pick two different jobs" : "请选择两个不同任务",
        "warn");
      return;
    }
    try {
      const data = await api(`/api/compare?base=${encodeURIComponent(values.base)}`
        + `&target=${encodeURIComponent(values.target)}`);
      const counts = data.counts || {};
      const lines = [];
      lines.push(state.language === "en"
        ? `Added ${counts.added || 0}, removed ${counts.removed || 0}, `
          + `common ${counts.common || 0}`
        : `新增 ${counts.added || 0} 条，消失 ${counts.removed || 0} 条，`
          + `共有 ${counts.common || 0} 条`);
      const section = (label, items) => {
        if (!items || !items.length) return;
        lines.push("", `== ${label} ==`);
        items.slice(0, 80).forEach((item) => {
          lines.push(`  [${item.kind}] ${item.summary || ""}`);
        });
      };
      section(state.language === "en" ? "Added" : "新增", data.added);
      section(state.language === "en" ? "Removed" : "消失", data.removed);
      await openModal({
        title: state.language === "en" ? "Comparison" : "任务对比",
        text: lines.join("\n"), hideCancel: true,
        okText: state.language === "en" ? "Close" : "关闭",
      });
    } catch (error) {
      toast(error.message, "error", 8000);
    }
  }

  async function openRulesDialog() {
    let info = { file: "", count: 0, names: [], error: "" };
    try {
      info = await api("/api/rules");
    } catch (error) {
      toast(error.message, "error", 7000);
    }
    const lines = [];
    lines.push(state.language === "en"
      ? `Loaded rules: ${info.count || 0}`
      : `已加载规则: ${info.count || 0} 条`);
    if (info.names && info.names.length) {
      lines.push(info.names.slice(0, 30).join(", "));
    }
    if (info.error) lines.push(`${state.language === "en" ? "Error" : "错误"}: ${info.error}`);
    lines.push(state.language === "en"
      ? "Leave the path empty to disable custom rules."
      : "将路径留空可关闭自定义规则。");
    const values = await openModal({
      title: state.language === "en" ? "Custom rules" : "自定义规则",
      text: lines.join("\n"),
      fields: [{
        name: "file", label: state.language === "en" ? "Rule file" : "规则文件路径",
        value: info.file || "", placeholder: "/path/to/rules.yar",
      }],
    });
    if (!values) return;
    try {
      const data = await api("/api/rules", {
        method: "POST", body: { file: values.file },
      });
      toast(state.language === "en"
        ? `Rules: ${data.count || 0}` : `规则已更新: ${data.count || 0} 条`,
        "good");
      state.meta.rules = { file: data.file || "", count: data.count || 0 };
    } catch (error) {
      toast(error.message, "error", 8000);
    }
  }

  async function uploadRulesFile(file) {
    if (!file) return;
    try {
      const data = await uploadFile(file, { kind: "rules" });
      toast(data.text || (state.language === "en"
        ? "Rules imported" : "规则文件已导入"), "good", 6000);
      await refreshMeta();
    } catch (error) {
      toast(error.message, "error", 8000);
    }
  }

  /* --------------------------------------------------------- live capture */
  function closeLiveDialog() {
    $("#live-modal").classList.add("hidden");
    if (state.liveTimer) {
      clearInterval(state.liveTimer);
      state.liveTimer = null;
    }
  }

  async function openLiveDialog() {
    if (!(state.meta.live && state.meta.live.available)) {
      toast(state.language === "en"
        ? "Live capture needs tshark" : "实时抓包需要 tshark", "warn");
      return;
    }
    $("#live-modal").classList.remove("hidden");
    const select = $("#live-interface");
    select.innerHTML = '<option value="">加载中…</option>';
    try {
      const data = await api("/api/capture/interfaces");
      const interfaces = data.interfaces || [];
      select.innerHTML = interfaces.length
        ? interfaces.map((item) =>
          `<option value="${esc(item.name)}">${esc(item.name)}${
            item.description ? ` — ${esc(item.description)}` : ""}</option>`).join("")
        : '<option value="">未找到可用网卡（需要抓包权限）</option>';
    } catch (error) {
      select.innerHTML = `<option value="">${esc(error.message)}</option>`;
    }
    await refreshLiveStatus();
    if (state.liveTimer) clearInterval(state.liveTimer);
    state.liveTimer = setInterval(refreshLiveStatus, 1200);
  }

  async function refreshLiveStatus() {
    const box = $("#live-status");
    if (!box || $("#live-modal").classList.contains("hidden")) return;
    try {
      const data = await api("/api/capture/status");
      const capture = data.capture || {};
      const running = !!capture.running;
      $("#live-start").disabled = running;
      $("#live-stop").disabled = !running;
      const lines = [];
      lines.push(state.language === "en"
        ? `Status: ${running ? "capturing" : "stopped"}`
        : `状态: ${running ? "抓包中" : "已停止"}`);
      if (capture.interface) {
        lines.push(`${state.language === "en" ? "Interface" : "网卡"}: ${capture.interface}`);
      }
      if (capture.filter) {
        lines.push(`${state.language === "en" ? "Filter" : "过滤器"}: ${capture.filter}`);
      }
      if (capture.path) {
        lines.push(`${state.language === "en" ? "File" : "文件"}: ${capture.path}`);
      }
      if (running) {
        lines.push(`${state.language === "en" ? "Elapsed" : "已抓包"}: ${
          capture.elapsed || 0}s · ${fmtSize(capture.size || 0)}`);
      } else if (capture.size) {
        lines.push(`${state.language === "en" ? "Size" : "大小"}: ${fmtSize(capture.size)}`);
      }
      if (capture.output) lines.push(capture.output.trim().slice(-800));
      box.textContent = lines.join("\n");
    } catch (error) {
      box.textContent = error.message;
    }
  }

  async function startLiveCapture() {
    const interfaceName = val("live-interface");
    if (!interfaceName) {
      toast(state.language === "en" ? "Pick an interface" : "请选择网卡", "warn");
      return;
    }
    try {
      await api("/api/capture/start", {
        method: "POST",
        body: {
          interface: interfaceName,
          filter: val("live-filter"),
          name: val("live-name"),
        },
      });
      toast(state.language === "en" ? "Capture started" : "已开始抓包", "good");
      await refreshLiveStatus();
    } catch (error) {
      setText("#live-status", error.message);
      toast(error.message, "error", 8000);
    }
  }

  async function stopLiveCapture() {
    try {
      const analyze = checked("live-analyze");
      const data = await api("/api/capture/stop", {
        method: "POST",
        body: {
          analyze,
          features: selectedFeatures(),
          params: collectParams(),
        },
      });
      const capture = data.capture || {};
      if (capture.path) setPcap(capture.path);
      toast(state.language === "en" ? "Capture stopped" : "抓包已停止", "good");
      await refreshLiveStatus();
      if (analyze && data.job) {
        closeLiveDialog();
        attachJob(data.job, t("status_running"));
      }
    } catch (error) {
      toast(error.message, "error", 8000);
    }
  }

  /* --------------------------------------------------------------- menus */
  function bindMenus() {
    $$(".menu-btn").forEach((button) => {
      button.addEventListener("click", (event) => {
        event.stopPropagation();
        const menu = button.parentElement;
        const open = menu.classList.contains("open");
        $$(".menu.open").forEach((item) => item.classList.remove("open"));
        if (!open) menu.classList.add("open");
      });
    });
    document.addEventListener("click", () => {
      $$(".menu.open").forEach((item) => item.classList.remove("open"));
    });
    $$(".dropdown").forEach((dropdown) => {
      dropdown.addEventListener("click", (event) => event.stopPropagation());
    });
  }

  function bindEvents() {
    bindMenus();
    $("#theme-select").addEventListener("change", (event) => {
      applyTheme(event.target.value, true);
      toast(`主题已切换：${event.target.selectedOptions[0].textContent}`, "info", 1800);
    });
    const langSelect = $("#lang-select");
    if (langSelect) {
      langSelect.addEventListener("change", (event) => {
        applyLanguage(event.target.value, true);
        toast(state.language === "en" ? "Language: English" : "界面语言：中文",
          "info", 1800);
      });
    }
    $("#pause-btn").addEventListener("click", togglePause);
    $("#history-compare").addEventListener("click", () => {
      openCompareDialog().catch((error) => toast(error.message, "error", 8000));
    });
    $("#rules-input").addEventListener("change", (event) => {
      uploadRulesFile(event.target.files[0]);
      event.target.value = "";
    });
    $("#live-btn").addEventListener("click", () => {
      openLiveDialog().catch((error) => toast(error.message, "error", 8000));
    });
    $("#live-close").addEventListener("click", closeLiveDialog);
    $("#live-ok").addEventListener("click", closeLiveDialog);
    $("#live-start").addEventListener("click", startLiveCapture);
    $("#live-stop").addEventListener("click", stopLiveCapture);
    $("#live-modal").addEventListener("click", (event) => {
      if (event.target === $("#live-modal")) closeLiveDialog();
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && state.upload) {
        cancelUpload();
        toast("上传已取消", "warn");
      }
    });

    $("#file-input").addEventListener("change", (event) => {
      uploadFiles(event.target.files);
      event.target.value = "";
    });
    $("#drop-zone").addEventListener("click", () => $("#file-input").click());
    $("#drop-zone").addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") $("#file-input").click();
    });
    ["dragenter", "dragover"].forEach((name) => {
      $("#drop-zone").addEventListener(name, (event) => {
        event.preventDefault();
        $("#drop-zone").classList.add("drag");
      });
    });
    ["dragleave", "drop"].forEach((name) => {
      $("#drop-zone").addEventListener(name, (event) => {
        event.preventDefault();
        $("#drop-zone").classList.remove("drag");
      });
    });
    $("#drop-zone").addEventListener("drop", (event) => {
      const files = Array.from(event.dataTransfer.files || []);
      if (files.length) uploadFiles(files);
    });

    $("#use-path").addEventListener("click", () => {
      const path = val("pcap-path");
      if (!path) { toast("请输入服务器本地路径", "warn"); return; }
      setPcap(path);
      toast("已使用本地路径", "good", 1600);
    });
    $("#pcap-path").addEventListener("keydown", (event) => {
      if (event.key === "Enter") $("#use-path").click();
    });

    $("#toggle-all").addEventListener("click", () => {
      const boxes = $$("#features input[type=checkbox]");
      const all = boxes.every((box) => box.checked);
      boxes.forEach((box) => { box.checked = !all; });
      refreshSelected();
      renderRecentFeatures();
    });
    const globalSearch = $("#global-search");
    if (globalSearch) {
      globalSearch.addEventListener("input", () => {
        state.featureSearch = globalSearch.value;
        filterFeatures();
      });
      globalSearch.addEventListener("keydown", (event) => {
        if (event.key !== "Escape") return;
        globalSearch.value = "";
        state.featureSearch = "";
        filterFeatures();
        globalSearch.blur();
      });
    }
    document.addEventListener("keydown", (event) => {
      const tag = (event.target && event.target.tagName || "").toLowerCase();
      if (event.key === "/" && !event.ctrlKey && !event.metaKey
          && !["input", "textarea", "select"].includes(tag)) {
        event.preventDefault();
        if (!globalSearch) return;
        globalSearch.focus();
        globalSearch.select?.();
      }
    });
    $("#history-refresh").addEventListener("click", () => {
      loadHistory().then(() => toast("任务历史已刷新", "good", 1400))
        .catch((error) => toast(error.message, "error", 7000));
    });
    $("#history").addEventListener("click", (event) => {
      const button = event.target.closest("button[data-history]");
      if (!button) return;
      const id = button.dataset.id;
      const action = button.dataset.history;
      const task = action === "view" ? viewHistory(id)
        : action === "rerun" ? rerunHistory(id)
          : action === "delete" ? deleteHistory(id) : Promise.resolve();
      task.catch((error) => toast(error.message, "error", 8000));
    });
    $("#start-btn").addEventListener("click", () => {
      startJob(selectedFeatures(), collectParams());
    });
    $("#cancel-btn").addEventListener("click", cancelJob);
    $("#sidebar-toggle").addEventListener("click", () => {
      $("#sidebar").classList.toggle("collapsed");
    });

    $("#batch-refresh").addEventListener("click", () => {
      pollBatch();
      toast("批量队列已刷新", "good", 1400);
    });
    $("#batch-clear").addEventListener("click", clearBatch);
    $("#batch-pause").addEventListener("click", toggleBatchPause);
    $("#batch-merge").addEventListener("click", () => {
      mergeBatchReport().catch((error) => toast(error.message, "error", 7000));
    });
    $("#batch-concurrency").addEventListener("change", (event) => {
      batchControl("concurrency", { concurrency: Number(event.target.value) || 1 });
    });
    $("#batch").addEventListener("click", (event) => {
      const button = event.target.closest("button[data-batch]");
      if (!button) return;
      const id = button.dataset.id;
      const task = button.dataset.batch === "view" ? Promise.resolve(viewBatchJob(id))
        : button.dataset.batch === "cancel" ? cancelBatchJob(id) : Promise.resolve();
      task.catch((error) => toast(error.message, "error", 7000));
    });
    $("#batch").addEventListener("dragstart", (event) => {
      const row = event.target.closest("tr[draggable=true]");
      if (!row) return;
      state.batch.drag = row.dataset.id;
      try {
        if (event.dataTransfer) {
          event.dataTransfer.effectAllowed = "move";
          event.dataTransfer.setData("text/plain", row.dataset.id);
        }
      } catch (error) { /* older browsers reject custom drag data */ }
      row.classList.add("dragging");
    });
    $("#batch").addEventListener("dragend", () => {
      state.batch.drag = null;
      $$("#batch tr.dragging, #batch tr.drag-over").forEach((row) =>
        row.classList.remove("dragging", "drag-over"));
    });
    $("#batch").addEventListener("dragover", (event) => {
      const row = event.target.closest("tr[draggable=true]");
      if (!row || !state.batch.drag || row.dataset.id === state.batch.drag) return;
      event.preventDefault();
      $$("#batch tr.drag-over").forEach((item) => item.classList.remove("drag-over"));
      row.classList.add("drag-over");
    });
    $("#batch").addEventListener("drop", (event) => {
      const row = event.target.closest("tr[draggable=true]");
      if (!row || !state.batch.drag) return;
      event.preventDefault();
      const order = (state.batch.summary && state.batch.summary.pending) || [];
      const ids = [...order];
      const from = ids.indexOf(state.batch.drag);
      const to = ids.indexOf(row.dataset.id);
      if (from >= 0 && to >= 0) {
        ids.splice(from, 1);
        ids.splice(to, 0, state.batch.drag);
        reorderBatch(ids).catch((error) => toast(error.message, "error", 7000));
      } else {
        toast("只能调整排队中的任务顺序", "warn");
      }
    });
    $("#tls-key-input").addEventListener("change", (event) => {
      uploadTlsKey(event.target.files[0]);
      event.target.value = "";
    });
    $("#viz-refresh").addEventListener("click", () => {
      loadViz().catch((error) => toast(error.message, "error", 7000));
    });
    $("#viz-buckets").addEventListener("change", () => {
      loadViz().catch((error) => toast(error.message, "error", 7000));
    });
    $("#viz-metric").addEventListener("change", renderViz);
    $("#viz-zoom-reset").addEventListener("click", () => {
      state.viz.zoom = null;
      renderTimeline();
    });
    $("#viz-export-svg").addEventListener("click", downloadSvg);
    $("#viz-export-png").addEventListener("click", () => {
      downloadPng().catch((error) => toast(error.message, "error", 7000));
    });
    $("#viz-protocols").addEventListener("click", (event) => {
      const row = event.target.closest("[data-protocol]");
      if (row) openProtocolDetail(row.dataset.protocol);
    });
    $("#viz-protocols").addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      const row = event.target.closest("[data-protocol]");
      if (!row) return;
      event.preventDefault();
      openProtocolDetail(row.dataset.protocol);
    });
    $("#viz-topology").addEventListener("click", (event) => {
      const node = event.target.closest(".topo-node");
      if (node) filterFindingsByEndpoint(node.dataset.node);
    });
    $("#viz-topology").addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      const node = event.target.closest(".topo-node");
      if (!node) return;
      event.preventDefault();
      filterFindingsByEndpoint(node.dataset.node);
    });

    $("#log-search").addEventListener("input", debounce(reRenderLog, 180));
    $("#log-filter").addEventListener("change", reRenderLog);
    $("#log-level").addEventListener("change", reRenderLog);
    $("#log").addEventListener("click", (event) => {
      const link = event.target.closest(".frame-link");
      if (link) openPacket(link.dataset.frame);
    });
    $("#clear-log").addEventListener("click", () => {
      state.logs = [];
      $("#log").innerHTML = '<div class="log-empty">日志已清空。</div>';
    });
    $("#download-log").addEventListener("click", () => {
      const text = state.logs.map((record) =>
        `${record.time || ""} ${record.tag || ""} ${record.text}`).join("\n");
      downloadText(`fnet-log-${Date.now()}.txt`, text || "（无日志）");
    });

    $$(".tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        switchTab(tab.dataset.tab);
        if (tab.dataset.tab === "history") {
          loadHistory().catch((error) => toast(error.message, "error", 7000));
        }
        if (tab.dataset.tab === "findings") {
          loadFindings(state.jobId, { quiet: true });
        }
        if (tab.dataset.tab === "batch") {
          pollBatch();
        }
        if (tab.dataset.tab === "viz") {
          loadViz().catch((error) => toast(error.message, "error", 7000));
        }
      });
    });

    $("#findings-search").addEventListener("input", debounce(() => {
      state.findingsPage = 1;
      renderFindings();
    }, 120));
    $("#findings-kind").addEventListener("change", () => {
      state.findingsPage = 1;
      renderFindings();
    });
    $("#findings-level").addEventListener("change", () => {
      state.findingsPage = 1;
      renderFindings();
    });
    $("#findings-page-size").addEventListener("change", (event) => {
      state.findingsPageSize = Number(event.target.value) || 100;
      state.findingsPage = 1;
      renderFindings();
    });
    $("#findings-refresh").addEventListener("click", () => {
      if (!state.jobId) { toast("还没有分析任务", "warn"); return; }
      loadFindings(state.jobId)
        .then(() => toast("分析结果已刷新", "good", 1400))
        .catch((error) => toast(error.message, "error", 7000));
    });
    $("#findings-copy").addEventListener("click", () => copyFindings("page"));
    $("#findings-copy-selected").addEventListener("click",
      () => copyFindings("selected"));
    $("#findings-columns-btn").addEventListener("click", () => {
      $("#findings-columns").classList.toggle("hidden");
    });
    $("#findings-columns").addEventListener("change", (event) => {
      const box = event.target.closest("input[data-column]");
      if (!box) return;
      if (box.checked) state.findingsHidden.delete(box.dataset.column);
      else state.findingsHidden.add(box.dataset.column);
      saveFindingsColumns();
    });
    $("#findings-jump").addEventListener("click", () => {
      const frame = Number(val("findings-frame-jump"));
      if (!frame) { toast("请输入帧号", "warn"); return; }
      openPacket(frame);
    });
    $("#findings-frame-jump").addEventListener("keydown", (event) => {
      if (event.key === "Enter") $("#findings-jump").click();
    });
    $("#findings-pager").addEventListener("click", (event) => {
      const button = event.target.closest("button[data-page]");
      if (!button || button.disabled) return;
      state.findingsPage = Number(button.dataset.page) || 1;
      renderFindings();
    });
    $("#findings").addEventListener("click", (event) => {
      const frame = event.target.closest(".frame-link");
      if (frame) {
        event.stopPropagation();
        openPacket(frame.dataset.frame);
        return;
      }
      const select = event.target.closest(".finding-select");
      if (select) {
        const seq = String(select.dataset.seq);
        if (select.checked) state.findingsSelected.add(seq);
        else state.findingsSelected.delete(seq);
        select.closest("tr").classList.toggle("selected", select.checked);
        return;
      }
      const selectPage = event.target.closest("#findings-select-page");
      if (selectPage) {
        pageSlice(state.findingsVisible).items.forEach((item) => {
          if (selectPage.checked) state.findingsSelected.add(String(item.seq));
          else state.findingsSelected.delete(String(item.seq));
        });
        renderFindings();
        return;
      }
      const header = event.target.closest("th[data-sort]");
      if (header) {
        const key = header.dataset.sort;
        const sort = state.findingsSort;
        // 三态循环：升序 → 降序 → 回到默认时间排序（null）。
        state.findingsSort = !sort || sort.key !== key
          ? { key, dir: 1 }
          : sort.dir === 1 ? { key, dir: -1 } : null;
        state.findingsPage = 1;
        renderFindings();
        return;
      }
      const row = event.target.closest("tr[data-seq]");
      if (row) showFinding(row.dataset.seq);
    });
    $("#findings").addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      if (event.target.closest(".frame-link")) return;
      const row = event.target.closest("tr[data-seq]");
      if (!row) return;
      event.preventDefault();
      showFinding(row.dataset.seq);
    });
    // Flag 汇总条：复制按钮优先，其次点击 chip 打开对应 finding；
    // 只有 extra.flags 兜底出来的 chip 没有 seq，点击时退化为复制。
    const flagBar = $("#flag-bar");
    if (flagBar) {
      flagBar.addEventListener("click", (event) => {
        const copy = event.target.closest("[data-flag-copy]");
        if (copy) {
          copyFlagText(copy.dataset.flagCopy);
          return;
        }
        const chip = event.target.closest(".flag-chip");
        if (!chip) return;
        if (chip.dataset.flagSeq) showFinding(chip.dataset.flagSeq);
        else copyFlagText(chip.textContent || "");
      });
    }

    $("#decode-btn").addEventListener("click", runDecode);
    $("#copy-decode").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(state.decodeText || "");
        toast("解码结果已复制", "good", 1600);
      } catch (error) {
        toast("复制失败，请手动选择文本", "warn");
      }
    });

    // Settings persistence.
    ["webshell_mode", "webshell_password", "webshell_filter", "shiro_mode",
      "shiro_remember", "shiro_key", "shiro_enctype", "winrm_auth",
      "winrm_ntlm", "winrm_password", "winrm_port", "sql_regex",
      "sql_success", "sql_compare", "sql_time_threshold", "sql_char",
      "sql_reverse", "sql_log", "keywords", "auto_regex", "post_only",
      "decode_aux", "wordlist"].forEach((id) => {
      const el = $("#" + id);
      if (!el) return;
      el.addEventListener("change", saveLocalSettings);
    });

    document.addEventListener("keydown", (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "enter") {
        event.preventDefault();
        $("#start-btn").click();
      }
      if (event.key === "Escape") { closeModal(); closePacket(); }
    });

    $$(".dropdown button[data-action]").forEach((button) => {
      button.addEventListener("click", () => {
        handleAction(button.dataset.action, button.dataset);
        $$(".menu.open").forEach((item) => item.classList.remove("open"));
      });
    });
    $$(".dropdown button[data-setting]").forEach((button) => {
      button.addEventListener("click", () => openSettingDialog(button.dataset.setting));
    });
    $$(".dropdown button[data-plugin]").forEach((button) => {
      button.addEventListener("click", () => runPlugin(button.dataset.plugin));
    });
  }

  function debounce(fn, delay) {
    let timer = null;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), delay);
    };
  }

  function switchTab(name) {
    $$(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === name));
    $$(".tab-panel").forEach((panel) =>
      panel.classList.toggle("active", panel.id === `tab-${name}`));
  }

  /* ------------------------------------------------------------- actions */
  async function handleAction(action, dataset = {}) {
    try {
      if (action === "pick-file") { $("#file-input").click(); return; }
      if (action === "shutdown") {
        if (!confirm("确定要停止 Fnet WebUI 服务吗？")) return;
        await api("/api/shutdown", { method: "POST", body: {} });
        document.body.innerHTML =
          '<div style="padding:40px;font-family:system-ui;color:#ccc;background:#1e2228;min-height:100vh">' +
          '<h2>Fnet 服务已停止</h2><p>可以关闭此页面，或在终端重新运行 <code>fnet</code>。</p></div>';
        return;
      }
      if (action === "about") { switchTab("about"); return; }
      if (action === "open-source") { switchTab("about"); return; }
      if (action === "github" || action === "open-url") {
        const url = dataset.url || "https://github.com/fyfhcgch/Fnet";
        await api("/api/action", { method: "POST", body: { action: "open_url", url } });
        toast("已在浏览器中打开项目仓库", "good");
        return;
      }
      if (action === "report-view") {
        if (!state.jobId) { toast("还没有分析任务", "warn"); return; }
        window.open(reportUrl(state.jobId, "html", true), "_blank", "noopener");
        return;
      }
      if (action === "report-export") {
        if (!state.jobId) { toast("还没有分析任务", "warn"); return; }
        const catalog = reportCatalog();
        if (!catalog.length) { toast("当前版本没有可导出的报告章节", "warn"); return; }
        const values = await openModal({
          title: "导出分析报告",
          fields: [
            {
              name: "format", label: "格式", type: "select", value: "html",
              options: [
                { value: "html", label: "HTML（可直接打印为 PDF）" },
                { value: "markdown", label: "Markdown" },
              ],
            },
            {
              name: "sections", label: "包含章节", type: "checkboxes",
              value: state.reportSections,
              options: catalog.map((item) => ({ value: item.key, label: item.title })),
            },
          ],
          okText: "导出",
        });
        if (!values) return;
        const sections = Array.isArray(values.sections) ? values.sections : [];
        if (!sections.length) { toast("请至少选择一个报告章节", "warn"); return; }
        saveReportSections(sections);
        window.location.href = reportUrl(state.jobId, values.format || "html");
        toast("报告已开始下载", "good", 2400);
        return;
      }
      if (action === "download-report") {
        if (!state.jobId) { toast("还没有分析任务", "warn"); return; }
        const url = `/api/download?job=${encodeURIComponent(state.jobId)}&path=report.txt&token=${encodeURIComponent(TOKEN)}`;
        window.location.href = url;
        return;
      }
      if (action === "save_config") {
        const data = await api("/api/action", { method: "POST", body: { action } });
        toast(data.text || "配置已保存", "good");
        return;
      }
      if (action === "reload_config") {
        const data = await api("/api/action", { method: "POST", body: { action } });
        toast(data.text || "配置已重载", "good");
        state.meta.config = data.config || state.meta.config;
        return;
      }
      if (action === "open_log") {
        const data = await api("/api/action", { method: "POST", body: { action } });
        toast(data.text || "已打开日志目录", "info");
        return;
      }
      if (action === "plugin_add") {
        const values = await openModal({
          title: "添加自定义工具",
          fields: [
            { name: "name", label: "工具名称", placeholder: "例如 mytool" },
            { name: "command", label: "命令", placeholder: "例如 /usr/bin/mytool --arg" },
          ],
        });
        if (!values) return;
        const data = await api("/api/action", {
          method: "POST",
          body: { action: "plugin_add", ...values },
        });
        toast(data.text || "已添加工具", "good");
        await refreshMeta();
        return;
      }
      if (action === "plugin_manage") {
        const userTools = (state.plugins || []).filter((item) => item.source === "user");
        if (!userTools.length) { toast("还没有自定义工具", "info"); return; }
        const values = await openModal({
          title: "管理自定义工具",
          fields: [{
            name: "name", label: "选择要移除的工具", type: "select",
            options: userTools.map((item) => ({ value: item.key, label: `${item.name} — ${item.target}` })),
          }],
          okText: "移除",
        });
        if (!values) return;
        const data = await api("/api/action", {
          method: "POST", body: { action: "plugin_remove", name: values.name },
        });
        toast(data.ok ? "已移除" : "未找到工具", data.ok ? "good" : "warn");
        await refreshMeta();
        return;
      }
      if (action === "update_check") {
        const data = await api("/api/action", { method: "POST", body: { action } });
        await openModal({ title: "检查更新", text: data.text, hideCancel: true });
        return;
      }
      if (action === "run_webshell") {
        await startJob(["webshell.decrypt"], collectParams(), "Webshell 解密");
        return;
      }
      if (action === "http_login") {
        if (!state.pcap) { toast("请先选择抓包文件", "warn"); return; }
        const data = await api("/api/action", {
          method: "POST", body: { action, pcap: state.pcap },
        });
        attachJob(data.job, "HTTP 登录识别");
        return;
      }
      if (action === "protocol_credentials" || action === "protocol_smb2") {
        const handler = action === "protocol_smb2"
          ? "protocols.smb2" : "protocols.credentials";
        const label = action === "protocol_smb2"
          ? "SMB2 文件与 NTLM 认证" : "多协议凭据提取";
        await startJob([handler], collectParams(), label);
        return;
      }
      if (action === "protocol_detect") {
        await startJob(["protocols.detect"], collectParams(), "协议自动识别");
        return;
      }
      if (action === "flag_deep") {
        await startJob(["text_scan.deep"], collectParams(), "深度 flag 扫描");
        return;
      }
      if (action === "forensics_correlate") {
        await startJob(["forensics.correlate"], collectParams(), "跨协议凭据关联");
        return;
      }
      if (action === "forensics_timeline") {
        await startJob(["forensics.timeline"], collectParams(), "认证时间线");
        return;
      }
      if (action === "upload-tls-keylog" || action === "upload-tls-key") {
        state.tlsKeyKind = action === "upload-tls-key" ? "key" : "keylog";
        $("#tls-key-input").accept = state.tlsKeyKind === "key"
          ? ".key,.pem,.crt,.txt" : ".log,.txt,.key,.pem";
        $("#tls-key-input").click();
        return;
      }
      if (action === "rules_settings") {
        await openRulesDialog();
        return;
      }
      if (action === "upload-rules") {
        $("#rules-input").click();
        return;
      }
      if (["export_objects", "carve", "repair", "etl"].includes(action)) {
        if (!state.pcap) { toast("请先选择抓包文件", "warn"); return; }
        toast("正在执行，请稍候…", "info");
        const body = { action, pcap: state.pcap };
        if (action === "etl") body.pcap = state.pcap;
        const data = await api("/api/action", { method: "POST", body });
        appendSystem(data.text || "操作完成", data.ok ? "good" : "error");
        switchTab("log");
        toast(data.ok ? "操作完成" : "操作失败", data.ok ? "good" : "error");
        return;
      }
      if (action === "stats") {
        if (!state.pcap) { toast("请先选择抓包文件", "warn"); return; }
        toast("正在统计…", "info");
        const data = await api("/api/action", {
          method: "POST", body: { action: "stats", sub: dataset.sub, pcap: state.pcap },
        });
        appendSystem(data.text || "统计完成", data.ok ? "good" : "error");
        switchTab("log");
        return;
      }
      toast(`未知操作：${action}`, "warn");
    } catch (error) {
      toast(error.message, "error", 8000);
    }
  }

  async function refreshMeta() {
    const meta = await api("/api/meta");
    state.meta.plugins = meta.plugins;
    state.plugins = meta.plugins;
    state.meta.tools = meta.tools;
    renderTools(meta.tools);
  }

  async function runPlugin(key) {
    try {
      if (!state.pcap && !["cyberchef"].includes(key)) {
        toast("请先选择抓包文件", "warn");
        return;
      }
      toast(`正在运行 ${key}…`, "info");
      const data = await api("/api/action", {
        method: "POST",
        body: { action: "plugin_run", key, target: state.pcap },
      });
      appendSystem(data.text || "工具执行完成", "good");
      switchTab("log");
      if (key === "cyberchef") toast("已在浏览器中打开 CyberChef", "good");
    } catch (error) {
      toast(error.message, "error", 7000);
    }
  }

  /* ------------------------------------------------------------ settings */
  const SETTING_META = {
    tls_keylog: { section: "paths", label: "TLS keylog 文件路径", placeholder: "/path/to/sslkeylog.log" },
    cobaltstrike_keys: { section: "paths", label: "Cobalt Strike beacon keys / minidump 路径", placeholder: "/path/to/.cobaltstrike.beacon_keys" },
    rdp_private_key: { section: "paths", label: "RDP 私钥或 Key log 路径", placeholder: "/path/to/rdp.key" },
    antsword_rsa_public_key: { section: "paths", label: "AntSword RSA 公钥路径", placeholder: "/path/to/public.pem" },
    passwddir: { section: "config", label: "暴力破解字典路径", placeholder: "/usr/share/wordlists/rockyou.txt" },
    javapath: { section: "config", label: "Java 可执行文件路径", placeholder: "/usr/bin/java" },
    tshark: { section: "config", label: "tshark 路径", placeholder: "/usr/bin/tshark" },
  };

  async function openSettingDialog(key) {
    const meta = SETTING_META[key];
    if (!meta) return;
    const snapshot = state.meta.config || {};
    const current = (snapshot[meta.section] || {})[key] || "";
    const values = await openModal({
      title: meta.label,
      fields: [{ name: "value", label: meta.label, value: current, placeholder: meta.placeholder }],
    });
    if (!values) return;
    await saveConfig(meta.section, { [key]: values.value });
    state.meta.config[meta.section] = state.meta.config[meta.section] || {};
    state.meta.config[meta.section][key] = values.value;
    toast("设置已保存", "good");
    if (key === "tshark") await refreshMeta();
  }

  async function saveConfig(section, values) {
    const data = await api("/api/config", {
      method: "POST", body: { section, values },
    });
    if (data.config) state.meta.config = data.config;
  }

  /* --------------------------------------------------------------- modal */
  let modalResolve = null;

  function openModal({ title, fields = [], text = "", html = "",
                       okText = "确定", hideCancel = false,
                       extraButtons = [] }) {
    // A new dialog supersedes any crack log that was being polled.
    stopCrackPoll();
    stopNtlmCrackPoll();
    const modal = $("#modal");
    setText("#modal-title", title);
    const body = $("#modal-body");
    body.innerHTML = "";
    const foot = $("#modal-ok").parentElement;
    $$(".modal-extra", foot).forEach((node) => node.remove());
    extraButtons.forEach((spec) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "ghost modal-extra";
      button.textContent = spec.label || spec.name;
      button.addEventListener("click", () => {
        if (typeof spec.onClick === "function") spec.onClick(button);
        else closeModal({ __action: spec.name });
      });
      foot.insertBefore(button, $("#modal-cancel"));
    });
    if (text) {
      const pre = document.createElement("pre");
      pre.textContent = text;
      body.appendChild(pre);
    }
    if (html) {
      const block = document.createElement("div");
      block.className = "modal-detail";
      block.innerHTML = html;
      body.appendChild(block);
    }
    fields.forEach((field) => {
      const wrap = document.createElement("div");
      wrap.className = "field";
      if (field.type === "checkbox") {
        const item = document.createElement("label");
        item.className = "inline";
        const box = document.createElement("input");
        box.type = "checkbox";
        box.id = `modal-field-${field.name}`;
        box.checked = Boolean(field.value);
        item.appendChild(box);
        item.appendChild(document.createTextNode(` ${field.label || field.name}`));
        wrap.appendChild(item);
        body.appendChild(wrap);
        return;
      }
      const label = document.createElement("label");
      label.textContent = field.label || field.name;
      wrap.appendChild(label);
      if (field.type === "checkboxes") {
        const group = document.createElement("div");
        group.className = "check-list";
        group.id = `modal-field-${field.name}`;
        const selected = new Set(Array.isArray(field.value) ? field.value : []);
        (field.options || []).forEach((option) => {
          const item = document.createElement("label");
          item.className = "inline";
          const box = document.createElement("input");
          box.type = "checkbox";
          box.value = option.value;
          box.checked = selected.has(option.value);
          item.appendChild(box);
          item.appendChild(document.createTextNode(` ${option.label}`));
          group.appendChild(item);
        });
        wrap.appendChild(group);
        body.appendChild(wrap);
        return;
      }
      let input;
      if (field.type === "select") {
        input = document.createElement("select");
        (field.options || []).forEach((option) => {
          const node = document.createElement("option");
          node.value = option.value;
          node.textContent = option.label;
          input.appendChild(node);
        });
      } else if (field.type === "textarea") {
        input = document.createElement("textarea");
        input.rows = 6;
      } else {
        input = document.createElement("input");
        input.type = field.type || "text";
      }
      input.id = `modal-field-${field.name}`;
      if (input.type === "checkbox") input.checked = Boolean(field.value);
      else input.value = field.value ?? "";
      if (field.placeholder) input.placeholder = field.placeholder;
      if (field.readonly) input.readOnly = true;
      wrap.appendChild(input);
      body.appendChild(wrap);
    });
    modal.classList.remove("hidden");
    $("#modal-cancel").style.display = hideCancel ? "none" : "";
    $("#modal-ok").textContent = okText;
    $("#modal-ok").focus();
    return new Promise((resolve) => { modalResolve = resolve; });
  }

  function closeModal(result = null) {
    stopCrackPoll();
    stopNtlmCrackPoll();
    $("#modal").classList.add("hidden");
    const resolve = modalResolve;
    modalResolve = null;
    if (resolve) resolve(result);
  }

  function bindModal() {
    $("#modal-close").addEventListener("click", () => closeModal(null));
    $("#modal-cancel").addEventListener("click", () => closeModal(null));
    $("#modal-ok").addEventListener("click", () => {
      const values = {};
      $$("#modal-body [id^=modal-field-]").forEach((input) => {
        const name = input.id.replace("modal-field-", "");
        if (input.classList.contains("check-list")) {
          values[name] = $$("input[type=checkbox]:checked", input).map((box) => box.value);
        } else if (input.type === "checkbox") {
          values[name] = input.checked;
        } else {
          values[name] = input.value;
        }
      });
      closeModal(values);
    });
    $("#modal").addEventListener("click", (event) => {
      if (event.target === $("#modal")) closeModal(null);
    });
    // 结果详情弹窗的“一键解码”/载荷面板：按钮是动态注入的，走事件委托。
    $("#modal-body").addEventListener("click", (event) => {
      const copyFlag = event.target.closest("[data-flag-copy]");
      if (copyFlag) {
        event.preventDefault();
        copyFlagText(copyFlag.dataset.flagCopy);
        return;
      }
      const payloadButton = event.target.closest("[data-payload-action]");
      if (payloadButton) {
        event.preventDefault();
        handlePayloadAction(payloadButton);
        return;
      }
      const button = event.target.closest("[data-decode-action]");
      if (button) handleDecodeAction(button);
    });
  }

  /* ---------------------------------------------------------- text tools */
  async function runDecode() {
    const text = $("#decode-input").value;
    if (!text.trim()) { toast("请先粘贴文本", "warn"); return; }
    try {
      const data = await api("/api/decode", { method: "POST", body: { text } });
      const box = $("#decode-output");
      box.classList.remove("muted");
      if (!data.candidates || !data.candidates.length) {
        box.innerHTML = '<div class="muted">没有找到可读的解码结果。</div>';
        state.decodeText = "";
        return;
      }
      state.decodeText = data.candidates.map((item) =>
        `[${item.label}]\n${item.value}`).join("\n\n");
      const flags = (data.flags || []).map((flag) =>
        `<span class="flag-chip">${esc(flag)}</span>`).join("");
      box.innerHTML = (flags ? `<div>${flags}</div>` : "") +
        data.candidates.map((item) => `
          <div class="decode-item">
            <div class="decode-label">${esc(item.label)}</div>
            <div class="decode-value">${esc(item.value)}</div>
          </div>`).join("");
    } catch (error) {
      toast(error.message, "error", 7000);
    }
  }

  function downloadText(filename, text) {
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 2000);
  }

  /* ---------------------------------------------------------- local state */
  const LOCAL_IDS = ["webshell_mode", "webshell_password", "webshell_filter",
    "shiro_mode", "shiro_remember", "shiro_key", "shiro_enctype", "winrm_auth",
    "winrm_ntlm", "winrm_password", "winrm_port", "sql_regex", "sql_success",
    "sql_compare", "sql_time_threshold", "sql_char", "sql_reverse", "sql_log",
    "keywords", "auto_regex", "post_only", "decode_aux", "wordlist"];

  function saveLocalSettings() {
    const data = {};
    LOCAL_IDS.forEach((id) => {
      const el = $("#" + id);
      if (!el) return;
      data[id] = el.type === "checkbox" ? el.checked : el.value;
    });
    try { localStorage.setItem("fnet.settings", JSON.stringify(data)); } catch (error) {}
  }

  function restoreLocalSettings() {
    let data = {};
    try { data = JSON.parse(localStorage.getItem("fnet.settings") || "{}"); } catch (error) {}
    LOCAL_IDS.forEach((id) => {
      if (!(id in data)) return;
      const el = $("#" + id);
      if (!el) return;
      if (el.type === "checkbox") el.checked = !!data[id];
      else el.value = data[id];
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    bindModal();
    bindPacket();
    init().catch((error) => {
      document.body.innerHTML = `<div style="padding:40px;font-family:system-ui;color:#eee;background:#1e2228;min-height:100vh">
        <h2>Fnet 启动失败</h2><pre style="white-space:pre-wrap">${esc(error.message)}</pre>
        <p>请确认服务仍在运行，然后刷新页面。</p></div>`;
    });
  });
})();
