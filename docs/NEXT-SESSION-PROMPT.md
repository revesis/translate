继续 Google BotGuard 字节码反编译（接着上一段工作的进度，不要从头重来）

工作目录：/root/codex/google-translate（git 远程 git@github.com:revesis/translate.git，分支 main）

第一步：先读 docs/botguard-notes.md 全文（§1–§13），这是唯一的基线。里面已经记录了：
- 可信/降级两种 token 的字节结构与区分方法
- 9 类已排除的信任假设（环境值、原型、布局、frame API、realm 内建、时钟、17 个原生函数、
  Error.stack/prepareStackTrace、sourceURL）
- 字节码离线取法：base64.b64decode(arr[0][3:3+29804]) → 22353 字节，构建固定
- 解释器完整性校验：arr[2] == base64url(sha256(解释器源码))，逐字节验证过
- 读取器完整源码与语义：JY(bits, decryptFlag, vm)，位指针在字段 230，可跨字节边界，
  NU 是 XOR 加密的，种子是程序内 32 位（字段 15）
- 字段写入器 D(fieldId, vm, value) 的规则（230=位指针，21=concat，10 个特定 id 走
  R(7,…)，其余走 R(21,…)）
- 13 个章节的结论与 4 个否定结果（尤其 §13：用抓到的密钥流做离线解密不成立，别重试）

已验证可用的工具与产物（都在 /tmp，若已清理可按笔记重建）：
- /tmp/interp_patched.js：插桩后的解释器源码（在 JY 入口和返回处记录读取与明文值）
- /tmp/reader_log.json：13482 次读取的位序列（12666×8 位 + 812×2 位 + 4×32 位）
- /tmp/reader_vals.json：13429 个解密后的返回值
- /tmp/bytecode.json：NU 原始 22353 字节
- /tmp/build3/arr.json：构建素材（arr[2] 是 hash，arr[5][-1] 是解释器源码）
- /tmp/freq_A.txt：内容绑定字符串
- 脚本：/tmp/src_vals.py（插桩+记录值）、/tmp/src_ks4.py（记录密钥流，结论是否定的）

关键技术要点（避免重走弯路）：
- 网页里的 VM 跑在 iframe realm，日志要从 document.querySelectorAll('iframe')[0].contentWindow
  取，不是顶层 window
- 改解释器源码后必须重算 arr[2] = base64url(sha256(新源码))，否则不执行（token 会塌到 913 字符）
- 插桩版会让 token 降级（913 字符），这不影响取数，不要试图同时拿可信 token
- 断点式追踪很慢：pause/resume 每次 1–2ms，Runtime.evaluate 有 120s 上限，单次轨迹控制在
  几百到一千次命中
- 按名字挂断点不可靠（标识符每次构建轮换且会撞名，比如 sh 在本构建里是 DOM 辅助函数）；
  按"参数是否随命中变化"判定分发器

本轮要继续做的事：
给惰性字段路径插桩（R / T → .create()，以及 w 里的 .create() 调用），把它的读取位置与 JY
的读取日志合并，补齐目前缺失的约 42% 程序内容。已是确定结论：JY 路径只覆盖 57.6%
（178824 位里 103034 位），中间有两段跳跃（32118 位和 59064 位）从不被 JY 读到，它们由字段
惰性创建路径按需读出。

目标和判断标准：
拿到 100% 的明文程序字节流，然后从中还原指令/字段结构，最终能用它对任意输入离线生成签名
所需的字段表。每个结论都要有可复现的实测输出支撑；发现之前的结论错了就直接撤回并在笔记里
改正（前面已经撤回过两次：hq 是构建常量、F×2 位偏移框架）。

交付要求：
- 新的发现继续追加到 docs/botguard-notes.md（保持章节编号连续，或新增 §14 起）
- 代码注释和 docstring 用英文，聊天回复用中文
- 每完成一个可验证的结论就 commit + push 到 main，commit message 说清楚证据
- 不要动已上线的 sidecar 部分（gt_server.py / bgr_sidecar.py / Dockerfile 等），
  反编译是独立研究线
