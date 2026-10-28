继续 Google BotGuard 字节码反编译（接着上一段工作的进度，不要从头重来）

工作目录：/root/codex/google-translate（git 远程 git@github.com:revesis/translate.git，分支 main）

第一步：读 docs/botguard-notes.md 的 §9 之后全部章节（§9–§25，约 1200 行）。§1–§8 是早期
的信任假设排除记录，只有 §7（必须用完整 chromium，不能用 headless-shell）和 §4 的否定结果
（环境值、原型、布局、frame API、时钟、原生函数、Error.stack 都不影响信任）还需要记住。
已被撤回、不要重试的结论：
- 「惰性字段路径会读程序」（§14 撤回：解释器里只有一处 `NU[...]`，就是读取器）
- 「用抓到的密钥流离线解密」（§13/§17 双重否定：密钥流不是块下标的函数）
- 「F×2 位偏移框架」（§10 撤回）
- 「block-capture 模式下的读取日志可以当执行轨迹」（§25：日志被强制读取污染/拖动）

现在是可用的工具与产物（都在 /tmp，清理后可按笔记重建）：
- research/bgpatch.py：结构化插桩器，四套构建都适配（Fhxs / EON / pBm / 更新的）。角色
  由结构推导，不依赖标识符和参数位置：entry 检查 → 指针字段与 vm，密钥流守卫 `<x>&&(` →
  flag，循环种子 → 位宽，读取器调用按该构建声明的顺序重建。
  hunk：entry/ret（在 VM 实例上记录每次读取与返回值）、boot（__vmref/__JY/__vmeta）、
  blockcache（每块 8 字节快照，含 __lock 防重入）、sweep、writes（字段写入 + 读取计数）、
  killswitch、canary、kinds、post。
- research/dump_program.py：一次页面加载内取同一构建对的素材（interp_<hash>.js /
  blob_<hash>.txt 会自动落盘），支持 --log-only / --sweep / --twice / --ab / --fields
  / --same / --mutate / --writers / --early。--fields 失败会区分 stage=pristine-vm（页面
  自己的副本赢了）并自动 reload 换构建对重试。
- research/read_records.py：把 rd/rv 折成 token（含 0x80 转义），按写入的读取计数切出
  「这次写入消耗了哪些程序 word」，--table / --record N / --fid N。
- research/freq.txt：真实 f_req 形状的负载（约 2075 字符），决定程序走多远；不填则用 "hello"，
  只覆盖程序开头一小段。

已经确认的事实（都有实测输出）：
- 取值编码：8 位读 = 0..127；最高位为 1 表示转义，再读 2 位，值 = ((b&0x7f)<<2)|t。1042/1042
  全部符合，算术恒等式 512 组全对。所以 2 位读取永远不是 opcode，而是扩展值的低位。
- 另有「裸字节」读取器（R3/Ww/A9，按构建改名）：无转义，用于 7 位 varint。
- 读取是线性连续流（13646/13785 步长为 0），宽只有 8/2/32；程序按 token 流被消费，不是
  跳转式 PC。真实负载下块覆盖率 49.9 % / 80.8 %（两套构建）。
- 程序里不存明文 ASCII（80 % 覆盖的重建里最长可打印串 ≤9 字符）。
- 字段写入 = 固定骨架 + 每次签名的随机字段 + 时钟 + 内容字段（id 随构建变，§20/§23）。
- 字符串多数是「算出来的」：100+ 字符的 handler 源码只消耗 3–7 个 token，而 10 字符随机名
  消耗 77 个。写入的读取区间不等于一条记录（fid 在区间内的位置 2/1/3/4/6/0/5/7 都有）。

下一步（按优先级）：
1. 把读取计数同时记在读取器 entry 上（现在只有 ret），这样一次写入能钉到区间内的具体读取，
   而不是边界。然后重新统计「写入 ↔ token」的对应关系。
2. 按 wrapper 隐含的操作数边界切分 token 流（普通 8 位、转义 9 位、种子 32 位），得到带类型
   的流，先不依赖 dispatch 表。
3. 只有前两步仍不能还原记录结构时，再回到 §10 的 `cH` 式断点追踪（按「参数是否随命中变化」
   挑分发器，别按名字）。

判断标准与交付要求：
- 每个结论都要有可复现的实测输出；发现之前错了就直接撤回并在笔记里改正（前面已撤回四次）。
- 新发现追加到 docs/botguard-notes.md，章节号连续。
- 代码注释和 docstring 用英文，聊天回复用中文。
- 每完成一个可验证的结论就 commit + push 到 main，commit message 写清证据。
- 不要动已上线的 sidecar 部分（gt_server.py / bgr_sidecar.py / Dockerfile 等），反编译是
  独立研究线。
- 构建每次加载都会轮换，且同一个 hash 会配不同 blob：一次页面加载只做一次实验；两段 dump
  只有同一页面内才可比。
