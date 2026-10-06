# Budget Reference Tables (预算参考表 · PWA)

年度固定支出估算表 + 保险保费明细表，纯前端单页应用，数据只存在**你自己的浏览器本地**（IndexedDB），可选 AES-GCM 加密，并已打包为可离线使用的 PWA（渐进式网页应用）。

## ✨ 功能

- 📊 年度固定支出估算表 + 分类汇总报表
- 🛡️ 保险保费明细表（按保单分组，支持多段年份区间、按年汇总）
- 📈 **收入预测（Income Forecast）**：可建立多个"假设情境"，每个情境分别录入"生息账户"（本金 + 年化利率）与"租金/固定月收入"两类收入来源，自动算出年度/月度总收入。全部手动录入，不依赖上面两张表的数据
- 🗺️ **多年度规划（Multi-Year Planner）**：可建立多个方案（Plan），分别设置账户（本金+年化回报率）、可选的分阶段分配规则（按年份区间设置盈余分配比例/亏空扣款优先级）、收入时间线与支出预算（均为按年份区间的多段录入），再运行任意年份区间的逐年预测（含图表），并可将某次预测"冻结"为基准（Baseline），之后逐年填入实际值对比误差
- 🔐 **可选加密**：开启后用口令派生 AES-GCM 密钥（PBKDF2 60 万次迭代；迭代次数随加密数据一起保存，早期版本加密的数据仍按原来的 25 万次正确解密，不受影响），口令本身从不落盘，仅存在于当前标签页内存中
- 🔒 **全屏锁屏**：加密开启后，打开页面 / 5 分钟无操作 / 点击"Lock Now" / 实际关闭标签页后重新打开，都会显示全屏锁屏，输入正确口令才能看到数据（在任何 JS 执行前就已通过内联脚本同步隐藏内容，无闪屏）。**注意**：单纯切到后台标签页或被其他 App 短暂遮挡**不会**立即锁屏——早期版本这样做过，但太容易误触锁屏、影响正常使用，所以改成了只在真正空闲超时 / 手动点锁 / 关闭页面时才锁
- 🏷️ 右下角有一个极小的版本号徽标（`APP_VERSION · APP_VERSION_DATE`），在锁屏界面（无需先解锁）也能看到，方便确认浏览器实际加载的是哪个版本
- 📴 **离线可用（PWA）**：Service Worker 预缓存整个应用外壳，断网也能正常打开、录入、查看数据
- 📲 **可安装到桌面/主屏幕**：通过 Web App Manifest 支持"添加到主屏幕"，独立窗口运行，带图标
- 📤 导入 / 导出 JSON（导出文件也可选加密）

## 📁 项目结构

```
.
├── index.html          # 应用主体（原 budget-reference.html）
├── manifest.json        # Web App Manifest
├── sw.js                 # Service Worker（离线缓存）
├── lib/                  # 本地托管的第三方库（chart.umd.min.js，用于多年度规划的图表，无需 CDN）
└── icons/                # 各尺寸图标（含 maskable 版本、favicon、apple-touch-icon）
```

## 🚀 部署到 GitHub Pages

1. 新建一个 GitHub 仓库，把本目录下的所有文件（`index.html`、`manifest.json`、`sw.js`、`lib/`、`icons/`）上传到仓库根目录（或某个子目录，只要相对路径关系保持不变）。
2. 仓库 **Settings → Pages**，Source 选择对应分支（如 `main`）和目录（`/root` 或 `/docs`），保存。
3. 等待几分钟，访问 GitHub 给出的 `https://<你的用户名>.github.io/<仓库名>/` 地址即可。
4. 用手机浏览器打开该地址后，选择"添加到主屏幕"（iOS Safari）或浏览器会自动提示"安装应用"（Android Chrome），即可像原生 App 一样使用，并支持离线打开。

> ⚠️ Service Worker 要求 **HTTPS**（或 `localhost`）才能注册，GitHub Pages 默认就是 HTTPS，无需额外配置。用 `file://` 直接双击打开 `index.html` 时，Service Worker 会静默跳过注册（其余功能不受影响）。

### ✅ 每次部署前的检查清单

有两个版本号，分别在两个文件里，**不会自动同步**，部署前手动检查一遍：

1. `index.html` 顶部 `<script>` 里的 `APP_VERSION` / `APP_VERSION_DATE`（纯展示用，显示在右下角小徽标里，包括锁屏界面）
2. `sw.js` 顶部的 `VERSION`（控制 Service Worker 缓存刷新——不改这个的话，用户浏览器可能继续用旧的缓存文件，看不到你的更新）

两个文件里各自都留了一条注释，指向对方作为提醒。改了代码要发布时，两处都记得bump一下。

部署后如果发现看到的版本号和你期望的对不上，通常不是没部署成功，而是浏览器还在用旧缓存——按 `Ctrl/Cmd+Shift+R` 强制刷新，或者在浏览器 DevTools 里手动清掉这个站点的 Service Worker / 缓存，再重新打开就好了（版本号只反映"这次构建打包了什么代码"，不反映"浏览器当前实际在跑什么"）。

## 🖥️ 本地预览

因为用到了 Service Worker 和 Manifest，建议用一个本地静态服务器预览（而不是直接双击打开文件），例如：

```bash
# 任选其一
npx serve .
python3 -m http.server 8080
```

然后浏览器打开 `http://localhost:8080/`（或对应端口）。

## 🔐 关于加密与数据安全

- 数据默认**不加密**，明文存于本机 IndexedDB。
- 点击右上角"Encryption: Off"可开启加密：设置口令后，所有敏感字段会用该口令派生的 AES-GCM 密钥加密后再写入 IndexedDB；`id` 等结构性字段保持明文以便索引查询。
- 口令**不会被存储**在任何地方（不进 localStorage、不进 IndexedDB、不上传），只在解锁后存在于当前标签页的内存变量里。**忘记口令 = 数据永久无法恢复**，请务必牢记或额外备份口令。
- 页面自带的 Content-Security-Policy（`connect-src 'none'`）从代码层面阻止了任何 `fetch`/`XHR`/`WebSocket` 请求发往任意域名 —— 也就是说，即便页面存在某种注入漏洞，解密后的数据或密钥本身也无法通过网络被带出这个页面。
- 该应用**没有后端、没有账号体系、不会主动联网上传任何数据**；唯一的网络请求是首次加载时从 jsDelivr / cdnjs 拉取 Dexie.js 和 Font Awesome 这两个公开的前端库文件（有 Subresource Integrity 校验），之后由 Service Worker 缓存供离线使用。

## 🛠️ 技术栈

- 原生 HTML/CSS/JS（无构建步骤）
- [Dexie.js](https://dexie.org/)（IndexedDB 封装）
- Web Crypto API（AES-GCM + PBKDF2）
- Font Awesome（图标字体）
- Service Worker + Web App Manifest（PWA）
