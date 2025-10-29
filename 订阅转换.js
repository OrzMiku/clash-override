// 调试模式开关，设置为 true 时会在控制台输出配置信息
const DEBUG = true;

// 覆写脚本主配置对象
const CONFIG = {
  // 节点过滤配置：排除包含特定关键词的代理节点
  nodeFilter: {
    // 排除关键词的正则表达式
    // 该正则会过滤掉包含以下内容的节点名称：
    // 官网|套餐|流量| expiring|剩余|时间|重置|URL|到期|过期|机场|group|sub|订阅|
    // 查询|续费|观看|频道|客服|M3U|车费|车友|上车|通知|公告|严禁
    excludeKeywords:
      /^(?!.*(官网|套餐|流量| expiring|剩余|时间|重置|URL|到期|过期|机场|group|sub|订阅|查询|续费|观看|频道|官网|客服|M3U|车费|车友|上车|通知|公告|严禁)).*$/i,
  },

  // 地区节点分组配置：按地区对代理节点进行自动分类
  regions: [
    {
      code: "HK", // 地区代码
      name: "香港", // 地区中文名称
      // 节点名称匹配正则：包含以下任一关键词的节点会被归类到此组
      regex: /(香港|HK|Hong Kong|🇭🇰)/i,
      type: "select", // 代理组类型：select（手动选择）
    },
    { code: "TW", name: "台湾", regex: /(台湾|台灣|TW|Taiwan|🇹🇼)/i },
    { code: "SG", name: "新加坡", regex: /(新加坡|狮城|SG|Singapore|🇸🇬)/i },
    { code: "JP", name: "日本", regex: /(日本|JP|Japan|东京|🇯🇵)/i },
    {
      code: "US",
      name: "美国",
      regex: /(美国|美國|US|USA|United States|America|🇺🇸)/i,
    },
    { code: "DE", name: "德国", regex: /(德国|DE|Germany|🇩🇪)/i },
    { code: "KR", name: "韩国", regex: /(韩国|韓國|KR|Korea|South Korea|🇰🇷)/i },
    { code: "UK", name: "英国", regex: /(英国|UK|United Kingdom|🇬🇧)/i },
    { code: "CA", name: "加拿大", regex: /(加拿大|CA|Canada|🇨🇦)/i },
    { code: "AU", name: "澳大利亚", regex: /(澳大利亚|AU|Australia|🇦🇺)/i },
    { code: "FR", name: "法国", regex: /(法国|FR|France|🇫🇷)/i },
    { code: "NL", name: "荷兰", regex: /(荷兰|NL|Netherlands|🇳🇱)/i },
  ],

  // 主代理组配置
  proxyGroup: {
    mainGroupName: "节点选择", // 主代理组名称
    testUrl: "http://www.apple.com/library/test/success.html", // 节点连通性测试地址
    testInterval: 300, // 测试间隔（秒）
    loadBalanceStrategy: "consistent-hashing", // 负载均衡策略：一致性哈希
  },

  // DNS 配置：用于域名解析
  dns: {
    enable: true, // 启用自定义 DNS
    // 默认 DNS 服务器（用于解析系统域名）
    "default-nameserver": ["tls://223.5.5.5", "tls://223.6.6.6"],
    // 代理模式下使用的 DNS 服务器列表
    nameserver: [
      "https://cloudflare-dns.com/dns-query",
      "https://dns.google/dns-query",
    ],
    // 代理服务器的 DNS 配置
    "proxy-server-nameserver": [
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query",
    ],
    // 直连模式的 DNS 配置
    "direct-nameserver": [
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query",
    ],
    "respect-rules": true, // 是否根据规则使用对应的 DNS
  },

  // 配置选项：是否保存用户选择
  profile: {
    "store-selected": true, // 保存选中的代理节点
    "store-fake-ip": true, // 保存 FakeIP 设置
  },

  // 地理数据库配置：用于路由规则
  geodata: {
    mode: true, // 启用地理数据模式
    autoUpdate: true, // 自动更新地理数据库
    updateInterval: 24, // 更新间隔（小时）
    urls: {
      // GeoIP 数据库：用于 IP 地址地理位置查询
      geoip:
        "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
      // GeoSite 数据库：用于网站域名分类
      geosite:
        "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
      // 国家/地区数据库：用于国家代码查询
      mmdb: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb",
      // ASN 数据库：用于自治系统号查询
      asn: "https://github.com/xishang0128/geoip/releases/download/latest/GeoLite2-ASN.mmdb",
    },
  },

  // TUN 配置：TUN 模式网络设置
  tun: {
    enable: true, // 启用 TUN 模式
    stack: "mixed", // 网络栈：mixed（混合模式）
    // DNS 劫持：将所有 DNS 查询重定向到本地
    "dns-hijack": ["any:53", "tcp://any:53"],
    "auto-route": true, // 自动设置系统路由
    "auto-redirect": true, // 自动重定向流量
    "auto-detect-interface": true, // 自动检测网络接口
    // 排除地址：这些地址不通过 TUN 路由
    "route-exclude-address": ["172.26.0.0/16", "172.25.0.0/16"],
  },

  // NTP 配置：网络时间同步
  ntp: {
    enable: true, // 启用 NTP
    "write-to-system": true, // 将时间写入系统时钟
    server: "time.apple.com", // NTP 服务器
    port: 123, // NTP 端口
    interval: 30, // 同步间隔（秒）
  },

  // 规则提供者配置：预定义的路由规则集
  ruleProviders: {
    // 广告拦截域名列表
    reject: {
      type: "http", // 提供者类型
      behavior: "domain", // 规则行为：域名匹配
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt",
      path: "./ruleset/reject.yaml",
    },
    // 代理服务域名列表
    proxy: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt",
      path: "./ruleset/proxy.yaml",
    },
    // 直连域名列表
    direct: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
      path: "./ruleset/direct.yaml",
    },
    // 私有网络域名列表
    private: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt",
      path: "./ruleset/private.yaml",
    },
    // 中国大陆 IP 地址段
    cncidr: {
      type: "http",
      behavior: "ipcidr", // IP 段匹配
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt",
      path: "./ruleset/cncidr.yaml",
    },
    // 局域网 IP 地址段
    lancidr: {
      type: "http",
      behavior: "ipcidr",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt",
      path: "./ruleset/lancidr.yaml",
    },
    // 应用程序列表
    applications: {
      type: "http",
      behavior: "classical", // 经典模式（按应用匹配）
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/applications.txt",
      path: "./ruleset/applications.yaml",
    },
  },
};

// 代理组配置模板：用于不同类型代理组的参数配置
const PROXY_GROUP_CONFIGS = {
  // 负载均衡类型：多个节点轮询使用
  "load-balance": (url, interval, strategy) => ({
    url, // 测试 URL
    interval, // 切换间隔
    strategy, // 负载均衡策略（如一致性哈希）
  }),
  // URL 测试类型：自动测试节点延迟并选择最优节点
  "url-test": (url, interval) => ({
    lazy: true, // 延迟加载：只在需要时测试节点
    url, // 测试地址
    interval, // 测试间隔
    tolerance: 50, // 延迟容忍度（毫秒）
  }),
  // 故障转移类型：主节点不可用时自动切换到备节点
  fallback: (url, interval) => ({ url, interval }),
};

/**
 * 主函数：执行覆写逻辑
 * @param {Object} config - Clash 配置文件对象
 * @returns {Object} - 处理后的配置对象
 */
function main(config) {
  // 从配置提供者加载代理节点
  loadProxiesFromProviders(config);
  // 如果没有代理节点，直接返回原配置
  if (!config.proxies?.length) return config;

  // 过滤代理节点
  filterProxies(config);
  // 构建代理组
  buildProxyGroups(config);
  // 应用覆写配置
  applyOverrides(config);

  // 调试模式下输出完整配置信息到控制台
  if (DEBUG === true) console.log(config);

  return config;
}

/**
 * 从本地文件加载代理提供者数据
 * @param {Object} config - 配置对象
 */
function loadProxiesFromProviders(config) {
  // 如果没有代理提供者，直接返回
  if (!config["proxy-providers"]) return;

  // 加载必要的 Node.js 模块
  const fs = require("fs");
  const path = require("path");
  const yaml = require("yaml");

  // 初始化 proxies 数组（如果不存在）
  config.proxies = config.proxies || [];

  // 遍历所有代理提供者
  Object.values(config["proxy-providers"]).forEach((provider) => {
    // 如果提供者没有本地路径，跳过
    if (!provider.path) return;

    // 解析文件的绝对路径
    const filePath = path.resolve(__dirname, "..", provider.path);
    try {
      // 读取并解析 YAML 文件
      const content = fs.readFileSync(filePath, "utf8");
      const data = yaml.parse(content);
      // 将代理节点添加到配置中
      if (data.proxies) config.proxies.push(...data.proxies);
    } catch (e) {
      // 静默处理错误（文件不存在或解析失败）
    }
  });
}

/**
 * 过滤代理节点：排除不符合条件的节点
 * @param {Object} config - 配置对象
 */
function filterProxies(config) {
  // 使用正则表达式过滤代理节点
  // 只保留不包含 excludeKeywords 中指定关键词的节点
  config.proxies = config.proxies.filter((proxy) =>
    CONFIG.nodeFilter.excludeKeywords.test(proxy.name)
  );
}

/**
 * 构建代理组：根据地区自动分组
 * @param {Object} config - 配置对象
 */
function buildProxyGroups(config) {
  // 如果没有代理节点，直接返回
  if (!config.proxies?.length) return;

  // 根据配置的地区创建代理组
  const regionGroups = CONFIG.regions
    .map((region) => {
      // 筛选出属于该地区的代理节点
      const proxies = config.proxies
        .filter((proxy) => region.regex.test(proxy.name)) // 节点名称匹配正则
        .map((p) => p.name); // 只保留节点名称

      // 如果该地区没有匹配的节点，返回 null
      if (!proxies.length) return null;

      // 创建代理组基础配置
      const base = {
        name: region.name, // 代理组名称
        type: region.type || "select", // 代理组类型（默认 select）
        icon: `https://cdn.jsdelivr.net/gh/Orz-3/mini@master/Color/${region.code}.png`, // 代理组图标（根据地区代码）
        proxies, // 包含的节点列表
      };
      // 获取该类型的配置模板
      const typeConfig = PROXY_GROUP_CONFIGS[region.type];

      // 合并基础配置和类型特定配置
      return typeConfig
        ? {
            ...base,
            ...typeConfig(
              CONFIG.proxyGroup.testUrl, // 测试 URL
              CONFIG.proxyGroup.testInterval, // 测试间隔
              CONFIG.proxyGroup.loadBalanceStrategy // 负载均衡策略
            ),
          }
        : base;
    })
    .filter(Boolean); // 移除 null 值

  // 创建完整的代理组列表
  config["proxy-groups"] = [
    {
      // 主代理组：用于选择具体地区或节点
      name: CONFIG.proxyGroup.mainGroupName,
      type: "select", // 手动选择模式
      icon: "https://cdn.jsdelivr.net/gh/Orz-3/mini@master/Color/Global.png", // 代理组图标
      proxies: [
        ...regionGroups.map((g) => g.name), // 所有地区组
        "DIRECT", // 直连选项
        ...config.proxies.map((p) => p.name), // 所有单独节点
      ],
    },
    ...regionGroups, // 添加所有地区代理组
  ];
}

/**
 * 应用覆写配置：设置 DNS、TUN、NTP、规则等
 * @param {Object} config - 配置对象
 */
function applyOverrides(config) {
  // 覆写 DNS 配置
  config.dns = CONFIG.dns;
  // 覆写配置选项
  config.profile = CONFIG.profile;
  // 覆写地理数据模式配置
  config["geodata-mode"] = CONFIG.geodata.mode;
  config["geo-auto-update"] = CONFIG.geodata.autoUpdate;
  config["geo-update-interval"] = CONFIG.geodata.updateInterval;
  config["geox-url"] = CONFIG.geodata.urls;
  // 覆写 TUN 配置
  config.tun = CONFIG.tun;
  // 覆写 NTP 配置
  config.ntp = CONFIG.ntp;
  // 覆写规则提供者
  config["rule-providers"] = CONFIG.ruleProviders;
  // 设置路由规则（按优先级排序）
  config.rules = [
    // 应用程序走直连
    "RULE-SET,applications,DIRECT",
    // Clash 控制面板走直连
    "DOMAIN,clash.razord.top,DIRECT",
    "DOMAIN,yacd.haishan.me,DIRECT",
    // 私有网络域名走直连
    "RULE-SET,private,DIRECT",
    // 广告域名拒绝
    "RULE-SET,reject,REJECT",
    // 代理服务域名走代理
    `RULE-SET,proxy,${CONFIG.proxyGroup.mainGroupName}`,
    // 其他直连域名走直连
    "RULE-SET,direct,DIRECT",
    // 局域网 IP 走直连
    "RULE-SET,lancidr,DIRECT",
    // 中国大陆 IP 走直连
    "RULE-SET,cncidr,DIRECT",
    // 局域网流量走直连
    "GEOIP,LAN,DIRECT",
    // 中国大陆流量走直连
    "GEOIP,CN,DIRECT",
    // 其他所有流量走代理
    `MATCH,${CONFIG.proxyGroup.mainGroupName}`,
  ];
}
