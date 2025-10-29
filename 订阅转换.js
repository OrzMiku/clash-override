/*
支持的传入参数：
- ipv6: 启用 IPv6 支持（默认 false）
- full: 输出完整配置（适合纯内核启动，默认 false）
- keepalive: 启用 tcp-keep-alive（默认 false）
- threshold: 国家节点数量小于该值时不显示分组 (默认 0)
- regiongrouponly: 主代理组只包含地区分组，不包含所有节点 (默认 false)
- regiongrouptype: 地区分组类型，支持 select、url-test、load-balance、fallback (默认 select)
*/

// =================================================================
// = 配置
// =================================================================

const DEBUG = true;

/** 覆写脚本主配置对象 */
const CONFIG = {
  /** 节点过滤配置 */
  nodeFilter: {
    /** 排除包含机场、套餐等无关信息的节点 */
    excludeKeywords:
      /^(?!.*(官网|套餐|流量|expiring|剩余|时间|重置|URL|到期|过期|机场|group|sub|订阅|查询|续费|观看|频道|客服|M3U|车费|车友|上车|通知|公告|严禁|未知|Channel)).*$/i,
  },

  /** 地区节点分组配置：按地区对代理节点进行自动分类 */
  regions: [
    {
      code: "HK",
      name: "香港",
      /** 节点名称匹配正则 */
      regex: /(香港|HK|Hong Kong|🇭🇰)/i,
      type: "select",
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

  /** 主代理组配置 */
  proxyGroup: {
    mainGroupName: "节点选择",
    testUrl: "http://www.apple.com/library/test/success.html",
    testInterval: 300,
    loadBalanceStrategy: "consistent-hashing",
  },

  /** DNS 配置 */
  dns: {
    enable: true,
    "default-nameserver": ["tls://223.5.5.5", "tls://223.6.6.6"],
    nameserver: [
      "https://cloudflare-dns.com/dns-query",
      "https://dns.google/dns-query",
    ],
    "proxy-server-nameserver": [
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query",
    ],
    "direct-nameserver": [
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query",
    ],
    "respect-rules": true,
  },

  /** 配置选项 */
  profile: {
    "store-selected": true,
    "store-fake-ip": true,
  },

  /** 地理数据库配置 */
  geodata: {
    mode: true,
    autoUpdate: true,
    updateInterval: 24,
    urls: {
      geoip:
        "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
      geosite:
        "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
      mmdb: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb",
      asn: "https://github.com/xishang0128/geoip/releases/download/latest/GeoLite2-ASN.mmdb",
    },
  },

  /** TUN 配置 */
  tun: {
    enable: true,
    stack: "mixed",
    "dns-hijack": ["any:53", "tcp://any:53"],
    "auto-route": true,
    "auto-redirect": true,
    "auto-detect-interface": true,
    "route-exclude-address": ["172.26.0.0/16", "172.25.0.0/16"],
  },

  /** NTP 配置 */
  ntp: {
    enable: true,
    "write-to-system": true,
    server: "time.apple.com",
    port: 123,
    interval: 30,
  },

  /** 规则提供者配置：预定义的路由规则集 */
  ruleProviders: {
    /** 广告拦截域名列表 */
    reject: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt",
      path: "./ruleset/reject.yaml",
    },
    /** 代理服务域名列表 */
    proxy: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt",
      path: "./ruleset/proxy.yaml",
    },
    /** 直连域名列表 */
    direct: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
      path: "./ruleset/direct.yaml",
    },
    /** 私有网络域名列表 */
    private: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt",
      path: "./ruleset/private.yaml",
    },
    /** 中国大陆 IP 地址段 */
    cncidr: {
      type: "http",
      behavior: "ipcidr",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt",
      path: "./ruleset/cncidr.yaml",
    },
    /** 局域网 IP 地址段 */
    lancidr: {
      type: "http",
      behavior: "ipcidr",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt",
      path: "./ruleset/lancidr.yaml",
    },
    /** 应用程序列表 */
    applications: {
      type: "http",
      behavior: "classical",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/applications.txt",
      path: "./ruleset/applications.yaml",
    },
  },

  /** 流量嗅探器配置，用于识别流量类型 */
  sniffer: {
    sniff: {
      TLS: {
        ports: [443, 8443],
      },
      HTTP: {
        ports: [80, 8080, 8880],
      },
      QUIC: {
        ports: [443, 8443],
      },
    },
    "override-destination": false,
    enable: true,
    "force-dns-mapping": true,
    "skip-domain": ["Mijia Cloud", "dlg.io.mi.com", "+.push.apple.com"],
  },

  /** Geo 数据文件下载 URL 配置 */
  geoxURL: {
    geoip:
      "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
    geosite:
      "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",
    mmdb: "https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb",
    asn: "https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/GeoLite2-ASN.mmdb",
  },
};

/** 代理组配置模板：用于不同类型代理组的参数配置 */
const PROXY_GROUP_CONFIGS = {
  /** 负载均衡类型：多个节点轮询使用 */
  "load-balance": (url, interval, strategy) => ({
    url,
    interval,
    strategy,
  }),
  /** URL 测试类型：自动测试节点延迟并选择最优节点 */
  "url-test": (url, interval) => ({
    lazy: true,
    url,
    interval,
    tolerance: 50,
  }),
  /** 故障转移类型：主节点不可用时自动切换到备节点 */
  fallback: (url, interval) => ({ url, interval }),
};

// =================================================================
// = 主函数
// =================================================================

/**
 * 主函数：执行覆写逻辑
 * @param {Object} config - Clash 配置文件对象
 * @returns {Object} - 处理后的配置对象
 */
function main(config) {
  // 解析功能标志
  const rawArgs = typeof $arguments !== "undefined" ? $arguments : {};
  const {
    loadBalance,
    landing,
    ipv6Enabled,
    fullConfig,
    keepAliveEnabled,
    fakeIPEnabled,
    quicEnabled,
    countryThreshold,
    regionGroupOnly,
    regionGroupType,
  } = buildFeatureFlags(rawArgs);

  // 从配置提供者加载代理节点
  loadProxiesFromProviders(config);
  // 如果没有代理节点，直接返回原配置
  if (!config.proxies?.length) return config;

  // 过滤代理节点
  filterProxies(config);
  // 构建代理组
  buildProxyGroups(config, countryThreshold, regionGroupOnly, regionGroupType);
  // 应用覆写配置
  applyOverrides(config, {
    loadBalance,
    landing,
    ipv6Enabled,
    fullConfig,
    keepAliveEnabled,
    fakeIPEnabled,
    quicEnabled,
    countryThreshold,
  });

  // 调试模式下输出配置信息
  if (DEBUG === true) console.log(config);

  return config;
}

// =================================================================
// = 辅助函数
// =================================================================

/**
 * 将任意值转换为布尔值
 * @param {*} value - 要转换的值
 * @returns {boolean} 转换后的布尔值
 */
function parseBool(value) {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    return value.toLowerCase() === "true" || value === "1";
  }
  return false;
}

/**
 * 将任意值转换为数字
 * @param {*} value - 要转换的值
 * @param {number} defaultValue - 转换失败时的默认值
 * @returns {number} 转换后的数字
 */
function parseNumber(value, defaultValue = 0) {
  if (value === null || typeof value === "undefined") {
    return defaultValue;
  }
  const num = parseInt(value, 10);
  return isNaN(num) ? defaultValue : num;
}

/**
 * 解析脚本参数，转换为功能开关对象
 * @param {object} args - 传入的原始参数对象
 * @returns {object} 包含所有功能开关状态的对象
 */
function buildFeatureFlags(args) {
  const spec = {
    ipv6: "ipv6Enabled",
    full: "fullConfig",
    keepalive: "keepAliveEnabled",
    regiongrouponly: "regionGroupOnly",
  };

  const flags = Object.entries(spec).reduce((acc, [sourceKey, targetKey]) => {
    acc[targetKey] = parseBool(args[sourceKey]) || false;
    return acc;
  }, {});

  // 单独处理数字参数
  flags.countryThreshold = parseNumber(args.threshold, 0);

  // 单独处理字符串参数
  flags.regionGroupType = args.regiongrouptype || "select";

  return flags;
}

/**
 * 从本地文件加载代理提供者数据
 * @param {Object} config - 配置对象，包含 proxy-providers 属性
 * @returns {void} 直接修改 config 对象的 proxies 数组
 */
function loadProxiesFromProviders(config) {
  // 如果没有代理提供者，直接返回
  if (!config["proxy-providers"]) return;

  // 加载必要的 Node.js 模块
  const fs = require("fs");
  const path = require("path");
  const yaml = require("yaml");

  // 初始化 proxies 数组
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
 * @param {Object} config - 配置对象，包含 proxies 数组
 * @returns {void} 直接修改 config.proxies 数组
 */
function filterProxies(config) {
  // 使用正则表达式过滤代理节点
  config.proxies = config.proxies.filter((proxy) =>
    CONFIG.nodeFilter.excludeKeywords.test(proxy.name)
  );
}

/**
 * 构建代理组：根据地区自动分组
 * @param {Object} config - 配置对象，包含 proxies 数组
 * @param {number} countryThreshold - 国家节点数量小于该值时不显示分组
 * @param {boolean} regionGroupOnly - 主代理组只包含地区分组，不包含所有节点
 * @param {string} regionGroupType - 地区分组类型（select、url-test、load-balance、fallback）
 * @returns {void} 直接修改 config 对象的 proxy-groups 属性
 */
function buildProxyGroups(
  config,
  countryThreshold = 0,
  regionGroupOnly = false,
  regionGroupType = "select"
) {
  // 如果没有代理节点，直接返回
  if (!config.proxies?.length) return;

  // 验证 regionGroupType 是否有效
  const validTypes = ["select", "url-test", "load-balance", "fallback"];
  const groupType = validTypes.includes(regionGroupType) ? regionGroupType : "select";

  // 根据配置的地区创建代理组
  const regionGroups = CONFIG.regions
    .map((region) => {
      // 筛选出属于该地区的代理节点
      const proxies = config.proxies
        .filter((proxy) => region.regex.test(proxy.name))
        .map((p) => p.name);

      // 如果该地区没有匹配的节点，返回 null
      if (!proxies.length) return null;

      // 如果节点数量小于阈值，不显示该分组
      if (countryThreshold > 0 && proxies.length < countryThreshold)
        return null;

      // 使用参数指定的类型，如果没有指定则使用地区配置中的类型
      const finalType = groupType || region.type || "select";

      // 创建代理组基础配置
      const base = {
        name: region.name,
        type: finalType,
        icon: `https://cdn.jsdelivr.net/gh/Orz-3/mini@master/Color/${region.code}.png`,
        proxies,
      };
      // 获取该类型的配置模板
      const typeConfig = PROXY_GROUP_CONFIGS[finalType];

      // 合并基础配置和类型特定配置
      return typeConfig
        ? {
            ...base,
            ...typeConfig(
              CONFIG.proxyGroup.testUrl,
              CONFIG.proxyGroup.testInterval,
              CONFIG.proxyGroup.loadBalanceStrategy
            ),
          }
        : base;
    })
    .filter(Boolean);

  // 构建主代理组的 proxies 列表
  const mainGroupProxies = regionGroupOnly
    ? [...regionGroups.map((g) => g.name), "DIRECT"]
    : [
        ...regionGroups.map((g) => g.name),
        "DIRECT",
        ...config.proxies.map((p) => p.name),
      ];

  // 创建完整的代理组列表（主代理组 + 地区代理组）
  config["proxy-groups"] = [
    {
      // 主代理组：用于选择具体地区或节点
      name: CONFIG.proxyGroup.mainGroupName,
      type: "select",
      icon: "https://cdn.jsdelivr.net/gh/Orz-3/mini@master/Color/Global.png",
      proxies: mainGroupProxies,
    },
    ...regionGroups,
  ];
}

/**
 * 应用覆写配置：设置 DNS、TUN、NTP、规则等
 * @param {Object} config - 配置对象
 * @param {Object} flags - 功能标志对象
 */
function applyOverrides(config, flags) {
  const { ipv6Enabled, fullConfig, keepAliveEnabled } = flags;

  // 如果启用完整配置模式，设置所有端口和高级选项
  if (fullConfig) {
    Object.assign(config, {
      "mixed-port": 7890,
      "redir-port": 7892,
      "tproxy-port": 7893,
      "routing-mark": 7894,
      "allow-lan": true,
      ipv6: ipv6Enabled,
      mode: "rule",
      "unified-delay": true,
      "tcp-concurrent": true,
      "find-process-mode": "off",
      "log-level": "info",
      "geodata-loader": "standard",
      "external-controller": ":9999",
      "disable-keep-alive": !keepAliveEnabled,
      profile: {
        "store-selected": true,
      },
    });
  }

  // 覆写各项配置
  config.dns = CONFIG.dns;
  config.profile = CONFIG.profile;
  config["geodata-mode"] = CONFIG.geodata.mode;
  config["geo-auto-update"] = CONFIG.geodata.autoUpdate;
  config["geo-update-interval"] = CONFIG.geodata.updateInterval;
  config["geox-url"] = CONFIG.geoxURL;
  config.tun = CONFIG.tun;
  config.ntp = CONFIG.ntp;
  config["rule-providers"] = CONFIG.ruleProviders;
  config.sniffer = CONFIG.sniffer;

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
