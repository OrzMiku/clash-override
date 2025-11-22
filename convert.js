// =================================================================
// = constants
// =================================================================

const DEBUG = false;

const FEATURE = {
  DNS: true,
  INCLUDE_ALL_PROXIES_IN_MAIN_GROUP: false,
};

const MAIN_GROUP_NAME = "节点选择";
const REGIONS = [
  { code: "HK", name: "香港", regex: /(香港|HK|Hong Kong|🇭🇰)/i },
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
];
const FILTER_REGEX =
  /^(?!.*(官网|套餐|流量|expiring|剩余|时间|重置|URL|到期|过期|机场|group|sub|订阅|查询|续费|观看|频道|客服|M3U|车费|车友|上车|通知|公告|严禁|未知|Channel)).*$/i;

// =================================================================
// = main
// =================================================================

function main(config) {
  const proxies = buildProxies(config);
  const filtered_proxies = filterProxies(proxies, FILTER_REGEX);
  const proxy_groups = buildProxyGroups(
    filtered_proxies,
    REGIONS,
    MAIN_GROUP_NAME,
    FEATURE.INCLUDE_ALL_PROXIES_IN_MAIN_GROUP
  );
  const rules = buildRules(MAIN_GROUP_NAME);

  const dns = FEATURE.DNS ? buildDns() : {};

  const result = {
    ...dns,
    proxies: filtered_proxies,
    ["proxy-groups"]: proxy_groups,
    ...rules,
  };

  if (DEBUG) console.log(result);
  return result;
}

// =================================================================
// = utils
// =================================================================

function buildDns() {
  return {
    dns: {
      enable: true,
      "respect-rules": true,
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
    },
  };
}

function filterProxies(proxies, regex) {
  return proxies.filter((proxy) => regex.test(proxy.name));
}

function buildProxies(config) {
  let proxies = config.proxies || [];

  // proxy providers
  if (!config["proxy-providers"]) return proxies;
  const proxyProviders = config["proxy-providers"];
  const fs = require("fs");
  const path = require("path");
  const yaml = require("yaml");
  Object.values(proxyProviders).forEach((provider) => {
    if (!provider.path) return;
    const filepath = path.resolve(__dirname, "../", provider.path);
    try {
      const content = fs.readFileSync(filepath, "utf-8");
      const data = yaml.parse(content);
      if (data.proxies) proxies = proxies.concat(data.proxies);
    } catch (e) {
      console.error(`Error reading ${filepath}:`, e);
    }
  });

  return proxies;
}

function buildProxyGroups(
  proxies,
  regions,
  main_group_name,
  include_all_proxies_in_main_group
) {
  // region groups
  const region_groups = regions.map((region) => {
    const region_proxies = filterProxies(proxies, region.regex);
    if (!region_proxies.length) return null;
    const base = {
      name: region.name,
      type: "url-test",
      icon: `https://cdn.jsdelivr.net/gh/Orz-3/mini@master/Color/${region.code}.png`,
      proxies: region_proxies.map((proxy) => proxy.name),
    };
    return base;
  });

  // Filter out null region groups
  const valid_region_groups = region_groups.filter((group) => group !== null);

  // main groups
  const main_group = {
    name: main_group_name,
    type: "select",
    proxies: [
      ...valid_region_groups.map((group) => group.name),
      "DIRECT",
      ...(include_all_proxies_in_main_group
        ? proxies.map((proxy) => proxy.name)
        : []),
    ],
  };

  return [main_group, ...valid_region_groups];
}

function buildRules(main_group_name) {
  return {
    "rule-providers": {
      reject: {
        type: "http",
        behavior: "domain",
        url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt",
        path: "./ruleset/reject.yaml",
      },
      proxy: {
        type: "http",
        behavior: "domain",
        url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt",
        path: "./ruleset/proxy.yaml",
      },
      direct: {
        type: "http",
        behavior: "domain",
        url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
        path: "./ruleset/direct.yaml",
      },
      private: {
        type: "http",
        behavior: "domain",
        url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt",
        path: "./ruleset/private.yaml",
      },
      cncidr: {
        type: "http",
        behavior: "ipcidr",
        url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt",
        path: "./ruleset/cncidr.yaml",
      },
      lancidr: {
        type: "http",
        behavior: "ipcidr",
        url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt",
        path: "./ruleset/lancidr.yaml",
      },
      applications: {
        type: "http",
        behavior: "classical",
        url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/applications.txt",
        path: "./ruleset/applications.yaml",
      },
      customProxy: {
        type: "http",
        behavior: "domain",
        url: "https://cdn.jsdelivr.net/gh/OrzMiku/clash-override@master/rules/custom-proxy.yaml",
        path: "./ruleset/custom-proxy.yaml",
      },
      customDirect: {
        type: "http",
        behavior: "domain",
        url: "https://cdn.jsdelivr.net/gh/OrzMiku/clash-override@master/rules/custom-direct.yaml",
        path: "./ruleset/custom-direct.yaml",
      },
    },
    rules: [
      `RULE-SET,customProxy,${main_group_name}`,
      `RULE-SET,customDirect,DIRECT`,
      "RULE-SET,applications,DIRECT",
      "DOMAIN,clash.razord.top,DIRECT",
      "DOMAIN,yacd.haishan.me,DIRECT",
      "RULE-SET,private,DIRECT",
      "RULE-SET,reject,REJECT",
      `RULE-SET,proxy,${main_group_name}`,
      "RULE-SET,direct,DIRECT",
      "RULE-SET,lancidr,DIRECT",
      "RULE-SET,cncidr,DIRECT",
      "GEOIP,LAN,DIRECT",
      "GEOIP,CN,DIRECT",
      `MATCH,${main_group_name}`,
    ],
  };
}
