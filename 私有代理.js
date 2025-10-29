// 调试模式开关，设置为 true 时会在控制台输出配置信息
const DEBUG = true;

// 覆写脚本配置对象
const CONFIG = {
  // 私有网络代理配置，用于处理内网流量
  privateTrust: {
    // 私有代理组名称，请确保与现有代理组名称不重复
    groupName: "aTrust",
    // 保活测试地址，需要填写一个仅在内网可访问的URL地址（如内网服务）
    // 例如：http://192.168.1.1:8080
    testUrl: "",
    // 如果 testUrl 为空，则使用 select 类型（手动选择代理）
    // 如果填写了 testUrl，则使用 url-test 类型（自动测试并选择最优节点）
    testInterval: 60, // 节点连通性测试间隔时间，单位：秒
    // 需要通过代理访问的内网网段列表
    cidrs: ["172.25.0.0/16"],
  },

  // 本地代理配置，需要根据实际情况修改
  localProxy: {
    name: "socks5", // 代理名称
    type: "socks5", // 代理类型（SOCKS5）
    server: "127.0.0.1", // 代理服务器地址
    port: 1080, // 代理服务器端口
  },
};

/**
 * 主函数：执行覆写逻辑
 * @param {Object} config - Clash 配置文件对象
 * @returns {Object} - 处理后的配置对象
 */
function main(config) {
  // 添加本地代理配置
  addLocalProxy(config);
  // 添加私有信任组配置
  addPrivateTrustGroup(config);
  // 添加私有网络规则
  addPrivateRules(config);

  // 调试模式下输出完整配置信息到控制台
  if (DEBUG === true) console.log(config);

  return config;
}

/**
 * 添加本地代理到配置中
 * @param {Object} config - 配置对象
 */
function addLocalProxy(config) {
  // 初始化 proxies 数组（如果不存在）
  config.proxies = config.proxies || [];
  // 将本地代理配置添加到 proxies 列表中
  config.proxies.push(CONFIG.localProxy);
}

/**
 * 添加私有网络代理组
 * @param {Object} config - 配置对象
 */
function addPrivateTrustGroup(config) {
  // 初始化 proxy-groups 数组（如果不存在）
  config["proxy-groups"] = config["proxy-groups"] || [];

  // 创建代理组配置
  const group = {
    name: CONFIG.privateTrust.groupName, // 代理组名称
    // 根据是否配置 testUrl 决定代理组类型
    // 有 testUrl：使用 url-test 类型（自动测试并选择最优节点）
    // 无 testUrl：使用 select 类型（手动选择代理）
    type: CONFIG.privateTrust.testUrl ? "url-test" : "select",
    proxies: [CONFIG.localProxy.name], // 包含的代理列表
  };

  // 如果配置了 testUrl，添加连通性测试参数
  if (CONFIG.privateTrust.testUrl) {
    group.url = CONFIG.privateTrust.testUrl; // 测试 URL
    group.interval = CONFIG.privateTrust.testInterval; // 测试间隔
  }

  // 将代理组添加到配置中
  config["proxy-groups"].push(group);
}

/**
 * 添加私有网络访问规则
 * @param {Object} config - 配置对象
 */
function addPrivateRules(config) {
  // 初始化 rules 数组（如果不存在）
  config.rules = config.rules || [];

  // 根据配置的 CIDR 网段生成规则
  // 每个网段添加一条规则：将该网段流量路由到私有代理组
  const privateRules = CONFIG.privateTrust.cidrs.map(
    (cidr) => `IP-CIDR,${cidr},${CONFIG.privateTrust.groupName}`,
  );

  // 将私有网络规则添加到规则列表的最前面（优先级更高）
  config.rules.unshift(...privateRules);
}
