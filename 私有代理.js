/** 调试模式开关，设置为 true 时会在控制台输出配置信息 */
const DEBUG = true;

/** 覆写脚本配置对象 */
const CONFIG = {
  /** 私有网络代理配置，用于处理内网流量 */
  privateTrust: {
    /** 私有代理组名称，确保与现有代理组名称不重复 */
    groupName: "aTrust",
    /**
     * 保活测试地址，填写仅在内网可访问的URL地址（如内网服务）
     * 例如：http://192.168.1.1:8080
     */
    testUrl: "",
    /**
     * 节点连通性测试间隔时间
     * 如果 testUrl 为空：使用 select 类型（手动选择代理）
     * 如果填写了 testUrl：使用 url-test 类型（自动测试并选择最优节点）
     */
    testInterval: 60,
    /** 需要通过代理访问的内网网段列表 */
    cidrs: ["172.25.0.0/16"],
  },

  /** 本地代理配置 */
  localProxy: {
    name: "socks5",
    type: "socks5",
    server: "127.0.0.1",
    port: 1080,
  },
};

/**
 * 主函数：执行覆写逻辑
 * @param {Object} config - Clash 配置文件对象
 * @returns {Object} - 处理后的配置对象
 */
function main(config) {
  // 添加本地代理配置、私有信任组和访问规则
  addLocalProxy(config);
  addPrivateTrustGroup(config);
  addPrivateRules(config);

  // 调试模式下输出配置信息
  if (DEBUG === true) console.log(config);

  return config;
}

/**
 * 添加本地代理到配置中
 * @param {Object} config - 配置对象
 */
function addLocalProxy(config) {
  // 初始化 proxies 数组
  config.proxies = config.proxies || [];
  // 添加本地 SOCKS5 代理配置
  config.proxies.push(CONFIG.localProxy);
}

/**
 * 添加私有网络代理组
 * 根据 testUrl 配置选择自动测试或手动选择模式
 * @param {Object} config - 配置对象
 */
function addPrivateTrustGroup(config) {
  // 初始化 proxy-groups 数组
  config["proxy-groups"] = config["proxy-groups"] || [];

  // 创建私有网络代理组配置
  const group = {
    name: CONFIG.privateTrust.groupName,
    // 根据 testUrl 决定代理组类型
    // url-test：自动测试并选择最优节点
    // select：手动选择代理
    type: CONFIG.privateTrust.testUrl ? "url-test" : "select",
    proxies: [CONFIG.localProxy.name],
  };

  // 如果配置了 testUrl，添加自动测试参数
  if (CONFIG.privateTrust.testUrl) {
    group.url = CONFIG.privateTrust.testUrl;
    group.interval = CONFIG.privateTrust.testInterval;
  }

  // 添加代理组到配置
  config["proxy-groups"].push(group);
}

/**
 * 添加私有网络访问规则
 * 将指定内网网段流量路由到私有代理组
 * @param {Object} config - 配置对象
 */
function addPrivateRules(config) {
  // 初始化 rules 数组
  config.rules = config.rules || [];

  // 根据配置的 CIDR 网段生成规则
  const privateRules = CONFIG.privateTrust.cidrs.map(
    (cidr) => `IP-CIDR,${cidr},${CONFIG.privateTrust.groupName}`
  );

  // 添加私有网络规则（优先级最高）
  config.rules.unshift(...privateRules);
}
