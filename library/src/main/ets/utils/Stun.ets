// Stun.ets — 极简 STUN（RFC 5389）客户端能力，ICE-lite 受控侧用
// 支持：Binding Request/Response、USERNAME、MESSAGE-INTEGRITY（HMAC-SHA1 短期凭证）、
//       PRIORITY、ICE-CONTROLLED、USE-CANDIDATE、XOR-MAPPED-ADDRESS 解析
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { util } from '@kit.ArkTS';

export const STUN_BINDING_REQUEST = 0x0001;
export const STUN_BINDING_RESPONSE = 0x0101;
const MAGIC_COOKIE = 0x2112a442;

const ATTR_USERNAME = 0x0006;
const ATTR_MESSAGE_INTEGRITY = 0x0008;
const ATTR_PRIORITY = 0x0024;
const ATTR_USE_CANDIDATE = 0x0025;
const ATTR_ICE_CONTROLLED = 0x8029;
const ATTR_XOR_MAPPED = 0x0020;

export interface StunMessage {
  type: number;
  txId: Uint8Array;
  attrs: Map<number, Uint8Array>;
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    b[i] = Math.floor(Math.random() * 256);
  }
  return b;
}

/** 构造 Binding Request。username/icePwd 提供时带 MESSAGE-INTEGRITY */
export async function buildBindingRequest(username: string, icePwd: string, tieBreaker: Uint8Array): Promise<Uint8Array> {
  const txId = randomBytes(12);
  const attrs: Uint8Array[] = [];

  const enc = new util.TextEncoder();
  const u = enc.encodeInto(username);
  attrs.push(packAttr(ATTR_USERNAME, u));

  const prio = new Uint8Array(4);
  new DataView(prio.buffer).setUint32(0, 0x7e0000ff, false); // host candidate 常见优先级
  attrs.push(packAttr(ATTR_PRIORITY, prio));

  attrs.push(packAttr(ATTR_ICE_CONTROLLED, tieBreaker));

  let bodyLen = 0;
  for (const a of attrs) {
    bodyLen += a.length;
  }
  // MESSAGE-INTEGRITY 占位 24 字节参与长度计算
  const withMi = username.length > 0;
  const total = bodyLen + (withMi ? 24 : 0);
  const head = packHeader(STUN_BINDING_REQUEST, total, txId);
  let msg = concat([head].concat(attrs));

  if (withMi) {
    // HMAC-SHA1 覆盖「头部(length 含 MI) + 之前所有属性」
    const mac = cryptoFramework.createMac('SHA1');
    const key = cryptoFramework.createSymKeyGenerator('HMAC').convertKeySync({ data: enc.encodeInto(icePwd) });
    mac.initSync(key);
    mac.updateSync({ data: msg });
    const digest = mac.doFinalSync().data;
    msg = concat([msg, packAttr(ATTR_MESSAGE_INTEGRITY, digest)]);
  }
  return msg;
}

/** 解析 STUN 消息；非法返回 null */
export function parseStun(data: Uint8Array): StunMessage | null {
  if (data.length < 20) {
    return null;
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.length);
  const type = dv.getUint16(0, false);
  const len = dv.getUint16(2, false);
  if (dv.getUint32(4, false) !== MAGIC_COOKIE || data.length < 20 + len) {
    return null;
  }
  const attrs = new Map<number, Uint8Array>();
  let off = 20;
  const end = 20 + len;
  while (off + 4 <= end) {
    const at = dv.getUint16(off, false);
    const al = dv.getUint16(off + 2, false);
    if (off + 4 + al > data.length) {
      break;
    }
    attrs.set(at, data.subarray(off + 4, off + 4 + al));
    off += 4 + al + ((4 - (al % 4)) % 4); // 4 字节对齐
  }
  return { type: type, txId: data.subarray(8, 20), attrs: attrs };
}

/** 校验响应的 MESSAGE-INTEGRITY（短期凭证） */
export async function verifyIntegrity(data: Uint8Array, msg: StunMessage, icePwd: string): Promise<boolean> {
  const mi = msg.attrs.get(ATTR_MESSAGE_INTEGRITY);
  if (!mi) {
    return false;
  }
  // MI 属性头起始偏移 = 消息中 MI value 前 24 字节
  const miValueOff = findAttrValueOffset(data, ATTR_MESSAGE_INTEGRITY);
  if (miValueOff < 24) {
    return false;
  }
  // 校验范围：头部(length 只算到 MI 结束) + MI 之前的属性
  const dv = new DataView(data.buffer, data.byteOffset, data.length);
  const covered = data.slice(0, miValueOff - 4);
  const coveredDv = new DataView(covered.buffer, covered.byteOffset, covered.length);
  coveredDv.setUint16(2, (miValueOff - 20 + 24) - 4, false); // length = 到 MI 属性结束
  const mac = cryptoFramework.createMac('SHA1');
  const enc = new util.TextEncoder();
  const key = cryptoFramework.createSymKeyGenerator('HMAC').convertKeySync({ data: enc.encodeInto(icePwd) });
  mac.initSync(key);
  mac.updateSync({ data: covered });
  const digest = mac.doFinalSync().data;
  if (digest.length !== mi.length) {
    return false;
  }
  for (let i = 0; i < digest.length; i++) {
    if (digest[i] !== mi[i]) {
      return false;
    }
  }
  return true;
}

function findAttrValueOffset(data: Uint8Array, attrType: number): number {
  const dv = new DataView(data.buffer, data.byteOffset, data.length);
  const len = dv.getUint16(2, false);
  let off = 20;
  const end = 20 + len;
  while (off + 4 <= end) {
    const at = dv.getUint16(off, false);
    const al = dv.getUint16(off + 2, false);
    if (at === attrType) {
      return off + 4;
    }
    off += 4 + al + ((4 - (al % 4)) % 4);
  }
  return -1;
}

function packHeader(type: number, bodyLen: number, txId: Uint8Array): Uint8Array {
  const h = new Uint8Array(20);
  const dv = new DataView(h.buffer);
  dv.setUint16(0, type, false);
  dv.setUint16(2, bodyLen, false);
  dv.setUint32(4, MAGIC_COOKIE, false);
  h.set(txId, 8);
  return h;
}

function packAttr(type: number, value: Uint8Array): Uint8Array {
  const pad = (4 - (value.length % 4)) % 4;
  const out = new Uint8Array(4 + value.length + pad);
  const dv = new DataView(out.buffer);
  dv.setUint16(0, type, false);
  dv.setUint16(2, value.length, false);
  out.set(value, 4);
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) {
    total += p.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
