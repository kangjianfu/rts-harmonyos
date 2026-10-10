// IceLiteClient.ets — ICE-lite 受控侧（UDP + STUN 配对），WHEP/RTS 拉流用
// 流程：bind UDP → 收到对端 Binding Request → 回 Response → 收到带 USE-CANDIDATE 的 Request
//       → 配对成功（onSelected），之后这条 UDP 通道交给 DTLS 层
import { socket } from '@kit.NetworkKit';
import { buildBindingRequest, parseStun, verifyIntegrity, STUN_BINDING_REQUEST, STUN_BINDING_RESPONSE } from './Stun';

export type IceLog = (msg: string) => void;

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    b[i] = Math.floor(Math.random() * 256);
  }
  return b;
}

export class IceLiteClient {
  onLog: IceLog = () => {};
  /** 配对成功：之后这条 UDP socket 进入 DTLS 阶段 */
  onSelected: () => void = () => {};
  /** 收到非 STUN 数据（DTLS/RTP 包）转给上层 */
  onData: (data: Uint8Array) => void = () => {};

  private udp: socket.UDPSocket = socket.constructUDPSocketInstance();
  private serverHost: string = '';
  private serverPort: number = 0;
  private remoteUfrag: string = '';   // 对端 ufrag（响应校验用：localUfrag:remoteUfrag）
  private localUfrag: string = '';
  private localPwd: string = '';
  private remotePwd: string = '';
  private tieBreaker: Uint8Array = randomBytes(8);
  private selected: boolean = false;

  getLocalUfrag(): string {
    return this.localUfrag;
  }

  getLocalPwd(): string {
    return this.localPwd;
  }

  /** 初始化本地凭证并绑定 UDP */
  async start(serverHost: string, serverPort: number, remoteUfrag: string, remotePwd: string): Promise<void> {
    this.serverHost = serverHost;
    this.serverPort = serverPort;
    this.remoteUfrag = remoteUfrag;
    this.remotePwd = remotePwd;
    this.localUfrag = randomBytes(4).reduce((s, b) => s + b.toString(16), '');
    this.localPwd = randomBytes(12).reduce((s, b) => s + b.toString(16), '');

    await this.udp.bind({ address: '0.0.0.0', port: 0 });
    this.udp.on('message', (data: socket.SocketMessageInfo) => {
      if (data.message) {
        this.onPacket(new Uint8Array(data.message));
      }
    });
    this.onLog(`UDP 已绑定，对端 ${serverHost}:${serverPort}`);
    // 受控侧也主动发 Binding Request 保活 NAT
    const req = await buildBindingRequest(`${remoteUfrag}:${this.localUfrag}`, remotePwd, this.tieBreaker);
    await this.sendRaw(req);
    this.onLog('已发 Binding Request（NAT 保活）');
  }

  private async onPacket(data: Uint8Array): Promise<void> {
    // STUN 包前两 bit 为 0 且带 magic cookie；RTP(0x80~)/DTLS(20-64) 直接上交
    if (data.length < 2 || (data[0] & 0xc0) !== 0) {
      this.onData(data);
      return;
    }
    const msg = parseStun(data);
    if (!msg) {
      this.onData(data);
      return;
    }
    if (msg.type === STUN_BINDING_REQUEST) {
      // 校验 USERNAME 与 MESSAGE-INTEGRITY
      const ok = await verifyIntegrity(data, msg, this.remotePwd);
      if (!ok) {
        this.onLog('STUN 请求校验失败（忽略）');
        return;
      }
      const hasUseCandidate = msg.attrs.has(0x0025);
      // 回 Binding Response（USERNAME 对调 + XOR-MAPPED-ADDRESS 可选，简化不带 mapped）
      const resp = await buildBindingRequest(this.remoteUfrag + ':' + this.localUfrag, this.remotePwd, this.tieBreaker);
      // 复用请求事务 id，改类型为 response：直接构造
      const dv = new DataView(resp.buffer);
      dv.setUint16(0, STUN_BINDING_RESPONSE, false);
      resp.set(msg.txId, 8);
      await this.sendRaw(resp);
      if (hasUseCandidate && !this.selected) {
        this.selected = true;
        this.onLog('ICE 配对成功（USE-CANDIDATE）');
        this.onSelected();
      }
    }
  }

  private sendRaw(data: Uint8Array): Promise<void> {
    return this.udp.send({
      data: data.buffer,
      address: { address: this.serverHost, port: this.serverPort }
    }).then(() => {});
  }

  /** DTLS 阶段后，上层用它发 DTLS/RTCP 包 */
  async send(data: Uint8Array): Promise<void> {
    await this.sendRaw(data);
  }

  async close(): Promise<void> {
    try {
      await this.udp.close();
    } catch (e) { /* 忽略 */ }
  }
}
