// WhepSignaling.ets — WHEP 拉流信令（HTTP POST SDP offer → SDP answer）
// 兼容 SRS（/rtc/v1/whep/?app=..&stream=..）；阿里云 RTS 端点按其控制台文档替换 url 即可
import { http } from '@kit.NetworkKit';
import { util } from '@kit.ArkTS';

/** POST SDP offer，返回 SDP answer */
export async function whepPlay(whepUrl: string, offerSdp: string): Promise<string> {
  const req = http.createHttp();
  try {
    const resp = await req.request(whepUrl, {
      method: http.RequestMethod.POST,
      header: { 'Content-Type': 'application/sdp' },
      extraData: offerSdp,
      connectTimeout: 10000,
      readTimeout: 10000
    });
    if (resp.responseCode !== 200 && resp.responseCode !== 201) {
      throw new Error(`信令失败 HTTP ${resp.responseCode}`);
    }
    const answer = typeof resp.result === 'string'
      ? resp.result
      : new util.TextDecoder('utf-8').decodeToString(new Uint8Array(resp.result as ArrayBuffer));
    return answer;
  } finally {
    req.destroy();
  }
}
