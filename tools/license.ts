// Копия ~/georomb/shared/license.ts — формат должен совпадать с приложением, правьте оба файла вместе.
// Общий формат лицензий GeoRomb — один и тот же для приложения (проверка) и бэкенда (подпись).
// Менять строки форматов нельзя: ими подписаны уже выданные коды и опубликованный revoked.json.
//   код устройства:  IWD1.<base64url("ID|срок")>.<base64url(подпись)>
//   список:          подпись над "IWDLIST1|ts|ID1,ID2|ID:срок,ID:срок"
// Подпись — ECDSA P-256 / SHA-256 (WebCrypto, формат r||s). Срок — YYYYMMDD или "0" (навсегда).

export const CODE_PREFIX = 'IWD1';
export const LIST_PREFIX = 'IWDLIST1';
export const LIST_VERSION = 2;

/** Открытый ключ, вшитый в приложение. Закрытая пара есть только у разработчика (keys/private.jwk.json). */
export const PUBLIC_KEY: JsonWebKey = {
  kty: 'EC', crv: 'P-256',
  x: 'PWQ948Xg_lw6hkf3vC-Cmmel8bNj6e_qpeEQomio1x8',
  y: 'aMpLfFJK3H-ZwnSB4qqmoA1nRTFRsLdnimwPmEnBUiM',
  ext: true
};

/** Адрес подписанного списка на GitHub Pages (репозиторий bakhtiyararzimetov/GeoRomb; до переименования аккаунта — bakhtiyar121). */
export const REVOKE_URL = 'https://bakhtiyararzimetov.github.io/GeoRomb/revoked.json';

/** ID устройства: 10 символов из алфавита без похожих букв/цифр. */
export const ID_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
export const ID_RE = /^[A-Z2-9]{10}$/;

export interface ListLicense { id: string; exp: string; }
export interface RevokedFile { v: number; ts: number; ids: string[]; lic: ListLicense[]; sig: string; }
export interface RevokedList { ts: number; ids: string[]; lic: ListLicense[]; }

export type VerifyFail = 'format' | 'sig' | 'device' | 'expired' | 'nocrypto';
export type VerifyResult = { ok: true; exp: string } | { ok: false; why: VerifyFail; exp?: string };

const ALG_KEY = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ALG_SIG = { name: 'ECDSA', hash: 'SHA-256' } as const;

export function b64uToBytes(s: string): Uint8Array<ArrayBuffer> {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while(s.length % 4) s += '=';
  const b = atob(s), a = new Uint8Array(b.length);
  for(let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
  return a;
}
export function bytesToB64u(a: Uint8Array): string {
  let s = '';
  a.forEach(x => { s += String.fromCharCode(x); });
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Дата как число YYYYMMDD (по местному времени — как в приложении). */
export function dateNum(d: Date = new Date()): number {
  return d.getFullYear() * 10000 + (d.getMonth() + 1) * 100 + d.getDate();
}
export function normalizeId(v: string): string { return String(v).toUpperCase().replace(/[^A-Z2-9]/g, ''); }
export function formatId(id: string): string { return id.slice(0, 5) + '-' + id.slice(5); }

export function codePayload(id: string, exp: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(id + '|' + exp);
}
export function listPayload(ts: number, ids: string[], lic: ListLicense[]): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(LIST_PREFIX + '|' + ts + '|' + ids.join(',') + '|' + lic.map(x => x.id + ':' + x.exp).join(','));
}

function hasCrypto(): boolean { return typeof crypto !== 'undefined' && !!crypto.subtle; }

async function verifyBytes(pub: JsonWebKey, sig: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>): Promise<boolean> {
  const key = await crypto.subtle.importKey('jwk', pub, ALG_KEY, false, ['verify']);
  return crypto.subtle.verify(ALG_SIG, key, sig, data);
}

/** Проверка кода активации для данного устройства. */
export async function verifyCode(code: string, deviceId: string, pub: JsonWebKey = PUBLIC_KEY, today: number = dateNum()): Promise<VerifyResult> {
  if(!hasCrypto()) return { ok: false, why: 'nocrypto' };
  const parts = String(code || '').replace(/\s+/g, '').split('.');
  if(parts.length !== 3 || parts[0] !== CODE_PREFIX) return { ok: false, why: 'format' };
  let payload: Uint8Array<ArrayBuffer>, sig: Uint8Array<ArrayBuffer>;
  try{ payload = b64uToBytes(parts[1]); sig = b64uToBytes(parts[2]); }catch{ return { ok: false, why: 'format' }; }
  let good = false;
  try{ good = await verifyBytes(pub, sig, payload); }catch{ return { ok: false, why: 'nocrypto' }; }
  if(!good) return { ok: false, why: 'sig' };
  const [id, exp] = new TextDecoder().decode(payload).split('|');
  if(id !== deviceId) return { ok: false, why: 'device' };
  if(exp !== '0' && today > Number(exp)) return { ok: false, why: 'expired', exp };
  return { ok: true, exp };
}

/** Проверка подписанного revoked.json; null — файл чужой, повреждён или подпись неверна. */
export async function verifyRevokedFile(d: unknown, pub: JsonWebKey = PUBLIC_KEY): Promise<RevokedList | null> {
  try{
    const f = d as Partial<RevokedFile> | null;
    if(!f || f.v !== LIST_VERSION || !Array.isArray(f.ids) || !Array.isArray(f.lic) || typeof f.sig !== 'string') return null;
    const ts = Number(f.ts);
    if(!isFinite(ts)) return null;
    const ids = f.ids.map(String);
    const lic = f.lic.map(x => ({ id: String(x.id), exp: String(x.exp) }));
    const ok = await verifyBytes(pub, b64uToBytes(f.sig), listPayload(ts, ids, lic));
    return ok ? { ts, ids, lic } : null;
  }catch{
    return null;
  }
}

// ---- подпись (только бэкенд: нужен закрытый ключ) ----
async function signBytes(priv: JsonWebKey, data: Uint8Array<ArrayBuffer>): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('jwk', priv, ALG_KEY, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign(ALG_SIG, key, data));
}
export async function signCode(priv: JsonWebKey, id: string, exp: string): Promise<string> {
  const payload = codePayload(id, exp);
  return CODE_PREFIX + '.' + bytesToB64u(payload) + '.' + bytesToB64u(await signBytes(priv, payload));
}
export async function signRevokedFile(priv: JsonWebKey, ids: string[], lic: ListLicense[], ts: number = Math.floor(Date.now() / 1000)): Promise<RevokedFile> {
  return { v: LIST_VERSION, ts, ids, lic, sig: bytesToB64u(await signBytes(priv, listPayload(ts, ids, lic))) };
}
