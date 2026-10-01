// Правка подписанного revoked.json из GitHub Actions (шаблоны «Активация на 7 / 30 / 365 дней», «Отозвать»).
//   node tools/grant.ts grant <дней> "<ID ID ...>"   — открыть доступ (или продлить) на N дней
//   node tools/grant.ts revoke "<ID ID ...>"         — отозвать
// Закрытый ключ — в секрете репозитория GEOROMB_PRIVATE_KEY (JWK), в файлы и логи он не попадает.
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import {
  ID_RE, PUBLIC_KEY, dateNum, formatId, normalizeId, signRevokedFile, verifyRevokedFile, type ListLicense
} from './license.ts';

const FILE = 'revoked.json';
const MAX_IDS = 20;

function fail(msg: string): never { console.error('Ошибка: ' + msg); process.exit(1); }

function parseIds(raw: string): string[] {
  const out: string[] = [];
  for(const part of String(raw || '').split(/[\s,;]+/)){
    if(!part) continue;
    const id = normalizeId(part);
    if(!ID_RE.test(id)) fail(`«${part}» — не ID устройства (нужно 10 символов, например ABCDE-23456)`);
    if(!out.includes(id)) out.push(id);
  }
  if(!out.length) fail('не указан ни один ID');
  if(out.length > MAX_IDS) fail(`за один запуск — не больше ${MAX_IDS} ID (указано ${out.length})`);
  return out;
}
// YYYYMMDD + n дней (по часовому поясу из TZ — в шаблонах Asia/Tashkent)
function addDays(ymd: number, n: number): string {
  const d = new Date(Math.floor(ymd / 10000), Math.floor(ymd / 100) % 100 - 1, ymd % 100 + n);
  return String(dateNum(d));
}
const human = (exp: string) => exp === '0' ? 'бессрочно' : `${exp.slice(6, 8)}.${exp.slice(4, 6)}.${exp.slice(0, 4)}`;

async function main(): Promise<void> {
  const [cmd, a1, a2] = process.argv.slice(2);
  const keyRaw = process.env.GEOROMB_PRIVATE_KEY;
  if(!keyRaw) fail('нет секрета GEOROMB_PRIVATE_KEY (Settings → Secrets and variables → Actions)');
  let key: JsonWebKey;
  try{ key = JSON.parse(keyRaw) as JsonWebKey; }catch{ fail('GEOROMB_PRIVATE_KEY — не JSON (вставьте содержимое private.jwk.json целиком)'); }
  if(key.x !== PUBLIC_KEY.x || key.y !== PUBLIC_KEY.y || !key.d) fail('ключ в секрете не подходит к приложению');

  // текущий список: подпись должна сойтись, иначе файл испорчен — ничего не трогаем
  const cur = await verifyRevokedFile(JSON.parse(readFileSync(FILE, 'utf8')));
  if(!cur) fail(`${FILE} повреждён или подписан чужим ключом`);
  const ids = new Set(cur.ids);
  const lic = new Map<string, string>(cur.lic.map(x => [x.id, x.exp]));
  const today = dateNum();
  const rows: string[] = [];
  let title: string;

  if(cmd === 'grant'){
    const days = Number(a1);
    if(!Number.isInteger(days) || days < 1 || days > 3660) fail('срок — целое число дней от 1 до 3660');
    for(const id of parseIds(a2)){
      const was = lic.get(id);
      let exp: string;
      if(was === '0') exp = '0';                                                    // бессрочную не укорачиваем
      else if(was && Number(was) >= today) exp = addDays(Number(was), days);       // ещё действует — продлеваем от конца
      else exp = addDays(today, days);
      const note = ids.has(id) ? 'снят отзыв, ' : '';
      ids.delete(id);
      lic.set(id, exp);
      rows.push(`| ${formatId(id)} | ${human(exp)} | ${note}${!was ? 'новая' : was === '0' ? 'уже бессрочная' : 'продлена (было до ' + human(was) + ')'} |`);
    }
    title = `Активация на ${days} дн.`;
  }else if(cmd === 'revoke'){
    for(const id of parseIds(a1)){
      ids.add(id);
      const was = lic.get(id);
      lic.delete(id);
      rows.push(`| ${formatId(id)} | отозвана | ${!was ? 'в списке не было — заблокирована' : was === '0' ? 'была бессрочная' : 'была до ' + human(was)} |`);
    }
    title = 'Отзыв лицензий';
  }else{
    fail('команда: grant <дней> "<ID ...>" или revoke "<ID ...>"');
  }

  // как keygen.html и backend: ID по алфавиту; ts — секунды, всегда больше прежнего (приложение не берёт старые списки)
  const outIds = [...ids].sort();
  const outLic: ListLicense[] = [...lic].map(([id, exp]) => ({ id, exp })).sort((a, b) => a.id < b.id ? -1 : 1);
  const ts = Math.max(Math.floor(Date.now() / 1000), cur.ts + 1);
  const file = await signRevokedFile(key, outIds, outLic, ts);
  if(!await verifyRevokedFile(file)) fail('новая подпись не прошла проверку');
  writeFileSync(FILE, JSON.stringify(file, null, 1) + '\n');

  const report = [`### ${title}`, '', '| ID | Действует до | |', '|---|---|---|', ...rows, '',
    `Всего в списке: ${outLic.length} активаций, ${outIds.length} отозванных. Клиенту: открыть приложение и нажать «Проверить» (через 1–2 минуты).`].join('\n');
  console.log(report);
  if(process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, report + '\n');
  if(process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `message=${title}: ${rows.length} ID\n`);
}
void main();
