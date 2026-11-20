// Mekari Sign (HMAC) untuk surat KTT Platform KTT.
// - Hanya akun berperan KTT (editor/admin) yang boleh memakai.
// - Kredensial (Client ID & Secret) per perusahaan disimpan di tabel ktt_mekari (RLS tanpa policy = hanya service role).
//   Secret tidak pernah dikirim balik ke browser.
// - Aksi: info, simpan, ping, kirim, cek, batal.
import { createClient } from 'npm:@supabase/supabase-js@2';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...CORS, 'Content-Type': 'application/json' } });
const err = (kode: string, pesan: string, s = 400) => json({ ok: false, kode, pesan }, s);

const ENVS: Record<string, string> = { sandbox: 'https://sandbox-api.mekari.com', production: 'https://api.mekari.com' };
const PREFIX = '/v2/esign-hmac';
const BUCKET = 'ktt-berkas';
const MAX_PDF = 20 * 1024 * 1024;
const METERAI = ['Akta Pejabat', 'Surat Berharga', 'Dokumen Transaksi', 'Dokumen Lelang', 'Dokumen pernyataan jumlah uang lebih dari 5jt', 'Akta Notaris', 'Surat Perjanjian', 'Dokumen lain-lain', 'Surat Keterangan', 'Surat Pernyataan', 'Dokumen penerimaan uang (lebih dari 5 juta)', 'Dokumen pelunasan utang (lebih dari 5 juta)', 'Surat Lainnya'];
const STATUS = ['in_progress', 'completed', 'voided', 'declined', 'denied'];

const te = new TextEncoder();
function b64(buf: ArrayBuffer | Uint8Array): string {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = ''; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64(s: string): Uint8Array | null {
  try { const bin = atob(s.replace(/^data:[^,]*,/, '').replace(/\s+/g, '')); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; } catch (_e) { return null; }
}
const isPdf = (u: Uint8Array | null) => !!u && u.length > 4 && u[0] === 0x25 && u[1] === 0x50 && u[2] === 0x44 && u[3] === 0x46;
const clip = (v: unknown, n: number) => String(v ?? '').trim().slice(0, n);
const mask = (v: string) => !v ? '' : v.length <= 10 ? '•'.repeat(v.length) : v.slice(0, 4) + '…' + v.slice(-4);
const nowIso = () => new Date().toISOString();

type Cred = { id: string; secret: string; env: string };

async function mekari(cred: Cred, method: string, path: string, body?: unknown, timeout = 60_000, raw = false) {
  const full = PREFIX + path;
  const date = new Date().toUTCString();
  const key = await crypto.subtle.importKey('raw', te.encode(cred.secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = b64(await crypto.subtle.sign('HMAC', key, te.encode(`date: ${date}\n${method} ${full} HTTP/1.1`)));
  const headers: Record<string, string> = {
    Date: date,
    Authorization: `hmac username="${cred.id}", algorithm="hmac-sha256", headers="date request-line", signature="${sig}"`,
    Accept: 'application/json, application/pdf',
  };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(ENVS[cred.env] + full, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: ctl.signal });
    const buf = new Uint8Array(await r.arrayBuffer());
    let j: any = null;
    if (!raw || !isPdf(buf)) { try { j = JSON.parse(new TextDecoder().decode(buf)); } catch (_e) { /* bukan JSON */ } }
    const out = { status: r.status, json: j, bytes: buf, error: '' };
    if (r.status < 200 || r.status >= 300) out.error = errText(r.status, j);
    return out;
  } catch (_e) {
    return { status: 0, json: null, bytes: new Uint8Array(), error: 'Tidak bisa terhubung ke Mekari Sign (waktu habis atau jaringan).' };
  } finally { clearTimeout(t); }
}
function errText(status: number, j: any): string {
  const parts: string[] = [];
  const pick = (v: any) => { if (!v) return; if (typeof v === 'string') parts.push(v); else if (Array.isArray(v)) v.forEach(pick); else if (typeof v === 'object') { if (v.detail || v.message || v.title) pick(v.detail || v.message || v.title); else Object.entries(v).forEach(([k, x]) => { if (typeof x === 'string') parts.push(k + ': ' + x); else if (Array.isArray(x)) parts.push(k + ': ' + x.join(', ')); }); } };
  if (j) { pick(j.errors); if (!parts.length) pick(j.message || j.error || j.detail); }
  const base = status === 401 || status === 403 ? 'Kredensial ditolak Mekari Sign (cek Client ID/Secret dan lingkungan)' : status === 422 ? 'Data ditolak Mekari Sign' : status === 402 ? 'Kuota Mekari Sign tidak cukup' : status === 429 ? 'Terlalu banyak permintaan ke Mekari Sign' : 'Mekari Sign membalas galat ' + status;
  return (parts.length ? base + ': ' + parts.join('; ') : base).slice(0, 480);
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });
  if (req.method !== 'POST') return err('metode', 'Gunakan POST', 405);
  try {
    const body = await req.json().catch(() => ({}));
    const aksi = String(body?.aksi ?? '');
    const url = Deno.env.get('SUPABASE_URL')!;
    const user = createClient(url, Deno.env.get('SUPABASE_ANON_KEY')!, { global: { headers: { Authorization: req.headers.get('Authorization') ?? '' } } });
    const admin = createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);

    const { data: u } = await user.auth.getUser();
    if (!u?.user) return err('belum_masuk', 'Silakan masuk lagi.', 401);
    const { data: m } = await admin.from('ktt_members').select('org_id,role,peran,nama,email').eq('user_id', u.user.id).maybeSingle();
    if (!m || !['editor', 'admin'].includes(m.role) || m.peran !== 'ktt') return err('izin', 'Fitur tanda tangan Mekari Sign hanya untuk akun KTT.', 403);
    const { data: o } = await admin.from('ktt_orgs').select('id,status').eq('id', m.org_id).maybeSingle();
    if (!o || o.status !== 'aktif') return err('izin', 'Perusahaan belum aktif.', 403);
    const org = m.org_id as string;
    const oleh = (m.nama || m.email || 'KTT') as string;

    const { data: cr } = await admin.from('ktt_mekari').select('*').eq('org_id', org).maybeSingle();
    const env = cr?.env === 'production' ? 'production' : 'sandbox';
    const credOf = (e: string): Cred => ({ env: e, id: (e === 'production' ? cr?.prod_id : cr?.sandbox_id) || '', secret: (e === 'production' ? cr?.prod_secret : cr?.sandbox_secret) || '' });
    const cred = credOf(env);
    const siap = !!(cred.id && cred.secret);

    if (aksi === 'info') {
      return json({ ok: true, env, siap,
        sandbox: { id: mask(cr?.sandbox_id || ''), secret: !!cr?.sandbox_secret },
        production: { id: mask(cr?.prod_id || ''), secret: !!cr?.prod_secret },
        diubah: cr?.updated_at || null });
    }

    if (aksi === 'simpan') {
      const e = body.env === 'production' ? 'production' : 'sandbox';
      const id = clip(body.client_id, 120), sec = clip(body.client_secret, 255);
      if (id && !/^[A-Za-z0-9._\-]{6,120}$/.test(id)) return err('input', 'Format Client ID tidak dikenali.');
      if (sec && (sec.length < 8 || /\s/.test(sec))) return err('input', 'Format Client Secret tidak dikenali.');
      const row: Record<string, unknown> = { org_id: org, env: body.pakai === false ? env : e, updated_at: nowIso(), updated_by: u.user.id };
      if (id) row[e === 'production' ? 'prod_id' : 'sandbox_id'] = id;
      if (sec) row[e === 'production' ? 'prod_secret' : 'sandbox_secret'] = sec;
      if (body.hapus === true) { row[e === 'production' ? 'prod_id' : 'sandbox_id'] = null; row[e === 'production' ? 'prod_secret' : 'sandbox_secret'] = null; }
      const { error } = await admin.from('ktt_mekari').upsert(row, { onConflict: 'org_id' });
      if (error) { console.error(error); return err('galat', 'Gagal menyimpan kredensial.', 500); }
      return json({ ok: true });
    }

    if (!siap) return err('belum_siap', 'Client ID dan Client Secret Mekari Sign (' + (env === 'production' ? 'Production' : 'Sandbox') + ') belum diisi. Buka Pengaturan surat KTT.', 400);

    if (aksi === 'ping') {
      const r = await mekari(cred, 'GET', '/v1/profile', undefined, 20_000);
      if (r.error) return err('mekari', r.error, 502);
      const a = r.json?.data?.attributes ?? {};
      const co = a.company; const coName = co && typeof co === 'object' ? (co.name ?? co.company_name ?? '') : (co ?? '');
      return json({ ok: true, env, nama: a.full_name ?? '', email: a.email ?? '', perusahaan: coName, saldo: a.balance ?? null });
    }

    const sid = clip(body.surat_id, 80);
    if (!sid) return err('input', 'Surat tidak dikenal.');
    const { data: kv } = await admin.from('ktt_kv').select('data').eq('org_id', org).eq('collection', 'surat').eq('id', sid).maybeSingle();
    if (!kv) return err('tidak_ada', 'Surat tidak ditemukan.', 404);
    const d: any = kv.data || {};
    if (d.asal !== 'ktt' || !d.ktt_surat) return err('izin', 'Hanya surat yang dibuat lewat Surat KTT yang dapat ditandatangani di sini.', 403);
    const save = async (nd: any) => {
      const { error } = await admin.from('ktt_kv').update({ data: nd }).eq('org_id', org).eq('collection', 'surat').eq('id', sid);
      if (error) throw error;
    };
    const logAdd = (nd: any, aksiLog: string, ket: string, siapa = oleh) => { nd.log = (Array.isArray(nd.log) ? nd.log.slice(-40) : []).concat([{ t: nowIso(), aksi: aksiLog, oleh: siapa, ket }]); };
    const credE = (e: any) => credOf(e?.env === 'production' ? 'production' : 'sandbox');

    if (aksi === 'kirim') {
      const cur = d.esign;
      if (cur && cur.doc_id && (cur.status === 'in_progress' || cur.status === 'completed')) {
        return err('konflik', cur.status === 'completed' ? 'Surat ini sudah selesai ditandatangani.' : 'Masih ada permintaan tanda tangan yang berjalan. Batalkan dulu bila ingin mengirim ulang.', 409);
      }
      const pdf = unb64(String(body.pdf ?? ''));
      if (!isPdf(pdf)) return err('input', 'Berkas PDF tidak valid.', 422);
      if (pdf!.length > MAX_PDF) return err('input', 'PDF terlalu besar (maksimal 20 MB).', 422);
      const mode = body.mode === 'psre' ? 'psre' : 'global';
      const meterai = body.meterai === true;
      const jm = METERAI.includes(body.jenis_meterai) ? body.jenis_meterai : 'Surat Lainnya';
      const pages = Math.max(1, Math.min(200, Number(body.halaman) || 1));
      const seen = new Set<string>();
      const signers: any[] = [];
      let nMet = 0;
      for (const sg of (Array.isArray(body.signers) ? body.signers : []).slice(0, 5)) {
        const name = clip(sg?.name, 150), email = clip(sg?.email, 190).toLowerCase();
        if (!name) return err('input', 'Nama penanda tangan wajib diisi.', 422);
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return err('input', 'Email penanda tangan tidak valid: ' + email, 422);
        if (seen.has(email)) return err('input', 'Email ' + email + ' dipakai lebih dari satu penanda tangan.', 422);
        seen.add(email);
        const ann: any[] = [];
        for (const a of (Array.isArray(sg?.annotations) ? sg.annotations : []).slice(0, 10)) {
          const type_of = ['signature', 'meterai'].includes(a?.type_of) ? a.type_of : 'signature';
          if (type_of === 'meterai' && !meterai) continue;
          const n = (v: unknown) => Math.round(Number(v) * 100) / 100;
          const one: any = { type_of, page: Math.max(1, Math.min(pages, Math.floor(Number(a?.page) || 1))), position_x: n(a?.x), position_y: n(a?.y), element_width: n(a?.w), element_height: n(a?.h), canvas_width: n(a?.cw), canvas_height: n(a?.ch) };
          if ([one.position_x, one.position_y, one.element_width, one.element_height, one.canvas_width, one.canvas_height].some((v) => !isFinite(v) || v < 0)) continue;
          if (one.element_width < 20 || one.element_height < 15 || one.canvas_width < 100 || one.canvas_height < 100) continue;
          if (type_of === 'meterai') nMet++;
          ann.push(one);
        }
        if (!ann.some((a) => a.type_of === 'signature')) return err('input', 'Posisi tanda tangan untuk ' + name + ' tidak ditemukan.', 422);
        signers.push({ name, email, order: signers.length + 1, annotations: ann });
      }
      if (!signers.length) return err('input', 'Isi minimal satu penanda tangan.', 422);
      if (meterai && !nMet) return err('input', 'Posisi e-Meterai tidak ditemukan.', 422);
      const receivers = (Array.isArray(body.receivers) ? body.receivers : []).slice(0, 10)
        .map((x: any) => ({ name: clip(x?.name, 150) || clip(x?.email, 150), email: clip(x?.email, 190).toLowerCase() }))
        .filter((x: any) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x.email) && !seen.has(x.email));
      const filename = (clip(body.filename, 150).replace(/[^\w.\- ]+/g, '-') || 'surat-ktt') .replace(/\.pdf$/i, '') + '.pdf';
      const path = mode === 'psre' ? (meterai ? '/v1/documents/request_psre_sign' : '/v1/documents/request_psre_sign_only') : (meterai ? '/v1/documents/request_global_sign' : '/v1/documents/request_global_sign_only');
      const req: any = { doc: b64(pdf!), filename, signing_order: signers.length > 1, signers };
      if (receivers.length) req.receivers = receivers;
      if (meterai) req.type_of_meterai = jm;
      const asli = `${org}/esign/${sid}-${Date.now().toString(36)}.pdf`;
      await admin.storage.from(BUCKET).upload(asli, pdf!, { contentType: 'application/pdf', upsert: false }).catch(() => null);
      const r = await mekari(cred, 'POST', path, req, 180_000);
      const docId = String(r.json?.data?.id ?? '');
      const ok = !r.error && !!docId;
      const nd: any = { ...d };
      if (cur && cur.doc_id) nd.esign_riwayat = (Array.isArray(d.esign_riwayat) ? d.esign_riwayat.slice(-9) : []).concat([cur]);
      nd.esign = { env, mode, meterai, jenis_meterai: meterai ? jm : '', doc_id: docId, status: ok ? 'in_progress' : 'gagal', filename,
        signers: signers.map((s) => ({ name: s.name, email: s.email, order: s.order, status: '', signed_at: null })),
        receivers, halaman: pages, ukuran: pdf!.length, asli_ref: asli, dikirim_at: nowIso(), dikirim_oleh: oleh, galat: ok ? '' : (r.error || 'Jawaban Mekari Sign tidak dikenali.') };
      if (ok) nd.status = 'Proses TTD';
      logAdd(nd, ok ? 'Dikirim ke Mekari Sign' : 'Gagal dikirim ke Mekari Sign', ok ? (mode === 'psre' ? 'PSrE' : 'Global') + (meterai ? ' + e-Meterai' : '') + ' · ' + signers.map((s) => s.name).join(', ') : nd.esign.galat);
      await save(nd);
      if (!ok) return err('mekari', r.error || 'Mekari Sign tidak mengembalikan ID dokumen.', 502);
      return json({ ok: true, esign: nd.esign, status: nd.status });
    }

    const e = d.esign;
    if (!e || !e.doc_id) return err('input', 'Surat ini belum dikirim ke Mekari Sign.');
    const ce = credE(e);
    if (!ce.id || !ce.secret) return err('belum_siap', 'Kredensial Mekari Sign untuk lingkungan dokumen ini belum diisi.');

    if (aksi === 'cek') {
      const r = await mekari(ce, 'GET', '/v1/documents/' + encodeURIComponent(e.doc_id), undefined, 30_000);
      if (r.error || !r.json?.data?.attributes) return err('mekari', r.error || 'Jawaban Mekari Sign tidak dikenali.', 502);
      const a = r.json.data.attributes;
      let st = String(a.signing_status ?? 'in_progress'); if (!STATUS.includes(st)) st = 'in_progress';
      const rem = Array.isArray(a.signers) ? a.signers : [];
      const nd: any = { ...d }; const ne: any = { ...e };
      ne.signers = (Array.isArray(e.signers) ? e.signers : []).map((s: any) => {
        const x = rem.find((y: any) => String(y?.email ?? '').toLowerCase() === String(s.email).toLowerCase());
        return x ? { ...s, status: String(x.status ?? ''), signed_at: x.signed_at ?? null, viewed_at: x.viewed_at ?? null } : s;
      });
      ne.stamping_status = a.stamping_status ?? ne.stamping_status ?? null;
      const inv = a.invalided;
      if (inv && typeof inv === 'object') ne.alasan = clip([inv?.invalid_by?.full_name ?? inv?.invalid_by?.email ?? '', inv?.reason ?? ''].filter(Boolean).join(': '), 400);
      const prev = e.status; ne.status = st; ne.sinkron_at = nowIso(); ne.galat = '';
      if (st === 'completed') {
        ne.selesai_at = ne.selesai_at || a.completed_at || nowIso();
        if (!ne.ttd_ref) {
          const dl = await mekari(ce, 'GET', '/v1/documents/' + encodeURIComponent(e.doc_id) + '/download', undefined, 90_000, true);
          if (dl.status === 200 && isPdf(dl.bytes)) {
            const p = `${org}/esign/${sid}-ttd-${Date.now().toString(36)}.pdf`;
            const up = await admin.storage.from(BUCKET).upload(p, dl.bytes, { contentType: 'application/pdf', upsert: false });
            if (!up.error) {
              ne.ttd_ref = p; ne.ttd_ukuran = dl.bytes.length;
              const nm = String(e.filename || 'surat-ktt.pdf').replace(/\.pdf$/i, '') + '-ditandatangani.pdf';
              nd.lampiran = (Array.isArray(d.lampiran) ? d.lampiran.filter((x: any) => !x?.esign) : []).concat([{ nama: nm, tipe: 'application/pdf', ukuran: dl.bytes.length, b64ref: p, esign: true }]);
            } else ne.galat = 'PDF bertanda tangan belum tersimpan: ' + up.error.message;
          } else if (dl.status !== 424) ne.galat = 'Unduh PDF bertanda tangan gagal: ' + (dl.error || 'bukan berkas PDF');
        }
        if (ne.ttd_ref) nd.status = 'Ditandatangani';
      } else if (st === 'declined' || st === 'denied' || st === 'voided') {
        nd.status = 'Draft';
      }
      nd.esign = ne;
      if (prev !== st) logAdd(nd, 'Mekari Sign: ' + ({ in_progress: 'menunggu tanda tangan', completed: 'selesai ditandatangani', voided: 'dibatalkan', declined: 'ditolak penanda tangan', denied: 'verifikasi identitas gagal' } as Record<string, string>)[st], ne.alasan || '', 'Mekari Sign');
      await save(nd);
      return json({ ok: true, esign: ne, status: nd.status, berubah: prev !== st });
    }

    if (aksi === 'batal') {
      if (e.status !== 'in_progress') return err('input', 'Hanya permintaan yang masih menunggu tanda tangan yang bisa dibatalkan.');
      const alasan = clip(body.alasan, 300) || 'Dibatalkan oleh KTT';
      const r = await mekari(ce, 'POST', '/v1/documents/' + encodeURIComponent(e.doc_id) + '/void', { reason: alasan }, 30_000);
      if (r.error) return err('mekari', r.error, 502);
      const nd: any = { ...d, esign: { ...e, status: 'voided', alasan, sinkron_at: nowIso() }, status: 'Draft' };
      logAdd(nd, 'Tanda tangan dibatalkan', alasan);
      await save(nd);
      return json({ ok: true, esign: nd.esign, status: nd.status });
    }

    return err('aksi', 'Aksi tidak dikenal.');
  } catch (e) {
    console.error(e);
    return err('galat', 'Terjadi kesalahan di server.', 500);
  }
});
