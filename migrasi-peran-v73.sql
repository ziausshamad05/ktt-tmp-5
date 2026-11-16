-- Migrasi peran v73: Direktur Utama, KTT, HSE, PJO, QAQC, Produksi
-- Akses data per peran dan per kontraktor, permohonan perubahan (koleksi 'ubah') yang diputuskan KTT atau Direktur.

-- 1. Daftar peran
alter table public.ktt_members drop constraint if exists ktt_members_peran_check;
alter table public.ktt_members drop constraint if exists ktt_members_peran_chk;
alter table public.ktt_members add constraint ktt_members_peran_check check (peran in ('direktur','ktt','hse','pjo','qaqc','produksi'));
alter table public.ktt_undangan drop constraint if exists ktt_undangan_peran_check;
alter table public.ktt_undangan add constraint ktt_undangan_peran_check check (peran in ('direktur','ktt','hse','pjo','qaqc','produksi'));

-- 2. Penjaga anggota: Direktur hanya diubah oleh Direktur; peran lapangan bukan Admin; kontraktor untuk PJO, QAQC, Produksi
create or replace function public.ktt_members_guard() returns trigger language plpgsql security definer set search_path to '' as $f$
declare o public.ktt_orgs; me public.ktt_members; uid uuid := auth.uid(); ada_dir boolean;
begin
  if tg_op = 'UPDATE' then
    if uid is not null and (new.user_id <> old.user_id or new.org_id <> old.org_id or new.email is distinct from old.email) then
      raise exception 'Identitas anggota tidak dapat diubah';
    end if;
    if uid is not null and not public.ktt_is_operator() then
      select * into me from public.ktt_members where user_id = uid;
      if old.peran = 'direktur' and me.peran is distinct from 'direktur' then
        raise exception 'Akses Direktur Utama hanya dapat diubah oleh Direktur Utama';
      end if;
      if new.peran = 'direktur' and old.peran is distinct from 'direktur' and me.peran is distinct from 'direktur' then
        select exists (select 1 from public.ktt_members x where x.org_id = new.org_id and x.peran = 'direktur') into ada_dir;
        if ada_dir then raise exception 'Hanya Direktur Utama yang dapat menetapkan Direktur Utama'; end if;
      end if;
    end if;
  end if;
  if new.peran = 'direktur' then new.role := 'admin'; end if;
  if tg_op = 'UPDATE' and old.role = 'admin' and new.role <> 'admin'
     and not exists (select 1 from public.ktt_members x where x.org_id = old.org_id and x.role = 'admin' and x.user_id <> old.user_id) then
    raise exception 'Perusahaan harus memiliki minimal satu admin';
  end if;
  if new.peran in ('hse','pjo','qaqc','produksi') then
    select * into o from public.ktt_orgs where id = new.org_id;
    if not o.internal and o.paket is distinct from 'profesional' then raise exception 'Peran % memerlukan paket Profesional', upper(new.peran); end if;
  end if;
  if new.peran in ('pjo','qaqc','produksi') and new.role = 'admin' then raise exception 'Peran % tidak boleh berhak akses Admin', upper(new.peran); end if;
  if new.peran in ('pjo','qaqc','produksi') then new.kontraktor := nullif(btrim(coalesce(new.kontraktor,'')),''); else new.kontraktor := null; end if;
  if new.peran = 'pjo' and new.kontraktor is null then raise exception 'PJO wajib dikaitkan ke satu kontraktor'; end if;
  return new;
end $f$;

create or replace function public.ktt_members_hapus_guard() returns trigger language plpgsql security definer set search_path to '' as $f$
declare me public.ktt_members;
begin
  if auth.uid() is null or public.ktt_is_operator() then return old; end if;
  select * into me from public.ktt_members where user_id = auth.uid();
  if old.peran = 'direktur' and me.peran is distinct from 'direktur' then raise exception 'Direktur Utama hanya dapat dikeluarkan oleh Direktur Utama'; end if;
  return old;
end $f$;
drop trigger if exists ktt_members_hapus_guard on public.ktt_members;
create trigger ktt_members_hapus_guard before delete on public.ktt_members for each row execute function public.ktt_members_hapus_guard();

create or replace function public.ktt_undangan_guard() returns trigger language plpgsql security definer set search_path to '' as $f$
declare o public.ktt_orgs; me public.ktt_members;
begin
  if new.peran = 'direktur' then
    new.role := 'admin';
    if auth.uid() is not null and not public.ktt_is_operator() then
      select * into me from public.ktt_members where user_id = auth.uid();
      if me.peran is distinct from 'direktur' and exists (select 1 from public.ktt_members x where x.org_id = new.org_id and x.peran = 'direktur') then
        raise exception 'Hanya Direktur Utama yang dapat mengundang Direktur Utama';
      end if;
    end if;
  end if;
  if new.peran in ('hse','pjo','qaqc','produksi') then
    select * into o from public.ktt_orgs where id = new.org_id;
    if not o.internal and o.paket is distinct from 'profesional' then raise exception 'Peran % memerlukan paket Profesional', upper(new.peran); end if;
  end if;
  if new.peran in ('pjo','qaqc','produksi') and new.role = 'admin' then raise exception 'Peran % tidak boleh berhak akses Admin', upper(new.peran); end if;
  if new.peran in ('pjo','qaqc','produksi') then new.kontraktor := nullif(btrim(coalesce(new.kontraktor,'')),''); else new.kontraktor := null; end if;
  if new.peran = 'pjo' and new.kontraktor is null then raise exception 'PJO wajib dikaitkan ke satu kontraktor'; end if;
  return new;
end $f$;

-- 3. Aturan akses data per peran. p_aksi: r baca, c tambah, u ubah, d hapus.
create or replace function public.ktt_kv_boleh(p_aksi text, p_col text, p_data jsonb) returns boolean
language plpgsql stable security definer set search_path to '' as $f$
declare
  m public.ktt_members; p text; k text; par public.ktt_kv;
  dk text := coalesce(p_data->>'kontraktor','');
  K3 text[] := array['insiden','inspeksi','temuan','agenda','inventaris','risiko','jamkerja','minepermit','simper'];
  RK text[] := array['reklamasi','revegetasi','rkgiat','pucuk','bibit','erosi','pasca','rkdok','rkthn'];
  OPD text[] := array['opsm','opcat','opeto','opform','oplog'];
  OPR text[] := array['opset','opmaster','opplan','oprkab','opkon'];
  UM text[] := array['profil','langganan','matrik'];
begin
  select * into m from public.ktt_members where user_id = auth.uid();
  if not found or m.role = 'pending' then return false; end if;
  if p_aksi <> 'r' and m.role not in ('editor','admin') then return false; end if;
  if p_col = 'langganan' and p_aksi <> 'r' then return false; end if;
  p := m.peran; k := nullif(btrim(coalesce(m.kontraktor,'')),'');

  -- lampiran mengikuti catatan induknya
  if p_col = 'berkas' then
    if p in ('direktur','ktt') then return true; end if;
    select * into par from public.ktt_kv where org_id = m.org_id and collection = p_data->>'kol' and id = p_data->>'rid';
    if not found then return false; end if;
    if p_aksi = 'r' then return public.ktt_kv_boleh('r', par.collection, par.data); end if;
    if p_aksi = 'c' then return public.ktt_kv_boleh('r', par.collection, par.data) and (public.ktt_kv_boleh('u', par.collection, par.data) or public.ktt_kv_boleh('c', par.collection, par.data)); end if;
    return public.ktt_kv_boleh('u', par.collection, par.data);
  end if;

  -- permohonan perubahan
  if p_col = 'ubah' then
    if p_aksi = 'r' then return p in ('direktur','ktt') or p_data->>'oleh' = auth.uid()::text; end if;
    if p_aksi = 'c' then
      if p in ('direktur','ktt') then return false; end if;
      if p_data->>'oleh' is distinct from auth.uid()::text or p_data->>'status' is distinct from 'menunggu' then return false; end if;
      select * into par from public.ktt_kv where org_id = m.org_id and collection = p_data->>'kol' and id = p_data->>'rid';
      if not found or not public.ktt_kv_boleh('r', par.collection, par.data) then return false; end if;
      dk := coalesce(par.data->>'kontraktor','');
      if p = 'hse' then return dk = '' and par.collection = any(K3 || RK || array['sop','ptw']); end if;
      if p = 'pjo' then return dk = k and par.collection = any(K3 || RK || array['opeto']); end if;
      if p = 'qaqc' and k is not null then return dk = k and par.collection = 'opeto'; end if;
      return false;
    end if;
    if p_aksi = 'u' then return p in ('direktur','ktt'); end if;
    return p in ('direktur','ktt') or (p_data->>'oleh' = auth.uid()::text and p_data->>'status' = 'menunggu');
  end if;

  if p in ('direktur','ktt') then return true; end if;

  if p = 'hse' then
    if p_col = any(UM) then return p_aksi = 'r'; end if;
    if p_col = any(K3 || RK || array['sop','ptw','jaminan','surat','distribusi']) then
      if p_aksi = 'r' then return true; end if;
      if p_aksi = 'c' then return dk = '' and p_col <> 'jaminan'; end if;
      if p_aksi = 'u' then return p_col in ('surat','distribusi'); end if;
    end if;
    return false;
  end if;

  if p = 'pjo' then
    if p_col = any(UM || OPR) then return p_aksi = 'r'; end if;
    if k is null then return false; end if;
    if p_col = any(K3 || RK) then return dk = k and p_aksi in ('r','c'); end if;
    if p_col = any(OPD) then return dk = k; end if;
    if p_col = 'kontraktor' then return p_data->>'nama' = k and p_aksi in ('r','u'); end if;
    if p_col = 'kdok' then return dk = k; end if;
    if p_col = 'personel' then return dk = k and p_aksi in ('r','c','u'); end if;
    if p_col in ('surat','ptw') then return p_aksi = 'r' and p_data->>'pjo_id' = auth.uid()::text; end if;
    return false;
  end if;

  if p = 'qaqc' then
    if p_col = any(UM) then return p_aksi = 'r'; end if;
    if k is null then return p_col = any(OPD || OPR || array['opbarge']); end if;
    if p_col = any(OPR) then return p_aksi = 'r'; end if;
    if p_col = any(OPD) then return dk = k; end if;
    return false;
  end if;

  if p = 'produksi' then
    if p_col = any(UM || OPR || array['opcat']) then return p_aksi = 'r'; end if;
    if p_col in ('opsm','oplog') then return k is null or dk = k; end if;
    return false;
  end if;

  return false;
end $f$;
revoke all on function public.ktt_kv_boleh(text, text, jsonb) from public;
grant execute on function public.ktt_kv_boleh(text, text, jsonb) to authenticated;

drop policy if exists ktt_kv_select on public.ktt_kv;
drop policy if exists ktt_kv_select_ops on public.ktt_kv;
drop policy if exists ktt_kv_select_pjo on public.ktt_kv;
drop policy if exists ktt_kv_insert on public.ktt_kv;
drop policy if exists ktt_kv_update on public.ktt_kv;
drop policy if exists ktt_kv_delete on public.ktt_kv;
drop policy if exists ktt_kv_ops_ins on public.ktt_kv;
drop policy if exists ktt_kv_ops_upd on public.ktt_kv;
drop policy if exists ktt_kv_ops_del on public.ktt_kv;
create policy ktt_kv_baca on public.ktt_kv for select to authenticated
  using (org_id = (select public.ktt_org()) and (select public.ktt_org_ok()) and public.ktt_kv_boleh('r', collection, data));
create policy ktt_kv_tambah on public.ktt_kv for insert to authenticated
  with check (org_id = (select public.ktt_org()) and (select public.ktt_org_ok()) and public.ktt_kv_boleh('c', collection, data));
create policy ktt_kv_ubah on public.ktt_kv for update to authenticated
  using (org_id = (select public.ktt_org()) and (select public.ktt_org_ok()) and public.ktt_kv_boleh('u', collection, data))
  with check (org_id = (select public.ktt_org()) and (select public.ktt_org_ok()) and public.ktt_kv_boleh('u', collection, data));
create policy ktt_kv_hapus on public.ktt_kv for delete to authenticated
  using (org_id = (select public.ktt_org()) and (select public.ktt_org_ok()) and public.ktt_kv_boleh('d', collection, data));

-- 4. Penjaga isi: operasional per peran, evaluasi CSMS hanya KTT
create or replace function public.ktt_kv_ops_guard() returns trigger language plpgsql security definer set search_path to '' as $f$
declare p text; kk text; ef text; k text; n jsonb; o jsonb;
begin
  if auth.uid() is null then return coalesce(new, old); end if;
  k := coalesce(new.collection, old.collection);
  p := public.ktt_peran(); kk := nullif(btrim(coalesce(public.ktt_kontraktor(),'')),'');
  if p = 'hse' and k like 'op%' then raise exception 'Peran HSE tidak dapat mengubah data Operasional'; end if;
  n := case when tg_op = 'DELETE' then null else new.data end;
  o := case when tg_op = 'INSERT' then null else old.data end;
  if p = 'pjo' and k = 'kontraktor' and tg_op = 'UPDATE' then
    if (n->'status') is distinct from (o->'status') or (n->'skor') is distinct from (o->'skor')
       or (n->'evaluasi') is distinct from (o->'evaluasi') or (n->'berikut') is distinct from (o->'berikut') then
      raise exception 'Status dan skor evaluasi CSMS hanya diisi oleh KTT';
    end if;
  end if;
  ef := case when p = 'produksi' then 'foreman' when p = 'pjo' then 'kontraktor' when p = 'qaqc' and kk is not null then 'kontraktor' else null end;
  if ef is null or k not like 'op%' then return coalesce(new, old); end if;
  if ef = 'foreman' then
    if k not in ('opsm','oplog') then raise exception 'Peran Produksi hanya mencatat produksi harian'; end if;
    if k = 'opsm' then
      if n is not null and (coalesce(n ->> 'final','false') = 'true' or n ->> 'oleh' is distinct from auth.uid()::text) then
        raise exception 'Peran Produksi hanya menyimpan draft buatannya sendiri; finalisasi oleh KTT, QAQC atau PJO';
      end if;
      if o is not null and (coalesce(o ->> 'final','false') = 'true' or o ->> 'oleh' is distinct from auth.uid()::text) then
        raise exception 'Peran Produksi hanya mengubah draft buatannya sendiri';
      end if;
    end if;
  end if;
  if k = 'opeto' and (n -> 'psi') is distinct from (o -> 'psi') then
    raise exception 'Hasil PSI perlu persetujuan KTT. Ajukan lewat permohonan perubahan';
  end if;
  return coalesce(new, old);
end $f$;

-- 5. Keputusan permohonan perubahan oleh KTT atau Direktur
create or replace function public.ktt_ubah_putus(p_id text, p_setuju boolean, p_catatan text default null) returns text
language plpgsql security definer set search_path to '' as $f$
declare uid uuid := auth.uid(); m public.ktt_members; u public.ktt_kv; t public.ktt_kv; v_baru jsonb; v_nm text; v_st text;
  v_cat text := nullif(left(btrim(coalesce(p_catatan,'')),1000),'');
  v_iso text := to_char(now() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"');
begin
  select * into m from public.ktt_members where user_id = uid;
  if uid is null or not found then raise exception 'Belum masuk'; end if;
  if m.peran not in ('ktt','direktur') or m.role not in ('editor','admin') then raise exception 'Hanya KTT atau Direktur Utama dengan hak penyunting yang dapat memutuskan permohonan'; end if;
  if not public.ktt_org_ok() then raise exception 'Akun perusahaan belum aktif'; end if;
  if p_setuju is null then raise exception 'Keputusan wajib dipilih'; end if;
  if not p_setuju and v_cat is null then raise exception 'Alasan penolakan wajib diisi'; end if;
  select * into u from public.ktt_kv where org_id = m.org_id and collection = 'ubah' and id = p_id for update;
  if not found then raise exception 'Permohonan tidak ditemukan'; end if;
  if u.data->>'status' is distinct from 'menunggu' then raise exception 'Permohonan ini sudah diputuskan'; end if;
  v_nm := coalesce(nullif(m.nama,''), m.email);
  if p_setuju then
    select * into t from public.ktt_kv where org_id = m.org_id and collection = u.data->>'kol' and id = u.data->>'rid' for update;
    if not found then raise exception 'Catatan asal sudah tidak ada'; end if;
    v_baru := u.data->'baru';
    if v_baru is null or jsonb_typeof(v_baru) <> 'object' then raise exception 'Isi perubahan tidak valid'; end if;
    v_baru := v_baru - 'id';
    if t.data ? 'kontraktor' then v_baru := v_baru || jsonb_build_object('kontraktor', t.data->'kontraktor'); else v_baru := v_baru - 'kontraktor'; end if;
    update public.ktt_kv set data = v_baru where org_id = t.org_id and collection = t.collection and id = t.id;
  end if;
  v_st := case when p_setuju then 'disetujui' else 'ditolak' end;
  update public.ktt_kv set data = data || jsonb_strip_nulls(jsonb_build_object('status', v_st, 'putus_oleh', v_nm, 'putus_ts', v_iso, 'catatan_putus', v_cat))
    where org_id = u.org_id and collection = 'ubah' and id = u.id;
  return v_st;
end $f$;
revoke all on function public.ktt_ubah_putus(text, boolean, text) from public;
grant execute on function public.ktt_ubah_putus(text, boolean, text) to authenticated;

-- 6. Direktur Utama diperlakukan seperti KTT di alur surat dan izin kerja
do $d$
declare r record; src text; baru text;
begin
  for r in select p.oid, p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace
           where n.nspname = 'public' and p.proname in ('ktt_ptw_putus','ktt_ptw_tutup','ktt_surat_auto','ktt_surat_balas','ktt_surat_buka','ktt_surat_kirim','ktt_surat_tindak') loop
    src := pg_get_functiondef(r.oid); baru := src;
    baru := replace(baru, $$m.peran not in ('hse','ktt')$$, $$m.peran not in ('hse','ktt','direktur')$$);
    baru := replace(baru, $$m.peran in ('hse','ktt')$$, $$m.peran in ('hse','ktt','direktur')$$);
    baru := replace(baru, $$m.peran is distinct from 'ktt'$$, $$coalesce(m.peran,'') not in ('ktt','direktur')$$);
    baru := replace(baru, $$(m.peran = 'ktt' and$$, $$(m.peran in ('ktt','direktur') and$$);
    baru := replace(baru, $$x.peran = 'ktt'$$, $$x.peran in ('ktt','direktur')$$);
    if baru = src then raise exception 'Fungsi % tidak berubah, periksa pola', r.proname; end if;
    execute baru;
  end loop;
end $d$;

-- 7. Direktur Utama PT Surya Saga Utama
update public.ktt_members m set peran = 'direktur', role = 'admin', kontraktor = null
  from public.ktt_orgs o where o.id = m.org_id and o.internal and m.email = 'ziausshamad05@gmail.com';
