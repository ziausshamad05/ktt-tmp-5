-- Migrasi v76: PJO mengundang dan mengatur akun QAQC dan Produksi untuk kontraktornya sendiri
create or replace function public.ktt_members_guard() returns trigger language plpgsql security definer set search_path to '' as $f$
declare o public.ktt_orgs; me public.ktt_members; uid uuid := auth.uid(); ada_dir boolean;
begin
  if tg_op = 'UPDATE' then
    if uid is not null and (new.user_id <> old.user_id or new.org_id <> old.org_id or new.email is distinct from old.email) then
      raise exception 'Identitas anggota tidak dapat diubah';
    end if;
    if uid is not null and not public.ktt_is_operator() then
      select * into me from public.ktt_members where user_id = uid;
      if me.peran = 'pjo' and (old.peran not in ('qaqc','produksi') or new.peran not in ('qaqc','produksi')
         or coalesce(old.kontraktor,'') <> coalesce(me.kontraktor,'') or coalesce(new.kontraktor,'') <> coalesce(me.kontraktor,'') or new.role = 'admin') then
        raise exception 'PJO hanya dapat mengatur akun QAQC dan Produksi di kontraktornya sendiri';
      end if;
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
  if auth.uid() is not null and not public.ktt_is_operator() then
    select * into me from public.ktt_members where user_id = auth.uid();
    if me.peran = 'pjo' and (new.peran not in ('qaqc','produksi') or coalesce(new.kontraktor,'') <> coalesce(me.kontraktor,'') or new.role not in ('viewer','editor')) then
      raise exception 'PJO hanya dapat mengundang QAQC atau Produksi untuk kontraktornya sendiri, dengan hak Pembaca atau Penyunting';
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

-- PJO mengelola akun QAQC dan Produksi di kontraktornya sendiri
drop policy if exists ktt_members_pjo_select on public.ktt_members;
drop policy if exists ktt_members_pjo_update on public.ktt_members;
drop policy if exists ktt_members_pjo_delete on public.ktt_members;
drop policy if exists ktt_undangan_pjo_select on public.ktt_undangan;
drop policy if exists ktt_undangan_pjo_insert on public.ktt_undangan;
drop policy if exists ktt_undangan_pjo_update on public.ktt_undangan;
drop policy if exists ktt_undangan_pjo_delete on public.ktt_undangan;
create policy ktt_members_pjo_select on public.ktt_members for select to authenticated
  using (org_id = (select public.ktt_org()) and (select public.ktt_peran()) = 'pjo' and peran in ('qaqc','produksi') and kontraktor = (select public.ktt_kontraktor()));
create policy ktt_members_pjo_update on public.ktt_members for update to authenticated
  using (org_id = (select public.ktt_org()) and (select public.ktt_org_ok()) and (select public.ktt_peran()) = 'pjo' and (select public.ktt_role()) = 'editor' and peran in ('qaqc','produksi') and kontraktor = (select public.ktt_kontraktor()))
  with check (org_id = (select public.ktt_org()) and peran in ('qaqc','produksi') and kontraktor = (select public.ktt_kontraktor()) and role in ('pending','viewer','editor'));
create policy ktt_members_pjo_delete on public.ktt_members for delete to authenticated
  using (org_id = (select public.ktt_org()) and (select public.ktt_org_ok()) and (select public.ktt_peran()) = 'pjo' and (select public.ktt_role()) = 'editor' and peran in ('qaqc','produksi') and kontraktor = (select public.ktt_kontraktor()));
create policy ktt_undangan_pjo_select on public.ktt_undangan for select to authenticated
  using (org_id = (select public.ktt_org()) and (select public.ktt_peran()) = 'pjo' and peran in ('qaqc','produksi') and kontraktor = (select public.ktt_kontraktor()));
create policy ktt_undangan_pjo_insert on public.ktt_undangan for insert to authenticated
  with check (org_id = (select public.ktt_org()) and (select public.ktt_org_ok()) and (select public.ktt_peran()) = 'pjo' and (select public.ktt_role()) = 'editor' and peran in ('qaqc','produksi') and kontraktor = (select public.ktt_kontraktor()) and role in ('viewer','editor'));
create policy ktt_undangan_pjo_update on public.ktt_undangan for update to authenticated
  using (org_id = (select public.ktt_org()) and (select public.ktt_peran()) = 'pjo' and (select public.ktt_role()) = 'editor' and peran in ('qaqc','produksi') and kontraktor = (select public.ktt_kontraktor()))
  with check (org_id = (select public.ktt_org()) and peran in ('qaqc','produksi') and kontraktor = (select public.ktt_kontraktor()) and role in ('viewer','editor'));
create policy ktt_undangan_pjo_delete on public.ktt_undangan for delete to authenticated
  using (org_id = (select public.ktt_org()) and (select public.ktt_peran()) = 'pjo' and (select public.ktt_role()) = 'editor' and peran in ('qaqc','produksi') and kontraktor = (select public.ktt_kontraktor()));
