-- Migrasi v78: perbaikan keamanan
--   1. Berkas (bucket ktt-berkas) hanya terbaca oleh yang berhak membaca datanya.
--   2. Berkas hanya terhapus oleh Direktur Utama/KTT, atau pengunggahnya bila sudah tidak dipakai data mana pun.
--   3. Koleksi, id, dan perusahaan baris ktt_kv tidak bisa diubah (menutup jalan memutar aturan hapus surat).
--   4. Lampiran tidak boleh menempel pada lampiran lain (mencegah rujukan melingkar).
--   5. ID surat hanya huruf, angka, garis bawah, dan tanda hubung (dipakai sebagai nama berkas di server).

create or replace function public.ktt_berkas_dirujuk(p_name text)
returns boolean language sql stable security definer set search_path to '' as $$
  select exists (
    select 1 from public.ktt_kv k
    where k.org_id = public.ktt_org()
      and jsonb_path_exists(k.data, 'strict $.** ? (@ == $p)', jsonb_build_object('p', p_name))
  )
$$;

create or replace function public.ktt_berkas_terbaca(p_name text)
returns boolean language sql stable security definer set search_path to '' as $$
  select exists (
    select 1 from public.ktt_kv k
    where k.org_id = public.ktt_org()
      and case when jsonb_path_exists(k.data, 'strict $.** ? (@ == $p)', jsonb_build_object('p', p_name))
               then public.ktt_kv_boleh('r', k.collection, k.data) else false end
  )
$$;

revoke all on function public.ktt_berkas_dirujuk(text) from public, anon;
revoke all on function public.ktt_berkas_terbaca(text) from public, anon;
grant execute on function public.ktt_berkas_dirujuk(text) to authenticated, service_role;
grant execute on function public.ktt_berkas_terbaca(text) to authenticated, service_role;

drop policy if exists ktt_berkas_baca on storage.objects;
create policy ktt_berkas_baca on storage.objects for select to authenticated
  using (
    bucket_id = 'ktt-berkas'
    and (storage.foldername(name))[1] = (select public.ktt_org())::text
    and (select public.ktt_org_ok())
    and (select public.ktt_role()) <> 'pending'
    and case
          when (select public.ktt_peran()) in ('direktur','ktt') then true
          when owner_id = (select auth.uid())::text then true
          else public.ktt_berkas_terbaca(name)
        end
  );

drop policy if exists ktt_berkas_hapus on storage.objects;
create policy ktt_berkas_hapus on storage.objects for delete to authenticated
  using (
    bucket_id = 'ktt-berkas'
    and (storage.foldername(name))[1] = (select public.ktt_org())::text
    and (select public.ktt_org_ok())
    and (select public.ktt_role()) in ('editor','admin')
    and case
          when (select public.ktt_peran()) in ('direktur','ktt') then true
          when owner_id = (select auth.uid())::text then not public.ktt_berkas_dirujuk(name)
          else false
        end
  );

create or replace function public.ktt_kv_kunci()
returns trigger language plpgsql set search_path to '' as $$
begin
  -- perawatan dari server (tanpa pengguna masuk) tidak dibatasi
  if auth.uid() is null then return new; end if;
  if tg_op = 'UPDATE' and (new.org_id is distinct from old.org_id or new.collection is distinct from old.collection or new.id is distinct from old.id) then
    raise exception 'Jenis, nomor induk, dan perusahaan sebuah data tidak boleh diubah' using errcode = '42501';
  end if;
  if tg_op = 'INSERT' and new.collection = 'surat' and new.id !~ '^[A-Za-z0-9_-]{1,80}$' then
    raise exception 'ID surat tidak valid' using errcode = '22023';
  end if;
  if new.collection = 'berkas' and new.data->>'kol' = 'berkas' then
    raise exception 'Lampiran tidak boleh menempel pada lampiran lain' using errcode = '22023';
  end if;
  return new;
end $$;

revoke all on function public.ktt_kv_kunci() from public, anon, authenticated;

drop trigger if exists ktt_kv_kunci on public.ktt_kv;
create trigger ktt_kv_kunci before insert or update on public.ktt_kv
  for each row execute function public.ktt_kv_kunci();

-- PEMBATALAN (jalankan bila perlu kembali ke keadaan sebelum v78):
--   drop trigger if exists ktt_kv_kunci on public.ktt_kv;
--   drop function if exists public.ktt_kv_kunci();
--   drop policy ktt_berkas_baca on storage.objects;
--   create policy ktt_berkas_baca on storage.objects for select to authenticated
--     using (bucket_id='ktt-berkas' and (storage.foldername(name))[1]=(select public.ktt_org())::text);
--   drop policy ktt_berkas_hapus on storage.objects;
--   create policy ktt_berkas_hapus on storage.objects for delete to authenticated
--     using (bucket_id='ktt-berkas' and (storage.foldername(name))[1]=(select public.ktt_org())::text and (select public.ktt_org_ok()) and (select public.ktt_role()) in ('editor','admin'));
--   drop function if exists public.ktt_berkas_terbaca(text), public.ktt_berkas_dirujuk(text);
