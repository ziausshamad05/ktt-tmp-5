-- Migrasi v77: bucket privat ktt-berkas untuk gambar dan lampiran, akses per perusahaan
insert into storage.buckets (id, name, public, file_size_limit) values ('ktt-berkas','ktt-berkas',false,5242880) on conflict (id) do nothing;
create policy ktt_berkas_baca on storage.objects for select to authenticated
  using (bucket_id='ktt-berkas' and (storage.foldername(name))[1]=(select public.ktt_org())::text);
create policy ktt_berkas_tambah on storage.objects for insert to authenticated
  with check (bucket_id='ktt-berkas' and (storage.foldername(name))[1]=(select public.ktt_org())::text and (select public.ktt_org_ok()) and (select public.ktt_role()) in ('editor','admin'));
create policy ktt_berkas_hapus on storage.objects for delete to authenticated
  using (bucket_id='ktt-berkas' and (storage.foldername(name))[1]=(select public.ktt_org())::text and (select public.ktt_org_ok()) and (select public.ktt_role()) in ('editor','admin'));
