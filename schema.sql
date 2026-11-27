-- =====================================================================
-- TPC2Do – Datenbank-Schema für Supabase (komplett, Stand: alle Funktionen)
-- Supabase-Dashboard → SQL Editor → New query → alles einfügen → Run
--
-- Das ist die EINZIGE Datei, die für eine neue Installation nötig ist.
-- (Du hast schon eine ältere Version laufen? Dann stattdessen nacheinander migration_round9.sql, migration_round10.sql, migration_round11.sql und migration_round12.sql ausführen.)
-- Die SQL-Editor-Einträge ("Snippets") darfst du nach dem Ausführen löschen –
-- die Tabellen/Funktionen bleiben in der Datenbank bestehen.
-- =====================================================================

-- ---------- Tabellen -------------------------------------------------

create table public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  username   text not null,
  avatar     text,                                     -- Profilbild als kleine Data-URL (JPEG/PNG/WebP)
  created_at timestamptz not null default now(),
  constraint username_format check (username ~ '^[A-Za-z0-9_.-]{3,24}$'),
  constraint avatar_format check (avatar is null or (length(avatar) <= 80000 and avatar ~ '^data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$'))
);
create unique index profiles_username_lower_idx on public.profiles (lower(username));

create table public.lists (
  id          uuid primary key default gen_random_uuid(),
  owner_id    uuid not null default auth.uid() references auth.users(id) on delete cascade,
  title       text not null default 'Neue Liste',
  columns     jsonb not null default '[]'::jsonb,      -- eigene Spalten: [{id,name,type}]
  link_role   text not null default 'none' check (link_role in ('none','view','edit')),
  share_token uuid not null default gen_random_uuid(), -- geheimer Token für den Teilen-Link
  link_subs   boolean not null default false,          -- Beitritt per Link gibt auch die verknüpften Unterlisten frei
  public_view boolean not null default false,          -- (Beta) schreibgeschützte Ansicht ohne Login unter #/view/<token>
  created_at  timestamptz not null default now()
);
create unique index lists_share_token_idx on public.lists (share_token);
create index lists_owner_idx on public.lists (owner_id);

create table public.list_members (
  list_id uuid not null references public.lists(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role    text not null check (role in ('view','edit')),
  primary key (list_id, user_id)
);
create index list_members_user_idx on public.list_members (user_id);

create table public.tasks (
  id          uuid primary key default gen_random_uuid(),
  list_id     uuid not null references public.lists(id) on delete cascade,
  done        boolean not null default false,
  title       text not null default '',
  notes       text not null default '',
  sub_list_id uuid references public.lists(id) on delete set null,
  data        jsonb not null default '{}'::jsonb,       -- Werte der eigenen Spalten {spaltenId: wert}
  position    double precision not null default 0,
  created_at  timestamptz not null default now(),
  done_at     timestamptz
);
create index tasks_list_idx on public.tasks (list_id, done, position);

-- ---------- Profil automatisch beim Registrieren anlegen --------------

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, username)
  values (new.id, coalesce(new.raw_user_meta_data->>'username', 'user_' || substr(new.id::text, 1, 8)));
  return new;
end $$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------- Hilfsfunktionen für die Rechte ---------------------------

create or replace function public.is_list_owner(lid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.lists l where l.id = lid and l.owner_id = auth.uid());
$$;

create or replace function public.is_list_member(lid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.list_members m where m.list_id = lid and m.user_id = auth.uid());
$$;

create or replace function public.can_view_list(lid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_list_owner(lid)
      or exists (select 1 from public.list_members m where m.list_id = lid and m.user_id = auth.uid());
$$;

create or replace function public.can_edit_list(lid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_list_owner(lid)
      or exists (select 1 from public.list_members m
                 where m.list_id = lid and m.user_id = auth.uid() and m.role = 'edit');
$$;

-- ---------- RPCs (Funktionen, die der Client aufruft) ----------------

-- Ist der Konto-Name noch frei? (auch ohne Login aufrufbar, für die Registrierung)
create or replace function public.username_available(uname text) returns boolean
language sql stable security definer set search_path = public as $$
  select not exists (select 1 from public.profiles where lower(username) = lower(trim(uname)));
$$;

-- Alle (auch verschachtelten) verknüpften Unterlisten einer Liste, die dem Aufrufer gehören
create or replace function public.owned_sublists(lid uuid) returns setof uuid
language sql stable security definer set search_path = public as $$
  with recursive s(id) as (
    select t.sub_list_id from public.tasks t where t.list_id = lid and t.sub_list_id is not null
    union
    select t.sub_list_id from public.tasks t join s on t.list_id = s.id where t.sub_list_id is not null
  )
  select l.id from s join public.lists l on l.id = s.id where l.owner_id = auth.uid() and l.id <> lid;
$$;

-- Liste mit einem Konto (per Konto-Name) teilen – nur Besitzer; optional inkl. Unterlisten
create or replace function public.share_with_username(lid uuid, uname text, r text, subs boolean default false) returns void
language plpgsql security definer set search_path = public as $$
declare target uuid; sid uuid;
begin
  if not public.is_list_owner(lid) then
    raise exception 'Nur der Besitzer kann diese Liste teilen.';
  end if;
  if r not in ('view','edit') then
    raise exception 'Ungültige Berechtigung.';
  end if;
  select id into target from public.profiles where lower(username) = lower(trim(uname));
  if target is null then
    raise exception 'Konto "%" wurde nicht gefunden.', trim(uname);
  end if;
  if target = auth.uid() then
    raise exception 'Das ist dein eigenes Konto.';
  end if;
  insert into public.list_members (list_id, user_id, role) values (lid, target, r)
  on conflict (list_id, user_id) do update set role = excluded.role;
  if subs then
    for sid in select public.owned_sublists(lid) loop
      insert into public.list_members (list_id, user_id, role) values (sid, target, r)
      on conflict (list_id, user_id) do update
        set role = case when public.list_members.role = 'edit' or excluded.role = 'edit' then 'edit' else 'view' end;
    end loop;
  end if;
end $$;

-- Über Teilen-Link beitreten (Berechtigung = link_role der Liste, nie eine Herabstufung)
create or replace function public.join_list_by_token(tok uuid) returns uuid
language plpgsql security definer set search_path = public as $$
declare l public.lists%rowtype;
begin
  if auth.uid() is null then
    raise exception 'Nicht angemeldet.';
  end if;
  select * into l from public.lists where share_token = tok and link_role <> 'none';
  if not found then
    raise exception 'Link ungültig oder Freigabe deaktiviert.';
  end if;
  if l.owner_id <> auth.uid() then
    insert into public.list_members (list_id, user_id, role) values (l.id, auth.uid(), l.link_role)
    on conflict (list_id, user_id) do update
      set role = case when public.list_members.role = 'edit' or excluded.role = 'edit' then 'edit' else 'view' end;
    if l.link_subs then          -- verknüpfte Unterlisten des Besitzers ebenfalls (mit derselben Berechtigung)
      insert into public.list_members (list_id, user_id, role)
        select s.id, auth.uid(), l.link_role
        from (with recursive s(id) as (
                select t.sub_list_id from public.tasks t where t.list_id = l.id and t.sub_list_id is not null
                union
                select t.sub_list_id from public.tasks t join s on t.list_id = s.id where t.sub_list_id is not null)
              select x.id from s join public.lists x on x.id = s.id where x.owner_id = l.owner_id and x.id <> l.id) s
      on conflict (list_id, user_id) do update
        set role = case when public.list_members.role = 'edit' or excluded.role = 'edit' then 'edit' else 'view' end;
    end if;
  end if;
  return l.id;
end $$;

-- Eigene Spalten ändern (Besitzer + Bearbeiter)
create or replace function public.set_list_columns(lid uuid, cols jsonb) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.can_edit_list(lid) then
    raise exception 'Keine Berechtigung zum Bearbeiten.';
  end if;
  if jsonb_typeof(cols) <> 'array' then
    raise exception 'Ungültige Spalten.';
  end if;
  update public.lists set columns = cols where id = lid;
end $$;

-- Teilen-Token auslesen / neu erzeugen – nur Besitzer
create or replace function public.get_share_token(lid uuid) returns uuid
language plpgsql security definer set search_path = public as $$
declare t uuid;
begin
  if not public.is_list_owner(lid) then
    raise exception 'Nur der Besitzer kann den Link sehen.';
  end if;
  select share_token into t from public.lists where id = lid;
  return t;
end $$;

create or replace function public.rotate_share_token(lid uuid) returns uuid
language plpgsql security definer set search_path = public as $$
declare t uuid := gen_random_uuid();
begin
  if not public.is_list_owner(lid) then
    raise exception 'Nur der Besitzer kann den Link ändern.';
  end if;
  update public.lists set share_token = t where id = lid;
  return t;
end $$;

-- Anmeldung per Konto-Name: liefert die E-Mail zu einem Konto-Namen (nötig, weil Supabase nur mit E-Mail anmeldet).
-- Hinweis: Wer einen Konto-Namen kennt, kann damit die zugehörige E-Mail abfragen.
create or replace function public.login_email(uname text) returns text
language sql stable security definer set search_path = public, auth as $$
  select u.email::text from public.profiles p join auth.users u on u.id = p.id
  where lower(p.username) = lower(trim(uname)) limit 1;
$$;

-- (Beta) Öffentliche, schreibgeschützte Ansicht einer Liste anhand ihres Tokens (ohne Login)
create or replace function public.get_public_list(tok uuid) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('title', l.title, 'columns', l.columns,
    'tasks', coalesce((select jsonb_agg(jsonb_build_object('id', t.id, 'done', t.done, 'title', t.title, 'notes', t.notes, 'data', t.data)
                       order by t.done, t.position) from public.tasks t where t.list_id = l.id), '[]'::jsonb))
  from public.lists l where l.share_token = tok and l.public_view;
$$;

-- Funktionsrechte: nur angemeldete Nutzer (username_available auch anonym)
revoke all on function public.is_list_owner(uuid), public.is_list_member(uuid), public.can_view_list(uuid), public.can_edit_list(uuid),
  public.username_available(text), public.share_with_username(uuid, text, text, boolean), public.owned_sublists(uuid),
  public.join_list_by_token(uuid), public.set_list_columns(uuid, jsonb),
  public.get_share_token(uuid), public.rotate_share_token(uuid), public.login_email(text), public.get_public_list(uuid)
  from public, anon, authenticated;

grant execute on function public.is_list_owner(uuid), public.is_list_member(uuid), public.can_view_list(uuid), public.can_edit_list(uuid),
  public.share_with_username(uuid, text, text, boolean), public.owned_sublists(uuid), public.join_list_by_token(uuid),
  public.set_list_columns(uuid, jsonb), public.get_share_token(uuid), public.rotate_share_token(uuid)
  to authenticated;
grant execute on function public.username_available(text), public.login_email(text), public.get_public_list(uuid) to anon, authenticated;

-- ---------- Row Level Security ---------------------------------------

alter table public.profiles     enable row level security;
alter table public.lists        enable row level security;
alter table public.list_members enable row level security;
alter table public.tasks        enable row level security;

-- profiles: angemeldete Nutzer sehen Konto-Namen (nötig zum Teilen), ändern nur ihren eigenen
create policy profiles_select on public.profiles for select to authenticated using (true);
create policy profiles_update on public.profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());

-- lists
create policy lists_select on public.lists for select to authenticated
  using (owner_id = auth.uid() or public.is_list_member(id));
create policy lists_insert on public.lists for insert to authenticated with check (owner_id = auth.uid());
create policy lists_update on public.lists for update to authenticated
  using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy lists_delete on public.lists for delete to authenticated using (owner_id = auth.uid());

-- list_members (Einfügen nur über die RPCs oben)
create policy members_select on public.list_members for select to authenticated
  using (user_id = auth.uid() or public.is_list_owner(list_id));
create policy members_update on public.list_members for update to authenticated
  using (public.is_list_owner(list_id)) with check (public.is_list_owner(list_id));
create policy members_delete on public.list_members for delete to authenticated
  using (public.is_list_owner(list_id) or user_id = auth.uid());

-- tasks
create policy tasks_select on public.tasks for select to authenticated using (public.can_view_list(list_id));
create policy tasks_insert on public.tasks for insert to authenticated with check (public.can_edit_list(list_id));
create policy tasks_update on public.tasks for update to authenticated
  using (public.can_edit_list(list_id)) with check (public.can_edit_list(list_id));
create policy tasks_delete on public.tasks for delete to authenticated using (public.can_edit_list(list_id));

-- ---------- Tabellenrechte (Spalten-Rechte verstecken den share_token) --

revoke all on public.profiles, public.lists, public.list_members, public.tasks from anon, authenticated;

grant select on public.profiles to authenticated;
grant update (username, avatar) on public.profiles to authenticated;

grant select (id, owner_id, title, columns, link_role, link_subs, public_view, created_at) on public.lists to authenticated;
grant insert (id, owner_id, title, columns, link_role) on public.lists to authenticated;
grant update (title, columns, link_role, link_subs, public_view) on public.lists to authenticated;
grant delete on public.lists to authenticated;

grant select on public.list_members to authenticated;
grant update (role) on public.list_members to authenticated;
grant delete on public.list_members to authenticated;

grant select, insert, update, delete on public.tasks to authenticated;


-- Live updates (Realtime) for tasks (not for lists: share_token must not leak via Realtime)
do $$ begin
  alter publication supabase_realtime add table public.tasks;
exception when duplicate_object then null;
end $$;

-- ---------------------------------------------------------------------
-- Verknüpfte Konten: zwei eigene Konten teilen automatisch alle Listen (beide dürfen bearbeiten).
-- Verknüpfen läuft über ein kurzlebiges Token: Konto B meldet sich in der App kurz an und erzeugt es,
-- Konto A löst es ein. So werden Passwörter nie an eigene Funktionen geschickt.
-- ---------------------------------------------------------------------
create table if not exists public.account_links (
  user_id   uuid not null references public.profiles(id) on delete cascade,
  linked_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (user_id, linked_id)
);
alter table public.account_links enable row level security;
drop policy if exists account_links_select on public.account_links;
create policy account_links_select on public.account_links for select to authenticated using (user_id = auth.uid());
revoke all on public.account_links from anon, authenticated;
grant select on public.account_links to authenticated;

create table if not exists public.link_tokens (
  token      uuid primary key default gen_random_uuid(),
  user_id    uuid not null references public.profiles(id) on delete cascade,
  expires_at timestamptz not null default now() + interval '5 minutes'
);
alter table public.link_tokens enable row level security;     -- keine Policy, kein Grant: nur über Funktionen erreichbar
revoke all on public.link_tokens from anon, authenticated;

create or replace function public.make_link_token() returns uuid
language plpgsql security definer set search_path = public as $$
declare t uuid;
begin
  if auth.uid() is null then raise exception 'Nicht angemeldet.'; end if;
  delete from public.link_tokens where user_id = auth.uid() or expires_at < now();
  insert into public.link_tokens (user_id) values (auth.uid()) returning token into t;
  return t;
end $$;

-- gegenseitig alle eigenen Listen als "bearbeiten"-Mitglied eintragen
create or replace function public.link_sync_lists(a uuid, b uuid) returns void
language sql security definer set search_path = public as $$
  insert into public.list_members (list_id, user_id, role)
    select l.id, b, 'edit' from public.lists l where l.owner_id = a
  on conflict (list_id, user_id) do update set role = 'edit';
  insert into public.list_members (list_id, user_id, role)
    select l.id, a, 'edit' from public.lists l where l.owner_id = b
  on conflict (list_id, user_id) do update set role = 'edit';
$$;

create or replace function public.link_accounts(tok uuid) returns uuid
language plpgsql security definer set search_path = public as $$
declare other uuid;
begin
  if auth.uid() is null then raise exception 'Nicht angemeldet.'; end if;
  select user_id into other from public.link_tokens where token = tok and expires_at > now();
  if other is null then raise exception 'Der Verknüpfungs-Code ist ungültig oder abgelaufen.'; end if;
  if other = auth.uid() then raise exception 'Das ist dasselbe Konto.'; end if;
  delete from public.link_tokens where token = tok;
  insert into public.account_links (user_id, linked_id) values (auth.uid(), other), (other, auth.uid()) on conflict do nothing;
  perform public.link_sync_lists(auth.uid(), other);
  return other;
end $$;

create or replace function public.my_links() returns table (id uuid, username text, avatar text)
language sql stable security definer set search_path = public as $$
  select p.id, p.username, p.avatar from public.account_links k join public.profiles p on p.id = k.linked_id where k.user_id = auth.uid();
$$;

-- Verknüpfung lösen: auch die dadurch entstandenen gegenseitigen Mitgliedschaften entfernen
create or replace function public.unlink_account(other uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.account_links where user_id = auth.uid() and linked_id = other) then return; end if;
  delete from public.account_links where (user_id = auth.uid() and linked_id = other) or (user_id = other and linked_id = auth.uid());
  delete from public.list_members m using public.lists l where m.list_id = l.id
    and ((l.owner_id = other and m.user_id = auth.uid()) or (l.owner_id = auth.uid() and m.user_id = other));
end $$;

-- neue Listen eines verknüpften Kontos sofort für alle Verknüpften eintragen
create or replace function public.link_new_list() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.list_members (list_id, user_id, role)
    select new.id, k.linked_id, 'edit' from public.account_links k where k.user_id = new.owner_id
  on conflict (list_id, user_id) do nothing;
  return new;
end $$;
drop trigger if exists link_new_list on public.lists;
create trigger link_new_list after insert on public.lists for each row execute function public.link_new_list();

revoke all on function public.make_link_token(), public.link_sync_lists(uuid, uuid), public.link_accounts(uuid), public.my_links(), public.unlink_account(uuid), public.link_new_list() from public, anon, authenticated;
grant execute on function public.make_link_token(), public.link_accounts(uuid), public.my_links(), public.unlink_account(uuid) to authenticated;

-- ---------------------------------------------------------------------
-- Runde 11: Admin-Rolle, volle Rechte für verknüpfte Konten, verschlüsselte Listen
-- ---------------------------------------------------------------------
alter table public.list_members drop constraint if exists list_members_role_check;
alter table public.list_members add constraint list_members_role_check check (role in ('view','edit','admin'));
alter table public.lists add column if not exists enc jsonb;           -- Ende-zu-Ende-Verschlüsselung: Salt, Prüfwert, verschlüsselter Titel/Spalten (nie der Schlüssel)

-- Besitzer = eigene Liste ODER Liste eines verknüpften Kontos (volle Rechte: teilen, löschen, ...)
create or replace function public.is_list_owner(lid uuid) returns boolean
language plpgsql stable security definer set search_path = public as $$
begin
  return exists (select 1 from public.lists l where l.id = lid
    and (l.owner_id = auth.uid()
         or exists (select 1 from public.account_links k where k.user_id = auth.uid() and k.linked_id = l.owner_id)));
end $$;

-- Verwalten = Besitzer oder Admin-Mitglied (teilen, umbenennen, Spalten, Link; Löschen bleibt dem Besitzer)
create or replace function public.can_manage_list(lid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_list_owner(lid)
      or exists (select 1 from public.list_members m where m.list_id = lid and m.user_id = auth.uid() and m.role = 'admin');
$$;

create or replace function public.can_edit_list(lid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_list_owner(lid)
      or exists (select 1 from public.list_members m
                 where m.list_id = lid and m.user_id = auth.uid() and m.role in ('edit','admin'));
$$;

create or replace function public.role_max(a text, b text) returns text
language sql immutable set search_path = public as $$
  select case when a = 'admin' or b = 'admin' then 'admin' when a = 'edit' or b = 'edit' then 'edit' else 'view' end;
$$;

create or replace function public.owned_sublists(lid uuid) returns setof uuid
language sql stable security definer set search_path = public as $$
  with recursive s(id) as (
    select t.sub_list_id from public.tasks t where t.list_id = lid and t.sub_list_id is not null
    union
    select t.sub_list_id from public.tasks t join s on t.list_id = s.id where t.sub_list_id is not null
  )
  select l.id from s join public.lists l on l.id = s.id where public.can_manage_list(l.id) and l.id <> lid;
$$;

create or replace function public.share_with_username(lid uuid, uname text, r text, subs boolean default false) returns void
language plpgsql security definer set search_path = public as $$
declare target uuid; sid uuid;
begin
  if not public.can_manage_list(lid) then
    raise exception 'Nur Besitzer oder Admins können diese Liste teilen.';
  end if;
  if r not in ('view','edit','admin') then
    raise exception 'Ungültige Berechtigung.';
  end if;
  select id into target from public.profiles where lower(username) = lower(trim(uname));
  if target is null then
    raise exception 'Konto "%" wurde nicht gefunden.', trim(uname);
  end if;
  if target = auth.uid() then
    raise exception 'Das ist dein eigenes Konto.';
  end if;
  if exists (select 1 from public.lists where id = lid and owner_id = target) then
    raise exception 'Das ist der Besitzer der Liste.';
  end if;
  insert into public.list_members (list_id, user_id, role) values (lid, target, r)
  on conflict (list_id, user_id) do update set role = excluded.role;
  if subs then
    for sid in select public.owned_sublists(lid) loop
      insert into public.list_members (list_id, user_id, role) values (sid, target, r)
      on conflict (list_id, user_id) do update set role = public.role_max(public.list_members.role, excluded.role);
    end loop;
  end if;
end $$;

create or replace function public.join_list_by_token(tok uuid) returns uuid
language plpgsql security definer set search_path = public as $$
declare l public.lists%rowtype;
begin
  if auth.uid() is null then
    raise exception 'Nicht angemeldet.';
  end if;
  select * into l from public.lists where share_token = tok and link_role <> 'none';
  if not found then
    raise exception 'Link ungültig oder Freigabe deaktiviert.';
  end if;
  if l.owner_id <> auth.uid() then
    insert into public.list_members (list_id, user_id, role) values (l.id, auth.uid(), l.link_role)
    on conflict (list_id, user_id) do update set role = public.role_max(public.list_members.role, excluded.role);
    if l.link_subs then          -- verknüpfte Unterlisten des Besitzers ebenfalls (mit derselben Berechtigung)
      insert into public.list_members (list_id, user_id, role)
        select s.id, auth.uid(), l.link_role
        from (with recursive s(id) as (
                select t.sub_list_id from public.tasks t where t.list_id = l.id and t.sub_list_id is not null
                union
                select t.sub_list_id from public.tasks t join s on t.list_id = s.id where t.sub_list_id is not null)
              select x.id from s join public.lists x on x.id = s.id where x.owner_id = l.owner_id and x.id <> l.id) s
      on conflict (list_id, user_id) do update set role = public.role_max(public.list_members.role, excluded.role);
    end if;
  end if;
  return l.id;
end $$;

create or replace function public.get_share_token(lid uuid) returns uuid
language plpgsql security definer set search_path = public as $$
declare t uuid;
begin
  if not public.can_manage_list(lid) then
    raise exception 'Nur Besitzer oder Admins können den Link sehen.';
  end if;
  select share_token into t from public.lists where id = lid;
  return t;
end $$;

create or replace function public.rotate_share_token(lid uuid) returns uuid
language plpgsql security definer set search_path = public as $$
declare t uuid := gen_random_uuid();
begin
  if not public.can_manage_list(lid) then
    raise exception 'Nur Besitzer oder Admins können den Link ändern.';
  end if;
  update public.lists set share_token = t where id = lid;
  return t;
end $$;

-- Verschlüsselte Listen: der Server speichert nur Chiffretext (Salt/Prüfwert/Titel/Spalten in "enc")
create or replace function public.enable_list_enc(lid uuid, e jsonb, ph_title text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.can_manage_list(lid) then raise exception 'Keine Berechtigung.'; end if;
  if jsonb_typeof(e) <> 'object' or not (e ? 'v') then raise exception 'Ungültige Verschlüsselungsdaten.'; end if;
  update public.lists set enc = e, title = coalesce(nullif(ph_title, ''), '🔒'), columns = '[]'::jsonb, public_view = false where id = lid;
end $$;

create or replace function public.set_list_enc(lid uuid, e jsonb) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.can_edit_list(lid) then raise exception 'Keine Berechtigung zum Bearbeiten.'; end if;
  if jsonb_typeof(e) <> 'object' or not (e ? 'v') then raise exception 'Ungültige Verschlüsselungsdaten.'; end if;
  if not exists (select 1 from public.lists where id = lid and enc is not null) then raise exception 'Liste ist nicht verschlüsselt.'; end if;
  update public.lists set enc = e where id = lid;
end $$;

create or replace function public.disable_list_enc(lid uuid, new_title text, cols jsonb) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.can_manage_list(lid) then raise exception 'Keine Berechtigung.'; end if;
  if jsonb_typeof(cols) <> 'array' then raise exception 'Ungültige Spalten.'; end if;
  update public.lists set enc = null, title = coalesce(nullif(new_title, ''), 'Liste'), columns = cols where id = lid;
end $$;

-- öffentliche Ansicht: nie für verschlüsselte Listen
create or replace function public.get_public_list(tok uuid) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('title', l.title, 'columns', l.columns,
    'tasks', coalesce((select jsonb_agg(jsonb_build_object('id', t.id, 'done', t.done, 'title', t.title, 'notes', t.notes, 'data', t.data)
                       order by t.done, t.position) from public.tasks t where t.list_id = l.id), '[]'::jsonb))
  from public.lists l where l.share_token = tok and l.public_view and l.enc is null;
$$;

-- Rechte (Policies) auf can_manage/is_list_owner umstellen
drop policy if exists lists_update on public.lists;
create policy lists_update on public.lists for update to authenticated
  using (public.can_manage_list(id)) with check (public.can_manage_list(id));
drop policy if exists lists_delete on public.lists;
create policy lists_delete on public.lists for delete to authenticated using (public.is_list_owner(id));
drop policy if exists members_select on public.list_members;
create policy members_select on public.list_members for select to authenticated
  using (user_id = auth.uid() or public.can_manage_list(list_id));
drop policy if exists members_update on public.list_members;
create policy members_update on public.list_members for update to authenticated
  using (public.can_manage_list(list_id)) with check (public.can_manage_list(list_id));
drop policy if exists members_delete on public.list_members;
create policy members_delete on public.list_members for delete to authenticated
  using (public.can_manage_list(list_id) or user_id = auth.uid());

revoke all on function public.can_manage_list(uuid), public.role_max(text, text), public.enable_list_enc(uuid, jsonb, text),
  public.set_list_enc(uuid, jsonb), public.disable_list_enc(uuid, text, jsonb) from public, anon, authenticated;
grant execute on function public.can_manage_list(uuid), public.role_max(text, text), public.enable_list_enc(uuid, jsonb, text),
  public.set_list_enc(uuid, jsonb), public.disable_list_enc(uuid, text, jsonb) to authenticated;
revoke all on function public.get_public_list(uuid) from public;
grant execute on function public.get_public_list(uuid) to anon, authenticated;
grant select (id, owner_id, title, columns, link_role, link_subs, public_view, enc, created_at) on public.lists to authenticated;

-- Der frühere Google-Sheets/Apps-Script-Sync ist entfernt. Falls du ihn je installiert hattest: remigration.sql ausführen.

-- ---------- Runde 12: automatische Ende-zu-Ende-Verschlüsselung ----------

alter table public.profiles add column if not exists pubkey text;
alter table public.profiles drop constraint if exists pubkey_format;
alter table public.profiles add constraint pubkey_format check (pubkey is null or (length(pubkey) <= 200 and pubkey ~ '^[A-Za-z0-9+/=]+$'));

-- privater Schlüssel jedes Kontos, verpackt mit Passwort und Wiederherstellungscode (der Server kann ihn nicht lesen)
create table if not exists public.user_keys (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  bundle     jsonb not null,
  updated_at timestamptz not null default now()
);
alter table public.user_keys enable row level security;
drop policy if exists user_keys_select on public.user_keys;
drop policy if exists user_keys_insert on public.user_keys;
drop policy if exists user_keys_update on public.user_keys;
create policy user_keys_select on public.user_keys for select to authenticated using (user_id = auth.uid());
create policy user_keys_insert on public.user_keys for insert to authenticated with check (user_id = auth.uid());
create policy user_keys_update on public.user_keys for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
revoke all on public.user_keys from anon, authenticated;
grant select, insert, update on public.user_keys to authenticated;

-- Listenschlüssel, je Mitglied mit dessen öffentlichem Schlüssel verpackt
create table if not exists public.list_keys (
  list_id uuid not null references public.lists(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  wrapped text not null check (length(wrapped) <= 2000),
  primary key (list_id, user_id)
);
alter table public.list_keys enable row level security;
drop policy if exists list_keys_select on public.list_keys;
create policy list_keys_select on public.list_keys for select to authenticated using (user_id = auth.uid());
revoke all on public.list_keys from anon, authenticated;
grant select on public.list_keys to authenticated;

create or replace function public.list_keys_cleanup() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  delete from public.list_keys where list_id = old.list_id and user_id = old.user_id;
  return old;
end $$;
drop trigger if exists list_keys_cleanup on public.list_members;
create trigger list_keys_cleanup after delete on public.list_members for each row execute function public.list_keys_cleanup();

create or replace function public.set_my_pubkey(pk text) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.profiles set pubkey = pk where id = auth.uid() and pubkey is null;
end $$;

-- Notausgang: neues Schlüsselpaar (alte verschlüsselte Listen werden für dieses Konto unlesbar)
create or replace function public.reset_my_keys(pk text) returns void
language plpgsql security definer set search_path = public as $$
begin
  delete from public.list_keys where user_id = auth.uid();
  delete from public.user_keys where user_id = auth.uid();
  update public.profiles set pubkey = pk where id = auth.uid();
end $$;

create or replace function public.put_list_key(lid uuid, uid uuid, wrapped text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'Nicht angemeldet.'; end if;
  if not exists (select 1 from public.lists l where l.id = lid and (l.owner_id = uid or exists (select 1 from public.list_members m where m.list_id = lid and m.user_id = uid))) then
    raise exception 'Kein Mitglied dieser Liste.'; end if;
  if uid <> auth.uid() and not public.can_manage_list(lid) then raise exception 'Keine Berechtigung.'; end if;
  insert into public.list_keys (list_id, user_id, wrapped) values (lid, uid, wrapped)
  on conflict (list_id, user_id) do update set wrapped = excluded.wrapped;
end $$;

create or replace function public.create_enc_list(e jsonb, wrapped text) returns uuid
language plpgsql security definer set search_path = public as $$
declare nid uuid;
begin
  if auth.uid() is null then raise exception 'Nicht angemeldet.'; end if;
  if jsonb_typeof(e) <> 'object' or (e->>'v') <> '2' then raise exception 'Ungültige Verschlüsselungsdaten.'; end if;
  insert into public.lists (owner_id, title, enc) values (auth.uid(), '🔒', e) returning id into nid;
  insert into public.list_keys (list_id, user_id, wrapped) values (nid, auth.uid(), wrapped);
  return nid;
end $$;

-- bestehende (unverschlüsselte oder alt verschlüsselte) Liste auf das neue Verfahren umstellen
create or replace function public.convert_list_enc(lid uuid, e jsonb, wrapped text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.can_manage_list(lid) then raise exception 'Keine Berechtigung.'; end if;
  if jsonb_typeof(e) <> 'object' or (e->>'v') <> '2' then raise exception 'Ungültige Verschlüsselungsdaten.'; end if;
  update public.lists set enc = e, title = '🔒', columns = '[]'::jsonb where id = lid;
  insert into public.list_keys (list_id, user_id, wrapped) values (lid, auth.uid(), wrapped)
  on conflict (list_id, user_id) do update set wrapped = excluded.wrapped;
end $$;

-- Mitglieder, für die noch kein Listenschlüssel hinterlegt ist (der Verwaltende verpackt ihn beim nächsten Öffnen)
create or replace function public.keyless_members() returns table (list_id uuid, user_id uuid, pubkey text)
language sql stable security definer set search_path = public as $$
  select l.id, u.uid, p.pubkey
  from public.lists l
  cross join lateral (select l.owner_id as uid union select m.user_id from public.list_members m where m.list_id = l.id) u
  join public.profiles p on p.id = u.uid
  where l.enc is not null and (l.enc->>'v') = '2' and p.pubkey is not null and u.uid <> auth.uid()
    and public.can_manage_list(l.id)
    and not exists (select 1 from public.list_keys k where k.list_id = l.id and k.user_id = u.uid);
$$;

-- öffentliche Ansicht: auch für verschlüsselte Listen (der Schlüssel steckt im Link hinter dem #, der Server sieht ihn nie)
create or replace function public.get_public_list(tok uuid) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('title', l.title, 'columns', l.columns, 'enc', l.enc,
    'tasks', coalesce((select jsonb_agg(jsonb_build_object('id', t.id, 'done', t.done, 'title', t.title, 'notes', t.notes, 'data', t.data)
                       order by t.done, t.position) from public.tasks t where t.list_id = l.id), '[]'::jsonb))
  from public.lists l where l.share_token = tok and l.public_view;
$$;

revoke all on function public.set_my_pubkey(text), public.reset_my_keys(text), public.put_list_key(uuid, uuid, text), public.create_enc_list(jsonb, text),
  public.convert_list_enc(uuid, jsonb, text), public.keyless_members() from public;
grant execute on function public.set_my_pubkey(text), public.reset_my_keys(text), public.put_list_key(uuid, uuid, text), public.create_enc_list(jsonb, text),
  public.convert_list_enc(uuid, jsonb, text), public.keyless_members() to authenticated;
revoke all on function public.get_public_list(uuid) from public;
grant execute on function public.get_public_list(uuid) to anon, authenticated;

-- Runde 12b (siehe migration_round12b.sql)

create or replace function public.disable_list_enc(lid uuid, new_title text, cols jsonb) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.can_manage_list(lid) then raise exception 'Keine Berechtigung.'; end if;
  if jsonb_typeof(cols) <> 'array' then raise exception 'Ungültige Spalten.'; end if;
  update public.lists set enc = null, title = coalesce(nullif(new_title, ''), 'Liste'), columns = cols where id = lid;
  delete from public.list_keys where list_id = lid;
end $$;

create or replace function public.convert_list_enc(lid uuid, e jsonb, wrapped text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.can_manage_list(lid) then raise exception 'Keine Berechtigung.'; end if;
  if jsonb_typeof(e) <> 'object' or (e->>'v') <> '2' then raise exception 'Ungültige Verschlüsselungsdaten.'; end if;
  update public.lists set enc = e, title = '🔒', columns = '[]'::jsonb where id = lid;
  delete from public.list_keys where list_id = lid and user_id <> auth.uid();
  insert into public.list_keys (list_id, user_id, wrapped) values (lid, auth.uid(), wrapped)
  on conflict (list_id, user_id) do update set wrapped = excluded.wrapped;
end $$;

revoke all on function public.disable_list_enc(uuid, text, jsonb), public.convert_list_enc(uuid, jsonb, text) from public, anon;
grant execute on function public.disable_list_enc(uuid, text, jsonb), public.convert_list_enc(uuid, jsonb, text) to authenticated;
