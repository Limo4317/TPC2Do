-- =====================================================================
-- TPC2Do – Datenbank-Schema für Supabase (komplett, Stand: alle Funktionen)
-- Supabase-Dashboard → SQL Editor → New query → alles einfügen → Run
--
-- Das ist die EINZIGE Datei, die für eine neue Installation nötig ist.
-- (Du hast schon eine ältere Version laufen? Dann stattdessen migration_round9.sql ausführen.)
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

-- Der frühere Google-Sheets/Apps-Script-Sync ist entfernt. Falls du ihn je installiert hattest: remigration.sql ausführen.
