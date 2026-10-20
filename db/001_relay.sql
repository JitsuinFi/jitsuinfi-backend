-- Relay tables (HNK-23.T4, D-33). Only what the relay needs: no IP, no sender, no content.
create table if not exists relay_mailboxes (
  mailbox_id  text primary key check (mailbox_id ~ '^[0-9a-f]{64}$'),
  mailbox_pk  bytea not null unique check (octet_length(mailbox_pk) = 32),
  created_at  timestamptz not null default now()
);

create table if not exists relay_messages (
  id          uuid primary key,
  mailbox_id  text not null references relay_mailboxes(mailbox_id) on delete cascade,
  ciphertext  bytea not null,
  size        integer not null,
  received_at timestamptz not null,
  expires_at  timestamptz not null
);
create index if not exists relay_messages_box on relay_messages (mailbox_id, received_at);
create index if not exists relay_messages_expiry on relay_messages (expires_at);

create table if not exists relay_challenges (
  id          uuid primary key,
  mailbox_pk  bytea not null,
  purpose     text not null check (purpose in ('register', 'read')),
  eph_secret  bytea not null,
  eph_public  bytea not null,
  nonce       bytea not null,
  expires_at  timestamptz not null
);

create table if not exists relay_read_tokens (
  token_hash  text primary key,
  mailbox_id  text not null references relay_mailboxes(mailbox_id) on delete cascade,
  expires_at  timestamptz not null
);

-- The browser never talks to the database (D-33): no Supabase API access to these tables.
alter table relay_mailboxes enable row level security;
alter table relay_messages enable row level security;
alter table relay_challenges enable row level security;
alter table relay_read_tokens enable row level security;
