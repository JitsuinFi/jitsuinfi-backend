-- The owner's sealed state, one per mailbox (HNK-25.T2, BL-D26-03): a buyer's history chain kept
-- across devices. Sealed to the mailbox's own key in the browser; the relay sees only its size.
create table if not exists relay_state (
  mailbox_id  text primary key references relay_mailboxes(mailbox_id) on delete cascade,
  ciphertext  bytea not null,
  size        integer not null,
  updated_at  timestamptz not null
);

alter table relay_state enable row level security;
