create table if not exists secrets (
    id integer primary key,
    ciphertext varchar(255) not null,
    enc_key blob not null
);