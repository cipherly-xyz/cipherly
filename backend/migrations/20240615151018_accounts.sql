create table if not exists accounts (
    id integer primary key,
    username varchar(255) not null unique,
    public_key blob not null
);