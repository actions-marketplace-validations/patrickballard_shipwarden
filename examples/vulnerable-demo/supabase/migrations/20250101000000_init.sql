-- A typical AI-generated schema with the classic mistakes.
create table public.profiles (
  id uuid primary key references auth.users,
  full_name text,
  phone text
);

create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users,
  total numeric
);
alter table public.orders enable row level security;

create policy "Users can view own orders" on public.orders for select using (auth.uid() = user_id);
create policy "System can manage orders" on public.orders for all using (true);
