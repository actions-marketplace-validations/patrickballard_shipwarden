import { createClient } from 'jsr:@supabase/supabase-js@2';

Deno.serve(async (req) => {
  const { userId } = await req.json();
  const supabase = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);
  await supabase.auth.admin.deleteUser(userId);
  return new Response('deleted');
});
