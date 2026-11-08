import Stripe from 'npm:stripe@17';

Deno.serve(async (req) => {
  const event = await req.json();
  if (event.type === 'checkout.session.completed') {
    // mark the user as paid...
  }
  return new Response('ok');
});
