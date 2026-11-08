export function Bio({ profile }: { profile: { bio: string } }) {
  return <div className="prose" dangerouslySetInnerHTML={{ __html: profile.bio }} />;
}
