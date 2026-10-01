export default async function SignedOut({ searchParams }: { searchParams: Promise<{ error?: string }> }) {
  const { error } = await searchParams;
  return (
    <div className="mx-auto mt-24 max-w-sm text-center">
      <h1 className="mb-2 text-xl font-semibold">{error ? "Sign-in failed" : "Signed out"}</h1>
      {error && <p className="mb-4 text-sm text-red-600">{error}</p>}
      <a href="/auth/login" className="text-sm underline">
        Sign in
      </a>
    </div>
  );
}
