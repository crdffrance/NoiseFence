export type User = {
  username: string;
  admin: boolean;
  csrf: string;
  addresses: string[];
};

export async function api<T = unknown>(
  path: string,
  data?: unknown,
  csrf?: string,
) {
  const response = await fetch(`/api/v1${path}`, {
    credentials: 'same-origin',
    method: data === undefined ? 'GET' : 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(csrf ? { 'X-CSRF-Token': csrf } : {}),
    },
    body: data === undefined ? undefined : JSON.stringify(data),
  });
  if (!response.ok) {
    if (response.status === 401)
      window.dispatchEvent(new Event('session-expired'));
    const error = (await response.json().catch(() => ({}))) as {
      error?: string;
    };
    throw new Error(
      error.error ||
        (response.status === 401
          ? 'Connectez-vous pour continuer.'
          : 'La demande a échoué. Réessayez.'),
    );
  }
  return (await response.json()) as T;
}
