/** Mirrors the server's 30-day cost-verification guard; never renews it. */
export function llmPricingStatus(checkedAt: unknown, nowSeconds: number) {
  if (typeof checkedAt !== 'number' || !Number.isFinite(checkedAt))
    return { state: 'unknown', message: 'LLM pricing verification date is unavailable. Check the saved configuration.' };
  const age = nowSeconds - checkedAt;
  if (age < 0 || age > 30 * 86400)
    return { state: 'expired', message: 'LLM analysis is suspended: pricing verification has expired or has an invalid future date. Verify provider prices before renewing the date. No automatic renewal is performed.' };
  const days = Math.ceil((30 * 86400 - age) / 86400);
  return days <= 7
    ? { state: 'expiring', message: `LLM pricing verification expires in ${days} day(s). Analysis will pause unless current prices are verified and the configuration is saved.` }
    : { state: 'current', message: `LLM pricing verification is current (${days} day(s) remaining). Budget and other availability limits still apply.` };
}
