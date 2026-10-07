'use client';
import { useEffect, useState } from 'react';
import { llmPricingStatus } from './llm-pricing';
export function LlmPricingNotice({ checkedAt }: { checkedAt: unknown }) {
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const timer = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 60000);
    return () => clearInterval(timer);
  }, []);
  const status = llmPricingStatus(checkedAt, now);
  return <p className="notice" role={status.state === 'expired' ? 'alert' : 'status'}>{status.message}</p>;
}
