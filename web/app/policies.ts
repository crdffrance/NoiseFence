export type DeliveryAction = 'deliver' | 'tag' | 'quarantine';
export type ActionPolicy = {
  spam: DeliveryAction;
  publicity: DeliveryAction;
  malware: DeliveryAction;
  quarantine_days: number;
};

export function deliveryPolicy(settings: {
  actions?: ActionPolicy | null;
  mailing?: { tag_subject: boolean } | null;
}): ActionPolicy {
  // Match the server's legacy policy, never the currently active revision.
  return (
    settings.actions ?? {
      spam: 'tag',
      malware: 'tag',
      publicity: settings.mailing?.tag_subject ? 'tag' : 'deliver',
      quarantine_days: 14,
    }
  );
}

export function restoreDefaults<
  T extends {
    actions?: ActionPolicy | null;
    filters: {
      rule_weights?: Record<string, number>;
      require_corroboration?: boolean;
    };
  },
>(settings: T) {
  // Older stored revisions omit fields introduced after they were saved.
  return {
    ...settings,
    actions: settings.actions ?? null,
    filters: {
      ...settings.filters,
      rule_weights: settings.filters.rule_weights ?? {},
      require_corroboration: settings.filters.require_corroboration ?? false,
    },
  };
}
