type Context = {
  registerTool(
    tool: {
      name: string;
      description: string;
      inputSchema: object;
      annotations: { readOnlyHint: boolean; untrustedContentHint: boolean };
      execute(input: unknown): Promise<unknown>;
    },
    options: { signal: AbortSignal },
  ): unknown;
};
export function registerFeedbackTool(
  correct: (id: string, spam: boolean) => Promise<void>,
) {
  const context = (document as Document & { modelContext?: Context })
    .modelContext;
  if (!context?.registerTool) return () => {};
  const controller = new AbortController();
  try {
    Promise.resolve(
      context.registerTool(
        {
          name: 'correct_message_classification',
          description:
            'Record the signed-in user’s spam or legitimate feedback. This affects future learning; it does not modify the delivered Proton message.',
          inputSchema: {
            type: 'object',
            properties: {
              messageId: { type: 'string' },
              spam: { type: 'boolean' },
            },
            required: ['messageId', 'spam'],
            additionalProperties: false,
          },
          annotations: { readOnlyHint: false, untrustedContentHint: false },
          async execute(value) {
            if (!value || typeof value !== 'object')
              throw new Error('Invalid input');
            const input = value as Record<string, unknown>;
            if (
              Object.keys(input).length !== 2 ||
              typeof input.messageId !== 'string' ||
              !/^[0-9a-f-]{36}$/i.test(input.messageId) ||
              typeof input.spam !== 'boolean'
            )
              throw new Error('Invalid messageId or spam flag');
            await correct(input.messageId, input.spam);
            return {
              recorded: true,
              messageId: input.messageId,
              spam: input.spam,
            };
          },
        },
        { signal: controller.signal },
      ),
    ).catch(() => {});
  } catch {
    /* Optional browser capability. The regular UI remains available. */
  }
  return () => controller.abort();
}
