import type { OpenClawPluginApi } from "./types/types.d.ts";
import type {
  PluginHookBeforeToolResultEvent,
  PluginHookBeforeToolResultResult,
  PluginHookToolContext,
} from "./types/types.d.ts";

interface ScanRequest {
  content: unknown;
  features?: Record<string, boolean>;
  scan_tier?: number;
}

interface ScanResponse {
  action: "allow" | "block" | "sanitize";
  reason?: string;
  sanitized_content?: unknown;
  matches?: Array<{
    pattern: string;
    severity: string;
    type: string;
    lang: string;
  }>;
}

export default (api: OpenClawPluginApi) => {
  const config = api.pluginConfig || {};
  
  // Service configuration
  const serviceUrl = (config.service_url as string) || "http://localhost:8080";
  const timeoutMs = (config.timeout_ms as number) || 5000;
  const failOpen = config.fail_open !== false;
  const scanEnabled = config.scan_enabled !== false;
  
  // Owner bypass - plugin handles this
  const ownerIds = (config.owner_ids as string[]) || [];
  
  // Excluded tools - plugin handles this
  const excludedTools = (config.excluded_tools as string[]) || [];
  
  // Feature flags
  const features = (config.features as Record<string, boolean>) || {};
  const promptGuardEnabled = features.prompt_guard !== false;
  
  // Scan tier
  const scanTier = (config.scan_tier as number) || 1;
  
  api.logger.info(`Prompt Defender plugin initialized`);
  api.logger.info(`  Service URL: ${serviceUrl}`);
  api.logger.info(`  Features: prompt_guard=${promptGuardEnabled}`);
  api.logger.info(`  Owner IDs: ${ownerIds.length > 0 ? ownerIds.join(', ') : '(none)'}`);
  api.logger.info(`  Excluded tools: ${excludedTools.length > 0 ? excludedTools.join(', ') : '(none)'}`);

  // Check if session should bypass scanning (owner)
  const shouldBypass = (sessionKey?: string): boolean => {
    if (!sessionKey || ownerIds.length === 0) return false;
    return ownerIds.includes(sessionKey);
  };

  // Check if tool should be excluded from scanning
  const isExcluded = (toolName: string): boolean => {
    return excludedTools.includes(toolName);
  };

  // Call the scanning service
  const scanContent = async (
    content: unknown
  ): Promise<ScanResponse | null> => {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);

      // Build flattened request body
      const requestBody: ScanRequest = {
        content,
        features,
        scan_tier: scanTier
      };

      const response = await fetch(`${serviceUrl}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
        },
        body: JSON.stringify(requestBody),
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json() as ScanResponse;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      api.logger.error(`Scan request failed: ${message}`);
      
      if (failOpen) {
        api.logger.warn(`Fail-open: allowing tool result despite scan failure`);
        return null;
      }
      
      return {
        action: "block",
        reason: `Scan service unavailable: ${message}`,
      };
    }
  };

  api.on(
    "before_tool_result",
    async (
      event: PluginHookBeforeToolResultEvent,
      ctx: PluginHookToolContext
    ): Promise<PluginHookBeforeToolResultResult | void> => {
      const { toolName, toolCallId, content, isError } = event;

      // Skip errors
      if (isError) {
        api.logger.debug(`[Prompt Defender] Skipping error result for ${toolName}`);
        return;
      }

      // Check if scanning is disabled
      if (!scanEnabled) {
        api.logger.debug(`[Prompt Defender] Scanning disabled`);
        return;
      }
      
      // Check if prompt_guard feature is enabled
      if (!promptGuardEnabled) {
        api.logger.debug(`[Prompt Defender] prompt_guard feature disabled`);
        return;
      }

      // Check if tool is excluded
      if (isExcluded(toolName)) {
        api.logger.debug(`[Prompt Defender] Tool '${toolName}' is excluded from scanning`);
        return;
      }

      // Check owner bypass
      if (shouldBypass(ctx.sessionKey)) {
        api.logger.info(`[Prompt Defender] Owner bypass for session ${ctx.sessionKey}`);
        return;
      }

      api.logger.info(`[Prompt Defender] Scanning tool result: ${toolName} (callId: ${toolCallId})`);

      const result = await scanContent(content);

      if (!result) {
        // Fail-open: allow through
        return;
      }

      if (result.action === "block") {
        const matchCount = result.matches?.length || 0;
        const categories = result.matches?.map(m => m.type).join(", ") || "unknown";
        
        api.logger.warn(
          `[Prompt Defender] BLOCKED ${toolName}: ${matchCount} pattern(s) matched (${categories})`
        );
        
        return {
          block: true,
          blockReason: result.reason || "Blocked by Prompt Defender",
        } as PluginHookBeforeToolResultResult;
      }

      if (result.action === "sanitize" && result.sanitized_content !== undefined) {
        api.logger.info(`[Prompt Defender] SANITIZED ${toolName}`);
        return {
          content: result.sanitized_content,
        } as PluginHookBeforeToolResultResult;
      }

      // Allow
      api.logger.debug(`[Prompt Defender] ALLOWED ${toolName}`);
      return;
    }
  );

  api.logger.info(`Prompt Defender: before_tool_result hook registered`);
};
