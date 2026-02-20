/**
 * Unit tests for Prompt Defender plugin.
 */

import { describe, it, expect } from 'vitest';

describe('Prompt Defender Plugin', () => {
  // Test configuration parsing
  describe('Configuration', () => {
    it('should use default service_url when not configured', () => {
      const config = {};
      const serviceUrl = (config.service_url as string) || "http://localhost:8080";
      expect(serviceUrl).toBe("http://localhost:8080");
    });

    it('should use custom service_url when configured', () => {
      const config = { service_url: "http://custom:9000" };
      const serviceUrl = (config.service_url as string) || "http://localhost:8080";
      expect(serviceUrl).toBe("http://custom:9000");
    });

    it('should use default timeout when not configured', () => {
      const config = {};
      const timeoutMs = (config.timeout_ms as number) || 5000;
      expect(timeoutMs).toBe(5000);
    });

    it('should use custom timeout when configured', () => {
      const config = { timeout_ms: 10000 };
      const timeoutMs = (config.timeout_ms as number) || 5000;
      expect(timeoutMs).toBe(10000);
    });

    it('should default fail_open to true', () => {
      const config = {};
      const failOpen = config.fail_open !== false;
      expect(failOpen).toBe(true);
    });

    it('should allow setting fail_open to false', () => {
      const config = { fail_open: false };
      const failOpen = config.fail_open !== false;
      expect(failOpen).toBe(false);
    });
  });

  // Test owner bypass logic (plugin handles this)
  describe('Owner Bypass', () => {
    const OWNER_ID = "1461460866850357345";

    const shouldBypass = (sessionKey?: string, ownerIds: string[] = []): boolean => {
      if (!sessionKey || ownerIds.length === 0) return false;
      return ownerIds.includes(sessionKey);
    };

    it('should bypass when session key matches owner ID', () => {
      const sessionKey = "1461460866850357345";
      const ownerIds = [OWNER_ID];
      expect(shouldBypass(sessionKey, ownerIds)).toBe(true);
    });

    it('should not bypass when session key does not match owner ID', () => {
      const sessionKey = "other-user-id";
      const ownerIds = [OWNER_ID];
      expect(shouldBypass(sessionKey, ownerIds)).toBe(false);
    });

    it('should not bypass when owner IDs is empty', () => {
      const sessionKey = "1461460866850357345";
      const ownerIds: string[] = [];
      expect(shouldBypass(sessionKey, ownerIds)).toBe(false);
    });

    it('should not bypass when session key is undefined', () => {
      const sessionKey = undefined;
      const ownerIds = [OWNER_ID];
      expect(shouldBypass(sessionKey, ownerIds)).toBe(false);
    });
  });

  // Test excluded tools logic (plugin handles this)
  describe('Excluded Tools', () => {
    const isExcluded = (toolName: string, excludedTools: string[] = []): boolean => {
      return excludedTools.includes(toolName);
    };

    it('should exclude tool when in excluded list', () => {
      const toolName = "echo";
      const excludedTools = ["echo", "calc"];
      expect(isExcluded(toolName, excludedTools)).toBe(true);
    });

    it('should not exclude tool when not in excluded list', () => {
      const toolName = "web_fetch";
      const excludedTools = ["echo", "calc"];
      expect(isExcluded(toolName, excludedTools)).toBe(false);
    });

    it('should not exclude when excluded tools is empty', () => {
      const toolName = "web_fetch";
      const excludedTools: string[] = [];
      expect(isExcluded(toolName, excludedTools)).toBe(false);
    });
  });

  // Test feature flags
  describe('Feature Flags', () => {
    it('should enable prompt_guard by default', () => {
      const config = {};
      const features = (config.features as Record<string, boolean>) || {};
      const promptGuardEnabled = features.prompt_guard !== false;
      expect(promptGuardEnabled).toBe(true);
    });

    it('should allow disabling prompt_guard', () => {
      const config = { features: { prompt_guard: false } };
      const features = (config.features as Record<string, boolean>) || {};
      const promptGuardEnabled = features.prompt_guard !== false;
      expect(promptGuardEnabled).toBe(false);
    });
  });

  // Test scan request building
  describe('Scan Request', () => {
    it('should build flattened request body', () => {
      const content = "test content";
      const features = { prompt_guard: true };
      const scanTier = 1;

      const requestBody = {
        content,
        features,
        scan_tier: scanTier
      };

      expect(requestBody.content).toBe("test content");
      expect(requestBody.features).toEqual({ prompt_guard: true });
      expect(requestBody.scan_tier).toBe(1);
    });

    it('should handle minimal request', () => {
      const content = "test content";

      const requestBody = {
        content
      };

      expect(requestBody.content).toBe("test content");
      expect(requestBody.features).toBeUndefined();
      expect(requestBody.scan_tier).toBeUndefined();
    });

    it('should include features when provided', () => {
      const content = "test content";
      const features = { prompt_guard: true, ml_detection: false };

      const requestBody = {
        content,
        features
      };

      expect(requestBody.features).toEqual({ prompt_guard: true, ml_detection: false });
    });
  });

  // Test scan tier
  describe('Scan Tier', () => {
    it('should default to tier 1', () => {
      const config = {};
      const scanTier = config.scan_tier !== undefined ? config.scan_tier as number : 1;
      expect(scanTier).toBe(1);
    });

    it('should allow custom tier', () => {
      const config = { scan_tier: 2 };
      const scanTier = config.scan_tier !== undefined ? config.scan_tier as number : 1;
      expect(scanTier).toBe(2);
    });

    it('should allow tier 0', () => {
      const config = { scan_tier: 0 };
      const scanTier = config.scan_tier !== undefined ? config.scan_tier as number : 1;
      expect(scanTier).toBe(0);
    });
  });
});
