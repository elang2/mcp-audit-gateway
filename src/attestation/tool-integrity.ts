import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

export interface ToolDefinition {
  name: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: Record<string, unknown>;
}

export interface ToolDriftEvent {
  toolName: string;
  namespace: string;
  previousDefinitionDigest: string;
  newDefinitionDigest: string;
}

export class ToolIntegrityMonitor {
  private baselines: Map<string, string> = new Map();

  computeDigest(tool: ToolDefinition): string {
    const obj: Record<string, unknown> = { name: tool.name };
    if (tool.description !== undefined) obj.description = tool.description;
    if (tool.inputSchema !== undefined) obj.inputSchema = tool.inputSchema;
    if (tool.annotations !== undefined) obj.annotations = tool.annotations;

    const canonical = canonicalize(obj);
    if (canonical === undefined) {
      throw new Error(`Failed to canonicalize tool definition: ${tool.name}`);
    }
    return createHash("sha256").update(canonical).digest("hex");
  }

  setBaseline(qualifiedName: string, digest: string): void {
    this.baselines.set(qualifiedName, digest);
  }

  getBaseline(qualifiedName: string): string | undefined {
    return this.baselines.get(qualifiedName);
  }

  checkAndUpdate(
    qualifiedName: string,
    namespace: string,
    tool: ToolDefinition,
  ): ToolDriftEvent | null {
    const newDigest = this.computeDigest(tool);
    const previousDigest = this.baselines.get(qualifiedName);

    if (previousDigest === undefined) {
      this.baselines.set(qualifiedName, newDigest);
      return null;
    }

    if (previousDigest === newDigest) {
      return null;
    }

    this.baselines.set(qualifiedName, newDigest);
    return {
      toolName: qualifiedName,
      namespace,
      previousDefinitionDigest: previousDigest,
      newDefinitionDigest: newDigest,
    };
  }

  hasBaseline(qualifiedName: string): boolean {
    return this.baselines.has(qualifiedName);
  }

  getBaselineCount(): number {
    return this.baselines.size;
  }
}
