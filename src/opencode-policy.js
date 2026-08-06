import { appendFileSync } from "node:fs"

import { inject, protectCommand, protectPath } from "./opencode-policy-rules.js"

const preview = (value) => String(value ?? "").slice(0, 200)
const file = new URL("../opencode-policy.log", import.meta.url)
const refusal = "The original user request was blocked by workspace policy. Briefly explain that the request was denied because it attempted to override instructions."

const deny = (reason) => {
  const error = new Error(`Blocked by opencode-policy: ${reason}`)
  error.stack = `Error: Blocked by opencode-policy: ${reason}`
  throw error
}

const record = async (client, level, message, extra) => {
  const body = {
    service: "opencode-policy",
    level,
    message,
    extra,
  }
  appendFileSync(file, `${JSON.stringify({ time: new Date().toISOString(), ...body })}\n`, "utf8")
}

const parts = (part) => {
  return [
    String(part?.text ?? ""),
    String(part?.prompt ?? ""),
    String(part?.command ?? ""),
    String(part?.source?.value ?? ""),
  ]
}

const listed = (list) => {
  return list.flatMap((part) => parts(part))
}

const unsafeToolPatterns = async (client, input, output) => {
  const path = String(output?.args?.filePath ?? "")
  await record(client, "debug", "tool.execute.before", {
    tool: preview(input?.tool),
    filePath: preview(output?.args?.filePath),
    command: preview(output?.args?.command),
    text: preview(output?.args?.text),
    prompt: preview(output?.args?.prompt),
    query: preview(output?.args?.query),
  })
  const pathRule = protectPath(path)
  if (pathRule) {
    await record(client, "warn", "unsafe tool pattern matched", {
      id: preview(pathRule.id),
      reason: preview(pathRule.reason),
      filePath: preview(path),
    })
    deny(pathRule.reason)
  }
  const command = String(output?.args?.command ?? "")
  await record(client, "debug", "tool.execute.before.scan", {
    tool: preview(input?.tool),
    argsText: preview(output?.args?.text),
    argsPrompt: preview(output?.args?.prompt),
    argsQuery: preview(output?.args?.query),
    argsCommand: preview(output?.args?.command),
  })
  const commandRule = protectCommand(command)
  if (commandRule) {
    await record(client, "warn", "unsafe tool pattern matched", {
      id: preview(commandRule.id),
      reason: preview(commandRule.reason),
      value: preview(command),
    })
    deny(commandRule.reason)
  }
  const values = [
    String(output?.args?.text ?? ""),
    String(output?.args?.prompt ?? ""),
    String(output?.args?.query ?? ""),
  ]
  for (const value of values) {
    const injection = inject(value)
    if (injection) {
      await record(client, "warn", "prompt injection matched", {
        id: preview(injection.id),
        reason: preview(injection.reason),
        value: preview(value),
      })
      deny(injection.reason)
    }
  }
}

const promptInjectionPatterns = async (client, _input, output) => {
  for (const message of output?.messages ?? []) {
    if (message?.info?.role !== "user") {
      continue
    }
    const values = listed(Array.isArray(message?.parts) ? message.parts : [])
    for (const value of values) {
      const injection = inject(value)
      if (!injection) {
        continue
      }
      await record(client, "warn", "prompt injection matched", {
        id: preview(injection.id),
        reason: preview(injection.reason),
        value: preview(value),
      })
      message.parts = [{ type: "text", text: refusal }]
      break
    }
  }
}

/**
 * OpenCode plugin with extensible unsafe tool patterns
 *
 * Usage:
 * Add the package name to the `plugin` array in `opencode.json`
 */
export const OpencodePolicy = async ({ client } = {}) => {
  return {
    "experimental.chat.messages.transform": async (input, output) => promptInjectionPatterns(client, input, output),
    "tool.execute.before": async (input, output) => unsafeToolPatterns(client, input, output),
  }
}

export default OpencodePolicy
