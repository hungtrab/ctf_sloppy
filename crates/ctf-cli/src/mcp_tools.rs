//! Bridges MCP servers (e.g. `GhidraMCP`) configured in `~/.claude.json` into
//! the ctf-cli agent's tool list, so the agent can call them like any other
//! tool (`mcp__<server>__<tool>`).

use serde_json::{json, Value};

use runtime::{ConfigLoader, ManagedMcpTool, McpServerManager, PermissionMode};
use tools::ToolSpec;

pub struct McpToolset {
    manager: McpServerManager,
    tools: Vec<ManagedMcpTool>,
    rt: tokio::runtime::Runtime,
}

/// Discover MCP servers + their tools from `~/.claude.json` (and any project
/// config). Returns `None` if no MCP servers are configured or discovery fails
/// (e.g. the server process isn't reachable yet).
pub fn load() -> Option<McpToolset> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let config = ConfigLoader::default_for(cwd).load().ok()?;
    let mut manager = McpServerManager::from_runtime_config(&config);

    let rt = tokio::runtime::Runtime::new().ok()?;
    // Stdio bridges (e.g. GhidraMCP) may block on stdio until they connect to
    // their backing app, retrying for a long time. Don't let that stall startup.
    let discovery = rt.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(5), manager.discover_tools()).await
    });
    let tools = match discovery {
        Ok(Ok(tools)) if !tools.is_empty() => tools,
        _ => {
            let _ = rt.block_on(async {
                tokio::time::timeout(std::time::Duration::from_secs(5), manager.shutdown()).await
            });
            return None;
        }
    };

    Some(McpToolset { manager, tools, rt })
}

/// Tool specs to advertise to the model, derived from the discovered MCP tools.
/// Names/descriptions are leaked to `'static str` once at startup — acceptable
/// for the lifetime of the CLI process.
pub fn tool_specs(toolset: &McpToolset) -> Vec<ToolSpec> {
    toolset
        .tools
        .iter()
        .map(|t| {
            let name: &'static str = Box::leak(t.qualified_name.clone().into_boxed_str());
            let description: &'static str = Box::leak(
                t.tool
                    .description
                    .clone()
                    .unwrap_or_else(|| {
                        format!("MCP tool `{}` from server `{}`", t.raw_name, t.server_name)
                    })
                    .into_boxed_str(),
            );
            ToolSpec {
                name,
                description,
                input_schema: t
                    .tool
                    .input_schema
                    .clone()
                    .unwrap_or_else(|| json!({ "type": "object", "additionalProperties": true })),
                required_permission: PermissionMode::DangerFullAccess,
            }
        })
        .collect()
}

/// Names of MCP servers configured in `~/.claude.json` (and any project
/// config), regardless of whether they're currently reachable. Used to
/// distinguish "not configured" from "configured but failed to connect".
#[must_use]
pub fn configured_servers() -> Vec<String> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let Ok(config) = ConfigLoader::default_for(cwd).load() else {
        return Vec::new();
    };
    config.mcp().servers().keys().cloned().collect()
}

/// Connected MCP servers and how many tools each exposes, e.g.
/// `[("ghidra", 3)]`. Used to show the user which MCP servers are active.
#[must_use]
pub fn server_summary(toolset: &McpToolset) -> Vec<(String, usize)> {
    let mut servers: Vec<(String, usize)> = Vec::new();
    for tool in &toolset.tools {
        match servers
            .iter_mut()
            .find(|(name, _)| *name == tool.server_name)
        {
            Some((_, count)) => *count += 1,
            None => servers.push((tool.server_name.clone(), 1)),
        }
    }
    servers
}

#[must_use]
pub fn is_mcp_tool(name: &str) -> bool {
    name.starts_with("mcp__")
}

/// Call an MCP tool by its qualified name (`mcp__<server>__<tool>`) and
/// flatten the result into a single string for the agent.
pub fn call(
    toolset: &mut McpToolset,
    qualified_name: &str,
    arguments: &Value,
) -> Result<String, String> {
    let response = toolset
        .rt
        .block_on(
            toolset
                .manager
                .call_tool(qualified_name, Some(arguments.clone())),
        )
        .map_err(|e| format!("{e:?}"))?;

    if let Some(error) = response.error {
        return Err(format!("{}: {}", error.code, error.message));
    }
    let result = response.result.ok_or("MCP tool returned no result")?;

    let mut out = String::new();
    for content in &result.content {
        if content.kind == "text" {
            if let Some(text) = content.data.get("text").and_then(Value::as_str) {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(text);
                continue;
            }
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&serde_json::to_string(&content.data).unwrap_or_default());
    }

    if result.is_error.unwrap_or(false) {
        return Err(out);
    }
    Ok(out)
}
