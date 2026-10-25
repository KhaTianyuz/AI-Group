export async function syncTasksToLocalDB(tasks: any[]) {
  // 等待 Codex 与 Gemini 对齐字段规范
  return { synced: tasks.length, timestamp: Date.now() };
}
