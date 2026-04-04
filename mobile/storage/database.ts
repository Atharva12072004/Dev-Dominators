import * as SQLite from "expo-sqlite";

// TODO: Replace this lightweight bootstrap with a fuller repository-backed persistence layer.
let databasePromise: Promise<SQLite.SQLiteDatabase> | null = null;

export async function getDatabase() {
  if (!databasePromise) {
    databasePromise = SQLite.openDatabaseAsync("cybershield.db");
  }
  return databasePromise;
}

export async function initializeDatabase() {
  const db = await getDatabase();
  await db.execAsync(`
    CREATE TABLE IF NOT EXISTS protection_events (
      id TEXT PRIMARY KEY NOT NULL,
      external_id TEXT,
      source_type TEXT NOT NULL,
      source_app TEXT,
      preview TEXT NOT NULL,
      raw_text TEXT,
      raw_url TEXT,
      label TEXT NOT NULL,
      risk_score INTEGER NOT NULL,
      reasons TEXT NOT NULL,
      status TEXT NOT NULL,
      should_block INTEGER NOT NULL DEFAULT 0,
      analysis_mode TEXT NOT NULL DEFAULT 'offline',
      detection_mode TEXT NOT NULL DEFAULT 'rule',
      partial_scan INTEGER NOT NULL DEFAULT 0,
      provider_used TEXT,
      ai_summary TEXT,
      base_risk_score INTEGER,
      attachment_analysis TEXT,
      explainability TEXT,
      created_at TEXT NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_protection_events_external_id
    ON protection_events(external_id)
    WHERE external_id IS NOT NULL;
  `);

  const columns = (await db.getAllAsync(`PRAGMA table_info(protection_events)`)) as Array<{
    name: string;
  }>;
  const columnNames = new Set(columns.map((column) => column.name));

  if (!columnNames.has("external_id")) {
    await db.execAsync(`ALTER TABLE protection_events ADD COLUMN external_id TEXT;`);
  }
  if (!columnNames.has("raw_text")) {
    await db.execAsync(`ALTER TABLE protection_events ADD COLUMN raw_text TEXT;`);
  }
  if (!columnNames.has("raw_url")) {
    await db.execAsync(`ALTER TABLE protection_events ADD COLUMN raw_url TEXT;`);
  }
  if (!columnNames.has("label")) {
    await db.execAsync(`ALTER TABLE protection_events ADD COLUMN label TEXT NOT NULL DEFAULT 'safe';`);
  }
  if (!columnNames.has("should_block")) {
    await db.execAsync(`ALTER TABLE protection_events ADD COLUMN should_block INTEGER NOT NULL DEFAULT 0;`);
  }
  if (!columnNames.has("analysis_mode")) {
    await db.execAsync(`ALTER TABLE protection_events ADD COLUMN analysis_mode TEXT NOT NULL DEFAULT 'offline';`);
  }
  if (!columnNames.has("provider_used")) {
    await db.execAsync(`ALTER TABLE protection_events ADD COLUMN provider_used TEXT;`);
  }
  if (!columnNames.has("ai_summary")) {
    await db.execAsync(`ALTER TABLE protection_events ADD COLUMN ai_summary TEXT;`);
  }
  if (!columnNames.has("detection_mode")) {
    await db.execAsync(`ALTER TABLE protection_events ADD COLUMN detection_mode TEXT NOT NULL DEFAULT 'rule';`);
  }
  if (!columnNames.has("partial_scan")) {
    await db.execAsync(`ALTER TABLE protection_events ADD COLUMN partial_scan INTEGER NOT NULL DEFAULT 0;`);
  }
  if (!columnNames.has("base_risk_score")) {
    await db.execAsync(`ALTER TABLE protection_events ADD COLUMN base_risk_score INTEGER;`);
  }
  if (!columnNames.has("attachment_analysis")) {
    await db.execAsync(`ALTER TABLE protection_events ADD COLUMN attachment_analysis TEXT;`);
  }
  if (!columnNames.has("explainability")) {
    await db.execAsync(`ALTER TABLE protection_events ADD COLUMN explainability TEXT;`);
  }
}
