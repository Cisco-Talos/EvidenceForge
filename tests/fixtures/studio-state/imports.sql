
            CREATE TABLE IF NOT EXISTS items (
                id TEXT PRIMARY KEY,
                workspace TEXT NOT NULL,
                kind TEXT NOT NULL,
                path TEXT NOT NULL,
                payload TEXT NOT NULL,
                content TEXT NOT NULL DEFAULT '',
                UNIQUE (workspace, kind, path)
            );
            CREATE TABLE IF NOT EXISTS folders (
                workspace TEXT NOT NULL,
                name TEXT NOT NULL,
                PRIMARY KEY (workspace, name)
            );
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                workspace TEXT NOT NULL,
                name TEXT NOT NULL COLLATE NOCASE,
                payload TEXT NOT NULL,
                UNIQUE (workspace, name)
            );
            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                workspace TEXT NOT NULL,
                item_id TEXT,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                workspace TEXT NOT NULL,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS imported_bundles (
                id TEXT PRIMARY KEY,
                workspace TEXT NOT NULL,
                root TEXT NOT NULL,
                payload TEXT NOT NULL,
                UNIQUE (workspace, root)
            );
            CREATE TABLE IF NOT EXISTS validations (
                item_id TEXT PRIMARY KEY,
                source_sha256 TEXT NOT NULL,
                completed_at REAL NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS views (
                workspace TEXT NOT NULL,
                name TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (workspace, name)
            );
            CREATE TABLE IF NOT EXISTS workspace_preferences (
                workspace TEXT PRIMARY KEY,
                export_directory TEXT
            );
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS control (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS items_workspace_idx ON items(workspace, kind);
            CREATE INDEX IF NOT EXISTS projects_workspace_idx ON projects(workspace);
            CREATE INDEX IF NOT EXISTS conversations_item_idx ON conversations(item_id);
            CREATE INDEX IF NOT EXISTS jobs_workspace_idx ON jobs(workspace, kind);
            CREATE INDEX IF NOT EXISTS imported_bundles_workspace_idx ON imported_bundles(workspace);
            