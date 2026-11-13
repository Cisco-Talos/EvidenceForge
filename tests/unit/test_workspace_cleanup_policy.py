"""Keep new workspace tree-removal paths on the reviewed platform boundary."""

import ast
from collections import Counter
from pathlib import Path


def test_recursive_removal_has_no_unreviewed_workspace_bypasses() -> None:
    root = Path(__file__).resolve().parents[2] / "src" / "evidenceforge"
    # These have separate ownership/durability contracts, or are POSIX-only arms
    # whose Windows arm already delegates to a native protected-storage backend.
    allowed = Counter(
        {
            ("_windows_cleanup.py", "remove_once"): 3,
            ("studio/service.py", "remove_scenario_runs"): 1,  # private metadata, not run data
            ("studio/state_upgrade.py", "prune"): 1,  # verified private recovery packages
            ("studio/runtime_cleanup.py", "_clean"): 1,  # POSIX; Windows retention disabled
            ("studio/windows_uninstall.py", "execute"): 2,  # POSIX; Windows uses pinned handles
            ("artifacts/removal.py", "_delete_tree_last_source"): 1,  # POSIX dir_fd
            ("generation/checkpoints/store.py", "_remove_checkpoint_tree"): 1,  # POSIX
            ("generation/checkpoints/store.py", "_rotate_recoveries"): 1,  # POSIX
            ("generation/checkpoints/store.py", "remove_workspace"): 1,  # POSIX
            ("generation/macos_es_ingress.py", "cleanup"): 1,  # POSIX
            ("generation/emitters/sorted_writer.py", "_cleanup_spool_unlocked"): 1,  # POSIX
        }
    )
    found: Counter[tuple[str, str]] = Counter()
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        modules = {"shutil"}
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(
                    alias.asname or alias.name for alias in node.names if alias.name == "shutil"
                )
            elif isinstance(node, ast.ImportFrom) and node.module == "shutil":
                names.update(
                    alias.asname or alias.name for alias in node.names if alias.name == "rmtree"
                )
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for candidate in (node.func, *node.args):
                direct = isinstance(candidate, ast.Name) and candidate.id in names
                qualified = (
                    isinstance(candidate, ast.Attribute)
                    and isinstance(candidate.value, ast.Name)
                    and candidate.value.id in modules
                    and candidate.attr == "rmtree"
                )
                if not (direct or qualified):
                    continue
                owner: ast.AST = node
                while owner in parents and not isinstance(
                    owner, (ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    owner = parents[owner]
                found[(path.relative_to(root).as_posix(), getattr(owner, "name", "<module>"))] += 1
    assert found == allowed, (
        "Review new recursive removals; workspace cleanup uses remove_owned_tree"
    )
