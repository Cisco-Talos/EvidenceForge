"""Regression for cyclic-GC retirement while an ASA binding operation owns its lock."""

import subprocess
import sys
import textwrap


def test_cisco_binding_gc_can_retire_another_owner_during_registry_operation() -> None:
    # Use a subprocess so a non-reentrant regression fails with a bounded timeout.
    script = textwrap.dedent(
        """
        import gc
        import inspect
        from threading import Lock
        from weakref import ref
        from evidenceforge.formats.loader import load_format
        from evidenceforge.generation.emitters.cisco_asa import (
            _new_cisco_exact_projection_binding_registry,
        )

        class Owner:
            def __init__(self) -> None:
                self._writers: dict[str, object] = {}
                self._writers_lock = Lock()
                self.cycle = self

        gc.disable()
        bind, _, settings = _new_cisco_exact_projection_binding_registry()
        expired, retained = Owner(), Owner()
        bind(expired, load_format("cisco_asa"), 100)
        bind(retained, load_format("cisco_asa"), 100)
        expired_ref = ref(expired)
        del expired
        # Allocation under bind/binding_for can collect a different cyclic owner.
        registry_lock = inspect.getclosurevars(bind).nonlocals["registry_lock"]
        with registry_lock:
            gc.collect()
        assert expired_ref() is None
        assert settings(retained).buffer_size == 100
        """
    )
    subprocess.run([sys.executable, "-c", script], check=True, timeout=15)
