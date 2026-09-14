"""Independent self-checks for the software storage-failure model."""

from tests.support.checkpoint_power_loss import PowerLossModel, StorageEvent


def test_file_flush_does_not_flush_its_directory_entry() -> None:
    model = PowerLossModel()
    model.apply(StorageEvent("create", "pending"))
    model.apply(StorageEvent("write", "pending", payload=b"checkpoint"))
    model.apply(StorageEvent("flush", "pending"))
    assert model.crash().files == {}
    model.apply(StorageEvent("rename", "pending", "CURRENT", write_through=True))
    assert model.crash().files == {"CURRENT": b"checkpoint"}


def test_directory_rename_does_not_flush_child_bytes_or_entries() -> None:
    model = PowerLossModel()
    model.apply(StorageEvent("mkdir", "pending"))
    model.apply(StorageEvent("create", "pending/child"))
    model.apply(StorageEvent("write", "pending/child", payload=b"dirty"))
    model.apply(StorageEvent("rename", "pending", "recovery", write_through=True))
    assert model.crash().directories == ("recovery",)
    assert model.crash().files == {}
    model.apply(StorageEvent("rename", "recovery/child", "recovery/head", write_through=True))
    assert model.crash().files == {"recovery/head": b""}
    model.apply(StorageEvent("flush", "recovery/head"))
    assert model.crash().files == {"recovery/head": b"dirty"}


def test_losing_an_unflushed_rename_preserves_the_prior_name_and_bytes() -> None:
    model = PowerLossModel()
    for name in ("old", "new"):
        model.apply(StorageEvent("create", name))
        model.apply(StorageEvent("write", name, payload=name.encode()))
        model.apply(StorageEvent("flush", name))
    model.apply(StorageEvent("rename", "old", "CURRENT", write_through=True))
    model.apply(StorageEvent("ack", sequence=0))
    model.apply(StorageEvent("rename", "new", "CURRENT"))
    assert model.crash().files == {"CURRENT": b"old"}
    assert model.crash().acknowledged_sequence == 0
    assert model.crash("all").files["CURRENT"] == b"new"


def test_torn_writes_change_only_unflushed_bytes_at_both_sector_sizes() -> None:
    for sector in (512, 4096):
        model = PowerLossModel()
        model.apply(StorageEvent("create", "pending"))
        model.apply(StorageEvent("write", "pending", payload=b"x" * (sector * 3)))
        model.apply(StorageEvent("rename", "pending", "file", write_through=True))
        assert model.crash("torn", sector_size=sector).files["file"] == (
            b"x" * sector + b"\x00" * sector + b"x" * sector
        )
        model.apply(StorageEvent("flush", "file"))
        for profile in ("drop", "all", "reverse", "partial", "torn"):
            assert model.crash(profile, sector_size=sector).files == {"file": b"x" * (sector * 3)}


def test_second_crash_starts_only_from_the_first_crash_survivors() -> None:
    model = PowerLossModel()
    model.apply(StorageEvent("create", "old-pending"))
    model.apply(StorageEvent("write", "old-pending", payload=b"committed"))
    model.apply(StorageEvent("flush", "old-pending"))
    model.apply(StorageEvent("rename", "old-pending", "CURRENT", write_through=True))
    model.apply(StorageEvent("ack", sequence=2))
    model.apply(StorageEvent("create", "lost-file"))
    restarted = PowerLossModel.from_image(model.crash())
    assert restarted.crash("all").files == {"CURRENT": b"committed"}
    assert restarted.acknowledged_sequence == 2
