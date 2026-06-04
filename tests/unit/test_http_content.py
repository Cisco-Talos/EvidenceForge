# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for shared HTTP content helpers."""

import random

from evidenceforge.generation.activity.http_content import (
    apply_transfer_size_variance,
    coerce_response_size_for_mime,
    infer_mime_type_from_path,
    is_health_endpoint_path,
    is_stable_resource_path,
    normalize_mime_type_for_path,
    response_mime_types_for_status,
    response_size_for_health_endpoint,
    response_size_for_mime,
    response_size_for_status,
)


def test_infer_mime_type_strips_query_and_fragment():
    assert infer_mime_type_from_path("/assets/status.gif?cache=1#view") == "image/gif"


def test_known_extension_overrides_supplied_content_type():
    assert normalize_mime_type_for_path("/status.gif", "text/html") == "image/gif"


def test_executable_download_uses_binary_mime_and_size_range():
    assert normalize_mime_type_for_path("/files/tool.exe", "text/html") == (
        "application/x-msdownload"
    )
    size = response_size_for_mime(random.Random(7), "application/x-msdownload")
    assert 5_000_000 <= size <= 150_000_000
    assert is_stable_resource_path("/files/tool.exe")


def test_installer_and_archive_downloads_use_production_scale_sizes():
    assert (
        normalize_mime_type_for_path(
            "/duo/device-health/2f7c6c95/DuoDeviceHealth-latest.msi",
            "application/octet-stream",
        )
        == "application/x-msdownload"
    )
    assert (
        normalize_mime_type_for_path(
            "/edgedl/chrome/chrome-for-testing/12adbeef/win64/chrome-win64.zip",
            "application/octet-stream",
        )
        == "application/zip"
    )
    assert is_stable_resource_path("/globalprotect/GlobalProtect64-4191fe73.msi")
    assert is_stable_resource_path(
        "/edgedl/chrome/chrome-for-testing/12adbeef/win64/chrome-win64.zip"
    )

    msi_size = response_size_for_status(
        200,
        "dl.duosecurity.com",
        "/duo/device-health/2f7c6c95/DuoDeviceHealth-latest.msi",
    )
    zip_size = response_size_for_status(
        200,
        "dl.google.com",
        "/edgedl/chrome/chrome-for-testing/12adbeef/win64/chrome-win64.zip",
    )

    assert 5_000_000 <= msi_size <= 150_000_000
    assert 1_000_000 <= zip_size <= 200_000_000


def test_download_mime_replaces_tiny_preferred_response_size():
    size = coerce_response_size_for_mime(
        random.Random(7),
        "application/x-msdownload",
        32_000,
    )
    assert 5_000_000 <= size <= 150_000_000


def test_archive_download_mime_replaces_tiny_preferred_response_size():
    size = coerce_response_size_for_mime(
        random.Random(7),
        "application/zip",
        32_000,
    )
    assert 1_000_000 <= size <= 200_000_000


def test_unknown_extension_keeps_supplied_content_type():
    assert normalize_mime_type_for_path("/download/custom.blob", "application/octet-stream") == (
        "application/octet-stream"
    )


def test_response_size_for_gif_uses_image_range():
    size = response_size_for_mime(random.Random(42), "image/gif")
    assert 500 <= size <= 50_000


def test_empty_body_statuses_have_zero_stable_response_size():
    assert response_size_for_status(204, "portal.example.com", "/assets/main.css") == 0
    assert response_size_for_status(304, "portal.example.com", "/assets/main.css") == 0


def test_redirect_response_size_is_small_and_stable():
    first = response_size_for_status(302, "portal.example.com", "/login")
    second = response_size_for_status(302, "portal.example.com", "/login")

    assert first == second
    assert 120 <= first <= 480


def test_response_mime_types_require_visible_body_and_success_status():
    assert response_mime_types_for_status(200, "text/css", 4096) == ["text/css"]
    assert response_mime_types_for_status(206, "application/javascript", 512) == [
        "application/javascript"
    ]
    assert response_mime_types_for_status(304, "text/css", 0) == []
    assert response_mime_types_for_status(200, "text/css", 0) == []
    assert response_mime_types_for_status(200, "text/css", 2048, method="HEAD") == []
    assert response_mime_types_for_status(403, "text/html", 900) == ["text/html"]
    assert response_mime_types_for_status(301, "application/javascript", 220) == ["text/html"]
    assert response_mime_types_for_status(404, "image/jpeg", 900) == ["text/html"]


def test_error_response_size_is_template_stable_by_status_host_and_uri():
    first = response_size_for_status(404, "portal.example.com", "/.git/HEAD")
    second = response_size_for_status(404, "portal.example.com", "/.git/HEAD")
    sibling = response_size_for_status(404, "portal.example.com", "/admin")

    assert first == second
    assert 128 <= first <= 2000
    assert abs(first - sibling) < 2000


def test_stable_resource_path_identifies_static_web_content():
    assert is_stable_resource_path("/assets/main.css")
    assert is_stable_resource_path("/assets/vendor.js?cache=1")
    assert is_stable_resource_path("/robots.txt")
    assert is_stable_resource_path("/index.html")
    assert is_stable_resource_path("/api/v1/health")
    assert not is_stable_resource_path("/api/v1/events")


def test_success_response_size_is_stable_for_same_resource():
    first = response_size_for_status(200, "portal.example.com", "/assets/main.css")
    second = response_size_for_status(200, "portal.example.com", "/assets/main.css")
    sibling = response_size_for_status(200, "portal.example.com", "/assets/vendor.js")

    assert first == second
    assert first != sibling


def test_static_response_size_is_stable_across_virtual_hosts():
    first = response_size_for_status(200, "portal.example.com", "/assets/main.css")
    second = response_size_for_status(200, "www.example.net", "/assets/main.css")
    cache_busted = response_size_for_status(200, "www.example.net", "/assets/main.css?v=2")
    dynamic_first = response_size_for_status(200, "portal.example.com", "/api/v1/events")
    dynamic_second = response_size_for_status(200, "www.example.net", "/api/v1/events")

    assert first == second
    assert first == cache_busted
    assert dynamic_first != dynamic_second


def test_transfer_variant_keeps_static_resource_bytes_stable_across_clients():
    base = response_size_for_status(200, "portal.example.com", "/assets/main.css")
    client_a = apply_transfer_size_variance(
        base,
        status_code=200,
        host="portal.example.com",
        uri="/assets/main.css",
        content_type="text/css",
        variant_key="10.10.1.10:chrome",
    )
    client_a_repeat = apply_transfer_size_variance(
        base,
        status_code=200,
        host="portal.example.com",
        uri="/assets/main.css",
        content_type="text/css",
        variant_key="10.10.1.10:chrome",
    )
    client_b = apply_transfer_size_variance(
        base,
        status_code=200,
        host="portal.example.com",
        uri="/assets/main.css",
        content_type="text/css",
        variant_key="10.10.1.11:firefox",
    )

    assert client_a == client_a_repeat
    assert client_a == client_b == base
    assert (
        apply_transfer_size_variance(
            0,
            status_code=304,
            host="portal.example.com",
            uri="/assets/main.css",
            content_type="text/css",
            variant_key="10.10.1.10:chrome",
        )
        == 0
    )


def test_transfer_variant_does_not_change_static_download_object_bytes():
    base = response_size_for_status(200, "dbeaver.io", "/files/dbeaver-ce-latest-x86_64-setup.exe")
    client_a = apply_transfer_size_variance(
        base,
        status_code=200,
        host="dbeaver.io",
        uri="/files/dbeaver-ce-latest-x86_64-setup.exe",
        content_type="application/x-msdownload",
        variant_key="10.0.1.1:chrome",
    )
    client_b = apply_transfer_size_variance(
        base,
        status_code=200,
        host="dbeaver.io",
        uri="/files/dbeaver-ce-latest-x86_64-setup.exe",
        content_type="application/x-msdownload",
        variant_key="10.0.1.4:firefox",
    )

    assert client_a == base
    assert client_b == base


def test_health_endpoint_response_sizes_are_small_and_stable():
    assert is_health_endpoint_path("/api/v1/health?probe=1")

    first = response_size_for_health_endpoint(200, "portal.example.com", "/api/v1/health")
    second = response_size_for_status(200, "portal.example.com", "/api/v1/health")
    status = response_size_for_status(200, "portal.example.com", "/status")

    assert first == second
    assert 42 <= first <= 720
    assert 18 <= status <= 180
