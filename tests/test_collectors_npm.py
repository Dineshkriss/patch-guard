import httpx
import respx

from app.collectors import npm


@respx.mock
async def test_npm_collect_parses_versions():
    respx.get("https://registry.npmjs.org/lodash").mock(
        return_value=httpx.Response(
            200,
            json={
                "time": {
                    "4.17.21": "2021-02-20T15:42:16.891Z",
                    "4.17.20": "2020-08-13T00:00:00.000Z",
                },
                "versions": {
                    "4.17.21": {"name": "lodash", "version": "4.17.21"},
                    "4.17.20": {"name": "lodash", "version": "4.17.20"},
                },
            },
        )
    )

    async with httpx.AsyncClient() as client:
        patches = await npm.collect(client, "lodash")

    versions = {p.fixed_version for p in patches}
    assert versions == {"4.17.21", "4.17.20"}
    assert all(p.ecosystem.value == "npm" for p in patches)
    assert all(p.vendor == "lodash" for p in patches)


@respx.mock
async def test_npm_collect_scoped_package_vendor_is_the_scope():
    respx.get("https://registry.npmjs.org/@angular/core").mock(
        return_value=httpx.Response(200, json={"time": {}, "versions": {"17.0.0": {}}})
    )

    async with httpx.AsyncClient() as client:
        patches = await npm.collect(client, "@angular/core")

    assert patches[0].vendor == "angular"
    assert patches[0].product == "@angular/core"


@respx.mock
async def test_npm_collect_skips_versions_without_timestamp():
    respx.get("https://registry.npmjs.org/weird-pkg").mock(
        return_value=httpx.Response(
            200, json={"time": {}, "versions": {"0.0.1": {"name": "weird-pkg"}}}
        )
    )

    async with httpx.AsyncClient() as client:
        patches = await npm.collect(client, "weird-pkg")

    assert len(patches) == 1
    assert patches[0].released_at is None
