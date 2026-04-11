from __future__ import annotations

import asyncio

from sensability.config import Config


async def compose_command(cfg: Config, *args: str) -> tuple[int, str, str]:
    compose_yml = cfg.compose_dir / "docker-compose.yml"
    if not compose_yml.is_file():
        return 1, "", f"compose file not found: {compose_yml}"
    proc = await asyncio.create_subprocess_exec(
        "docker",
        "compose",
        "-f",
        str(compose_yml),
        *args,
        cwd=str(cfg.compose_dir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out_b, err_b = await proc.communicate()
    out = out_b.decode(errors="replace")
    err = err_b.decode(errors="replace")
    code = proc.returncode or 0
    return code, out, err


def compose_dir_ok(cfg: Config) -> bool:
    p = cfg.compose_dir
    return p.is_dir() and (p / "docker-compose.yml").is_file()
