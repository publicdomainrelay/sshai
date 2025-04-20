import sys
import click
import pathlib

import uvicorn
from mcp.server.fastmcp import FastMCP


os_release_path = pathlib.Path("/usr/lib/os-release")
if not os_release_path.exists():
    os_release_path = pathlib.Path("/etc/os-release")


SAMPLE_RESOURCES = {
    "/usr/lib/os-release": os_release_path.read_text(),
    "/etc/os-release": os_release_path.read_text(),
}


@click.command()
@click.option("--port", default=8000, help="Port to listen on for SSE")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse"]),
    default="stdio",
    help="Transport type",
)
@click.option(
    "--uds",
    default="files.sock",
    help="UNIX Domain Socket to listen at",
)
def main(port: int, transport: str, uds: str) -> int:

    class UNIXFastMCP(FastMCP):

        async def run_sse_async(self) -> None:
            """Run the server using SSE transport."""
            starlette_app = self.sse_app()

            config = uvicorn.Config(
                starlette_app,
                uds=uds,
                log_level=self.settings.log_level.lower(),
            )
            server = uvicorn.Server(config)
            await server.serve()

    # Create server
    mcp = UNIXFastMCP("OS info sever")


    @mcp.tool()
    def get_files() -> list[str]:
        print("[debug-server] get_files()")
        return list(SAMPLE_RESOURCES.keys())


    @mcp.tool()
    def get_file_content(file: str) -> str:
        print("[debug-server] get_file_content()")
        return SAMPLE_RESOURCES[file]


    mcp.run(transport="sse")

if __name__ == "__main__":
    sys.exit(main())
