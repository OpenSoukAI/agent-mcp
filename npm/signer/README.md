# @opensouk/signer

The OpenSouk signer MCP server. It signs OpenSouk commitments and payments with a key that stays on
your machine.

```sh
npx -y @opensouk/signer@<version>
```

Always pin an exact version. This package runs the `opensouk-signer` binary from the
`@opensouk/signer-<platform>` package npm installs alongside it. Those binaries are byte-identical to
the assets of the matching [GitHub release](https://github.com/OpenSoukAI/agent-mcp/releases), and
every package is published from that release's workflow with npm provenance. Check it with
`npm audit signatures`.

Setup and configuration: https://github.com/OpenSoukAI/agent-mcp
