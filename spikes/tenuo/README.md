# Tenuo / Biscuit spike (board task 4f9ed2c9)

Throwaway code from the 2026-10-02 spike. Never merged; kept so phase 0 can start from what worked.
Run with a venv holding tenuo 0.3.1, biscuit-python 0.4.0 and mcp 2.2.0. Keys are generated per run.

| Script | What it shows |
| --- | --- |
| spike_1_mint.py | scope/limit/TTL mapping, mint, MonotonicityError cases |
| spike_1b_probe.py | proof-of-possession required, closed-world args, terminal, replay window |
| spike_1c_board_custody.py | board holds intermediate links, agent holds the leaf; cascade still works |
| spike_2_mcp.py | in-process MCP server verifying warrants from `params._meta.tenuo` |
| spike_3_revocation.py | signed revocation list cascade matrix |
| spike_4_biscuit.py | Biscuit mint, attenuate, authorize, revocation ids |
| spike_5_ingest.py | verify a third-party warrant and map it to a mandate |

Findings are in the task's result on the board.
