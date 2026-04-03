# @shade-protocol/indexer

Event indexer and REST API for Shade Protocol. Scans Citrea mainnet for contract events, maintains a Merkle tree, and serves data to the SDK and frontend.

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/keys/register` | Register `0xAddress → viewingPublicKey` mapping |
| `GET` | `/keys/:address` | Look up viewing public key for an address |
| `GET` | `/events?from=block` | Get events since block number |
| `GET` | `/merkle/root` | Current Merkle root and leaf count |
| `GET` | `/merkle/path/:leafIndex` | Merkle inclusion proof |
| `GET` | `/health` | Service health status |

## Run

```bash
npm install
npm run build
npm start
```

Environment variables (see `.env.example`):
- `CONTRACT_ADDRESS` — ShadePool contract address
- `RPC_URL` — Citrea mainnet RPC (default: `https://rpc.citreascan.com`)
- `DEPLOYMENT_BLOCK` — Block number of contract deployment
- `PORT` — API port (default: 4000)

## Docker

```bash
docker build -t shade-indexer .
docker run -p 4000:4000 --env-file .env shade-indexer
```

## Related Repos

- [contracts](https://github.com/shadeprotocolcom/contracts) — Smart contracts
- [sdk](https://github.com/shadeprotocolcom/sdk) — TypeScript SDK
- [frontend](https://github.com/shadeprotocolcom/frontend) — Web app

## License

MIT
