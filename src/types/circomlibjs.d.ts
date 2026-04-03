declare module "circomlibjs" {
  export function buildPoseidon(): Promise<any>;
  export function buildBabyjub(): Promise<any>;
  export function buildEddsa(): Promise<any>;
}
