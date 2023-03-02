declare global {
  namespace NodeJS {
    interface ProcessEnv {
      RPC_URL: any;
      DEPLOYER_KEY: any;
      NETWORK: any;
      MNEMONIC: any;
      PROVIDER_HOST?: any;
      PROVIDER_PORT?: any;
    }
  }
}

export {};
