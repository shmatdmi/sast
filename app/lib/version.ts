import packageMetadata from "../../package.json";

declare const __APP_BUILD_VERSION__: string;

const embeddedVersion = typeof __APP_BUILD_VERSION__ === "string"
  ? __APP_BUILD_VERSION__.trim()
  : "";

export const appVersion = embeddedVersion || packageMetadata.version;
