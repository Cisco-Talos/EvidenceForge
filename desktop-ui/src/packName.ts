import { artifactNameError } from "./artifactNaming";

export function packNameError(name: string): string | null {
  return artifactNameError(name, "pack");
}
