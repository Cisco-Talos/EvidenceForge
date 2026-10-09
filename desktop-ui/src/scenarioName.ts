import { artifactNameError } from "./artifactNaming";

export function scenarioNameError(name: string): string | null {
  return artifactNameError(name, "scenario");
}
