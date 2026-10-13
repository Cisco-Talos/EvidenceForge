import { createContext } from "react";
import type { StudioJob } from "./api";

export const JobActionContext = createContext<{
  jobs: StudioJob[];
  removedIds: string[];
  showGeneration?: (id: string) => void;
} | null>(null);
