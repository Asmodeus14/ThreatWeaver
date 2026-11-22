import type { LucideIcon } from "lucide-react";
import {
  BrainCircuit,
  ChartLine,
  Dna,
  FlaskConical,
  History,
  LayoutDashboard,
  Lock,
  Network,
  ScanSearch,
  Settings,
  ShieldAlert,
} from "lucide-react";

export interface NavItem {
  id: string;
  label: string;
  icon: LucideIcon;
  /** Extra words the command palette matches on. */
  keywords?: string;
}

export const NAV: { group?: string; items: NavItem[] }[] = [
  {
    items: [
      { id: "overview", label: "Overview", icon: LayoutDashboard, keywords: "home dashboard attention" },
      { id: "scan", label: "Scan", icon: ScanSearch, keywords: "analyse folder file drive" },
      { id: "detections", label: "Detections", icon: ShieldAlert, keywords: "results flagged malicious suspicious" },
      { id: "web", label: "Threat web", icon: Network, keywords: "graph folders map" },
    ],
  },
  {
    group: "Response",
    items: [
      { id: "quarantine", label: "Quarantine", icon: Lock, keywords: "vault restore isolate" },
      { id: "reports", label: "Scan history", icon: History, keywords: "reports past scans export" },
    ],
  },
  {
    group: "Intelligence",
    items: [
      { id: "families", label: "Families", icon: Dna, keywords: "malware families dataset" },
      { id: "learning", label: "Learning", icon: BrainCircuit, keywords: "labels feedback retrain" },
    ],
  },
  {
    group: "Research",
    items: [
      { id: "performance", label: "Model performance", icon: ChartLine, keywords: "roc evaluation metrics fpr" },
      { id: "experiments", label: "Experiments", icon: FlaskConical, keywords: "ablation continual" },
    ],
  },
  { items: [{ id: "settings", label: "Settings", icon: Settings, keywords: "preferences watcher intel" }] },
];

export const NAV_ITEMS: NavItem[] = NAV.flatMap((g) => g.items);
