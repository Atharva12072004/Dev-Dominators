import { useEffect, useMemo, useState } from "react";

import {
  AdvancedInsightsModel,
  AttackStageKey,
  IntelligenceInput,
  SimulationEvent,
} from "@/utils/advancedIntelligenceTypes";
import { buildAttackChain } from "@/utils/attackChainBuilder";
import { detectAIPhishing } from "@/utils/aiPhishingDetector";
import { buildCampaignCluster } from "@/utils/clusterEngine";
import { buildSimulationTimeline } from "@/utils/dynamicBehaviorSimulator";

const STEP_DELAY_MS = 1200;

export function useAttackChain(input: IntelligenceInput | null) {
  const insights = useMemo<AdvancedInsightsModel | null>(() => {
    if (!input) {
      return null;
    }
    const chain = buildAttackChain(input);
    const campaign = buildCampaignCluster(input);
    const aiPhishing = detectAIPhishing(input);
    const simulation = buildSimulationTimeline(chain);
    return {
      chain,
      campaign,
      aiPhishing,
      simulation,
    };
  }, [input]);

  const [isSimulating, setIsSimulating] = useState(false);
  const [activeStepIndex, setActiveStepIndex] = useState<number>(-1);
  const [showCampaign, setShowCampaign] = useState(true);
  const activeStageKey = useMemo<AttackStageKey | null>(() => {
    if (!insights || activeStepIndex < 0) {
      return null;
    }
    const activeStep = insights.simulation[Math.min(activeStepIndex, insights.simulation.length - 1)];
    return activeStep?.stageKey ?? null;
  }, [activeStepIndex, insights]);

  useEffect(() => {
    if (!isSimulating || !insights) {
      return;
    }
    setActiveStepIndex(0);
    let step = 0;
    const intervalId = setInterval(() => {
      step += 1;
      if (step >= insights.simulation.length) {
        clearInterval(intervalId);
        setIsSimulating(false);
        setActiveStepIndex(insights.simulation.length - 1);
        return;
      }
      setActiveStepIndex(step);
    }, STEP_DELAY_MS);

    return () => clearInterval(intervalId);
  }, [insights, isSimulating]);

  function startSimulation() {
    if (!insights) {
      return;
    }
    setActiveStepIndex(-1);
    setIsSimulating(true);
  }

  function resetSimulation() {
    setIsSimulating(false);
    setActiveStepIndex(-1);
  }

  function visibleSimulationSteps(): SimulationEvent[] {
    if (!insights) {
      return [];
    }
    if (activeStepIndex < 0) {
      return [];
    }
    return insights.simulation.slice(0, activeStepIndex + 1);
  }

  return {
    insights,
    isSimulating,
    activeStepIndex,
    activeStageKey,
    showCampaign,
    setShowCampaign,
    startSimulation,
    resetSimulation,
    visibleSimulationSteps: visibleSimulationSteps(),
  };
}
