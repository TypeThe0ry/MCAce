package com.ellan.mcace.core.risk;

import com.ellan.mcace.sdk.RiskBand;
import com.ellan.mcace.sdk.RiskReason;
import java.util.List;

public record RiskAssessment(int score, RiskBand band, String policyVersion, List<RiskReason> reasons) {
    public RiskAssessment {
        reasons = List.copyOf(reasons);
    }
}
