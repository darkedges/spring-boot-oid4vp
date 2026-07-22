package com.darkedges.oid4vp.wallet;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.eval.CredentialPresentationPlan;
import com.darkedges.oid4vp.core.dcql.eval.CredentialStore;
import com.darkedges.oid4vp.core.dcql.eval.DcqlEvaluationResult;
import com.darkedges.oid4vp.core.dcql.eval.DcqlEvaluator;
import com.darkedges.oid4vp.core.response.PresentationEntry;
import com.darkedges.oid4vp.core.response.VpToken;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Evaluates an incoming Authorization Request's DCQL query against a Wallet's {@link CredentialStore}
 * (via {@link DcqlEvaluator}) and, if satisfiable, builds the {@code vp_token} by dispatching each
 * selected credential to the registered format-specific {@link PresentationBuilder}.
 */
public final class WalletAuthorizationResponseBuilder {

    private final DcqlEvaluator evaluator = new DcqlEvaluator();
    private final Map<CredentialFormat, PresentationBuilder> builders;

    public WalletAuthorizationResponseBuilder(Map<CredentialFormat, PresentationBuilder> builders) {
        this.builders = Map.copyOf(builders);
    }

    public WalletAuthorizationResponseResult build(DcqlQuery query, CredentialStore store, PresentationBuildParams params) {
        DcqlEvaluationResult evaluation = evaluator.evaluate(query, store);
        if (evaluation instanceof DcqlEvaluationResult.Rejected rejected) {
            return new WalletAuthorizationResponseResult.Declined(rejected.reason());
        }

        DcqlEvaluationResult.Selected selected = (DcqlEvaluationResult.Selected) evaluation;
        Map<String, List<PresentationEntry>> presentations = new LinkedHashMap<>();
        for (Map.Entry<String, List<CredentialPresentationPlan>> entry : selected.presentations().entrySet()) {
            List<PresentationEntry> built = new ArrayList<>();
            for (CredentialPresentationPlan plan : entry.getValue()) {
                PresentationBuilder builder = builders.get(plan.credential().format());
                if (builder == null) {
                    throw new IllegalStateException("no PresentationBuilder registered for format: " + plan.credential().format());
                }
                built.add(builder.build(plan, params));
            }
            presentations.put(entry.getKey(), built);
        }
        return new WalletAuthorizationResponseResult.Built(new VpToken(presentations));
    }
}
