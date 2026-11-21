package com.darkedges.oid4vc.tenancy.domains;

import com.darkedges.oid4vc.tenancy.Slugs;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Custom domains from the deployment's own configuration ({@code oid4vc.tenancy.custom-domains}): for development and for a
 * domain the operator set up by hand. Whoever writes the configuration vouches for ownership.
 */
public final class StaticDomainDirectory implements DomainDirectory {

    private final Map<String, DomainBinding> byHost = new LinkedHashMap<>();

    public StaticDomainDirectory(Map<String, String> hostToEnvironment) {
        hostToEnvironment.forEach((host, env) -> {
            String h = Slugs.normalizeHost(host);
            byHost.put(h, new DomainBinding(h, env, null));
        });
    }

    @Override
    public Optional<DomainBinding> lookup(String host) {
        return Optional.ofNullable(byHost.get(Slugs.normalizeHost(host)));
    }

    /** Asks each directory in turn. */
    public static DomainDirectory firstOf(List<DomainDirectory> directories) {
        return host -> directories.stream().map(d -> d.lookup(host)).flatMap(Optional::stream).findFirst();
    }
}
