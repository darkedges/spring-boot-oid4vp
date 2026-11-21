package com.darkedges.oid4vc.tenancy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Caches lookups by id and slug for a short time: every request resolves its tenant, and a change made through another instance
 * shows within {@code ttl}. Changes made through this instance show at once.
 */
public final class CachingTenantRepository implements TenantRepository {

    private record Entry(Optional<Tenant> tenant, Instant expires) {}

    private final TenantRepository delegate;
    private final Duration ttl;
    private final Clock clock;
    private final Map<String, Entry> byId = new ConcurrentHashMap<>();
    private final Map<String, Entry> bySlug = new ConcurrentHashMap<>();

    public CachingTenantRepository(TenantRepository delegate, Duration ttl, Clock clock) {
        this.delegate = delegate;
        this.ttl = ttl;
        this.clock = clock;
    }

    public CachingTenantRepository(TenantRepository delegate, Duration ttl) {
        this(delegate, ttl, Clock.systemUTC());
    }

    @Override
    public Optional<Tenant> findById(String id) {
        return cached(byId, id, () -> delegate.findById(id));
    }

    @Override
    public Optional<Tenant> findBySlug(String slug) {
        return cached(bySlug, slug, () -> delegate.findBySlug(slug));
    }

    private Optional<Tenant> cached(Map<String, Entry> cache, String key, java.util.function.Supplier<Optional<Tenant>> load) {
        Instant now = clock.instant();
        Entry entry = cache.get(key);
        if (entry != null && now.isBefore(entry.expires())) return entry.tenant();
        Optional<Tenant> loaded = load.get();
        cache.put(key, new Entry(loaded, now.plus(ttl)));
        return loaded;
    }

    @Override
    public List<Tenant> findAll() {
        return delegate.findAll();
    }

    @Override
    public Tenant save(Tenant tenant) {
        Tenant saved = delegate.save(tenant);
        invalidate();
        return saved;
    }

    @Override
    public boolean delete(String id) {
        boolean deleted = delegate.delete(id);
        invalidate();
        return deleted;
    }

    public void invalidate() {
        byId.clear();
        bySlug.clear();
    }
}
