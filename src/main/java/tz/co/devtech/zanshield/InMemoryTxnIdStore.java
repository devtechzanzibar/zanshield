package tz.co.devtech.zanshield;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** A {@link TxnIdStore} for a single server process. Expired entries are pruned as new ones arrive. */
public class InMemoryTxnIdStore implements TxnIdStore {

    private final Map<String, Instant> used = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryTxnIdStore() {
        this(Clock.systemUTC());
    }

    InMemoryTxnIdStore(Clock clock) {
        this.clock = clock;
    }

    @Override
    public boolean markUsed(String txnId, Instant keepUntil) {
        Instant now = clock.instant();
        used.values().removeIf(expiry -> expiry.isBefore(now));
        return used.putIfAbsent(txnId, keepUntil) == null;
    }
}
