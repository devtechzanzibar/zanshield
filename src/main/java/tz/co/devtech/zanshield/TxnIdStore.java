package tz.co.devtech.zanshield;

import java.time.Instant;

/**
 * Remembers which acknowledgement {@code txnID}s have already been accepted, so a leaked callback
 * URL can't be replayed into a second session. The default, {@link InMemoryTxnIdStore}, is fine
 * for a single server; with several instances behind a load balancer, implement this over shared
 * storage (a database unique key, Redis {@code SET NX}, ...).
 */
public interface TxnIdStore {

    /**
     * Records {@code txnId} as used, keeping it at least until {@code keepUntil}.
     *
     * @return true if this is the first time the ID is seen; false if it was already used
     */
    boolean markUsed(String txnId, Instant keepUntil);
}
