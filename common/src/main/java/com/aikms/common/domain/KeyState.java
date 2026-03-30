package com.aikms.common.domain;

public enum KeyState {
    PENDING,
    ACTIVE,
    SUSPENDED,
    DEPRECATED,
    SCHEDULED_DESTROY,
    DESTROYED;

    public boolean isUsableForEncryption() {
        return this == ACTIVE;
    }

    public boolean isUsableForDecryption() {
        return this == ACTIVE || this == SUSPENDED || this == DEPRECATED;
    }

    public boolean canTransitionTo(KeyState target) {
        return switch (this) {
            case PENDING           -> target == ACTIVE;
            case ACTIVE            -> target == SUSPENDED || target == DEPRECATED || target == SCHEDULED_DESTROY;
            case SUSPENDED         -> target == ACTIVE || target == SCHEDULED_DESTROY;
            case DEPRECATED        -> target == SCHEDULED_DESTROY || target == SUSPENDED;
            case SCHEDULED_DESTROY -> target == SUSPENDED || target == DESTROYED;
            case DESTROYED         -> false;
        };
    }
}
