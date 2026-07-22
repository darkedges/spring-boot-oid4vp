package com.darkedges.oid4vp.core.dcql;

/**
 * One element of a {@link ClaimsPathPointer}: a string (object key), {@code null} (all elements of the
 * currently selected array(s)), or a non-negative integer (array index).
 */
public sealed interface PathComponent {

    record Key(String name) implements PathComponent {
        public Key {
            if (name == null) {
                throw new IllegalArgumentException("name must not be null");
            }
        }
    }

    record AllElements() implements PathComponent {
        public static final AllElements INSTANCE = new AllElements();
    }

    record Index(int value) implements PathComponent {
        public Index {
            if (value < 0) {
                throw new IllegalArgumentException("index must be non-negative, was: " + value);
            }
        }
    }
}
