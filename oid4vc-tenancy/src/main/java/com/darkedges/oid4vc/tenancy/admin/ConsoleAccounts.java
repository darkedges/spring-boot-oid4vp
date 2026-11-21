package com.darkedges.oid4vc.tenancy.admin;

/** Who a console token belongs to. */
public interface ConsoleAccounts {

    /**
     * @throws ConsoleAccountException 401 for a missing, expired or unknown token, 403 for an account that may not administer
     *                                 tenants, 503 when AuthStack cannot be asked
     */
    ConsoleAccount verify(String bearerToken);

    final class ConsoleAccountException extends RuntimeException {
        private final int status;

        public ConsoleAccountException(int status, String message) {
            super(message);
            this.status = status;
        }

        public int status() {
            return status;
        }
    }
}
