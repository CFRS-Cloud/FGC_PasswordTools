package uk.org.cambsfire.security;

/*-
 * #%L
 * Password Tools
 * %%
 * Copyright (C) 2016 - 2017 Cambridgeshire Fire and Rescue Service
 * %%
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Cambridgeshire Fire and Rescue Service nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * #L%
 */

import javax.xml.bind.DatatypeConverter;

@SuppressWarnings({ "PMD.MethodReturnsInternalArray", "PMD.ArrayIsStoredDirectly" })
public class EncodedPassword {
    private static final int CURRENT_VERSION = 1;
    private static final int HEX_RADIX = 16;
    private static final int MAX_ENCODED_PASSWORD_CHARS = 1024;
    private static final String ENCODED_VALUE_DELIMITER = ".";
    private final byte[] salt;
    private final byte[] passwordHash;
    private final int numIterations;

    public EncodedPassword(final byte[] salt, final int iterations, final byte[] passwordHash) {
        this.salt = salt;
        this.numIterations = iterations;
        this.passwordHash = passwordHash;
    }

    public int getVersion() {
        return CURRENT_VERSION;
    }

    public byte[] getSalt() {
        return salt;
    }

    public byte[] getPasswordHash() {
        return passwordHash;
    }

    public int getNumIterations() {
        return numIterations;
    }

    public static EncodedPassword parse(final String encodedPasswordString) {
        final String saltAndPasswordString = verifyAndRemoveVersion(encodedPasswordString);

        final int indexOfEndOfSalt = saltAndPasswordString.indexOf(ENCODED_VALUE_DELIMITER);
        if (indexOfEndOfSalt < 0) {
            throw new EncodedPasswordException("Encoded password should contain a salt");
        }
        final int indexOfEndOfIterations =
                saltAndPasswordString.indexOf(ENCODED_VALUE_DELIMITER, indexOfEndOfSalt + 1);
        if (indexOfEndOfIterations < 0) {
            throw new EncodedPasswordException("Encoded password should contain number of iterations");
        }
        try {
            final String b64Salt = saltAndPasswordString.substring(0, indexOfEndOfSalt);
            final String hexIterations = saltAndPasswordString.substring(indexOfEndOfSalt + 1, indexOfEndOfIterations);
            final String b64EncodedPassword = saltAndPasswordString.substring(indexOfEndOfIterations + 1);

            return new EncodedPassword(DatatypeConverter.parseBase64Binary(b64Salt),
                    Integer.parseInt(hexIterations, HEX_RADIX),
                    DatatypeConverter.parseBase64Binary(b64EncodedPassword));
        } catch (final IndexOutOfBoundsException | NumberFormatException e) {
            throw new EncodedPasswordException("Unable to read encoded password: " + saltAndPasswordString, e);
        }
    }

    private static String verifyAndRemoveVersion(final String encodedPasswordString) {
        if (!encodedPasswordString.startsWith(CURRENT_VERSION + ENCODED_VALUE_DELIMITER)) {
            throw new EncodedPasswordException("Unknown verson of encoded password: " + encodedPasswordString);
        }
        final int endOfVersionDelimiterIndex = encodedPasswordString.indexOf(ENCODED_VALUE_DELIMITER);
        final String saltAndPasswordString =
                encodedPasswordString.substring(endOfVersionDelimiterIndex + 1);
        return saltAndPasswordString;
    }

    /**
     * Encodes the password with the salt and iterations in the form:
     * <p>
     * <code>&lt;ENCODER VERSION&gt;.&lt;SALT&gt;.&lt;NUM ITERATIONS (hex)&gt;.&lt;ENCODED PASSWORD&gt;</code>
     * </p>
     * <p>
     * For EncoderVersion see {@link EncodedPassword.CURRENT_VERSION}
     * </p>
     */
    public String asEncodedString() {
        final String base64Salt = DatatypeConverter.printBase64Binary(salt);
        final String hexIterations = Integer.toHexString(numIterations);
        final String b64PasswordHash = DatatypeConverter.printBase64Binary(passwordHash);
        return new StringBuilder(MAX_ENCODED_PASSWORD_CHARS)
                .append(CURRENT_VERSION)
                .append(ENCODED_VALUE_DELIMITER)
                .append(base64Salt)
                .append(ENCODED_VALUE_DELIMITER)
                .append(hexIterations)
                .append(ENCODED_VALUE_DELIMITER)
                .append(b64PasswordHash)
                .toString();

    }
}
