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

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;

public class PasswordEncoderTest {

    @Test
    public void encodePasswordAppendsIterationsToEncodedPassword() {
        // given
        final int numIterations = 501;

        // when
        final String encodedPasswordWithSalt = PasswordEncoder.encode("rawPassword", numIterations);

        // then
        final EncodedPassword encodedPassword = EncodedPassword.parse(encodedPasswordWithSalt);
        assertThat(encodedPassword.getNumIterations()).isEqualTo(numIterations);
    }

    @Test
    public void encodePasswordAppendsSaltToEncodedPassword() {
        // when
        final String encodedPasswordWithSalt = PasswordEncoder.encode("rawPassword");

        // then
        final EncodedPassword encodedPassword = EncodedPassword.parse(encodedPasswordWithSalt);
        final int minSaltLength = 64;
        assertThat(encodedPassword.getSalt().length).isGreaterThanOrEqualTo(minSaltLength);
        assertThat(encodedPassword.getPasswordHash()).isNotEmpty();
    }

    @Test
    public void matchesReturnsFalseIfEncodedPasswordIsNotValid() {
        assertThat(PasswordEncoder.matches("password", "not-a-realhash")).isFalse();
        assertThat(PasswordEncoder.matches("password", "not.a.realhash")).isFalse();
        assertThat(PasswordEncoder.matches("password", "..")).isFalse();
    }

    @Test
    public void matchesGivesTrueForSamePassword() {
        // given
        final String password = "password";
        final String encodedPassword = PasswordEncoder.encode(password);

        // when
        final boolean passwordsMatch = PasswordEncoder.matches(password, encodedPassword);

        // then
        assertThat(passwordsMatch).isTrue();

    }

    @Test
    public void matchesGivesFalseForDifferentPasswords() {
        // given
        final String encodedPassword = PasswordEncoder.encode("password");

        // when
        final boolean passwordsMatch = PasswordEncoder.matches("another-password", encodedPassword);

        // then
        assertThat(passwordsMatch).isFalse();

    }
}
