/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TelegramLinkPolicyTest {
    @Test fun permitsOnlyBotFatherOrBotUsernamesOnExactTelegramHost() {
        assertEquals("https://t.me/BotFather", TelegramLinkPolicy.externalUrl("https://t.me/BotFather"))
        assertEquals("https://t.me/my_test_bot", TelegramLinkPolicy.externalUrl("https://t.me/my_test_bot"))
        assertEquals("https://t.me/BOTFATHER", TelegramLinkPolicy.externalUrl("HTTPS://T.ME/BOTFATHER"))
        assertEquals("https://t.me/TetrisBot", TelegramLinkPolicy.externalUrl("https://t.me/TetrisBot"))
    }

    @Test fun rejectsExternalHostsCredentialsAndNonHttpsSchemes() {
        for (url in listOf(
            "http://t.me/BotFather", "tg://resolve?domain=BotFather",
            "https://example.com/BotFather", "https://t.me.evil.test/BotFather",
            "https://t.me@evil.test/BotFather", "https://user@t.me/BotFather",
            "https://t.me:443/BotFather", "https://127.0.0.1/BotFather",
            "https://t.me\\@evil.test/BotFather", "https://t.me%2eevil.test/BotFather"
        )) assertNull(url, TelegramLinkPolicy.externalUrl(url))
    }

    @Test fun rejectsUnexpectedPathQueryFragmentAndEncoding() {
        for (url in listOf(
            "https://t.me/", "https://t.me/anotheruser", "https://t.me/BotFather/extra",
            "https://t.me/BotFather/", "https://t.me/BotFather?start=payload",
            "https://t.me/BotFather#fragment", "https://t.me/%42otFather",
            "https://t.me/four", "https://t.me/abc+bot", "https://t.me/abc.bot",
            "https://t.me/${"a".repeat(30)}bot", "https://t.me/BotFather\n"
        )) assertNull(url, TelegramLinkPolicy.externalUrl(url))
    }
}
