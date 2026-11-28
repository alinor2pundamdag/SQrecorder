package com.alinor.sqrecorder.vault.android

/** Canonical RFC 4648 standard Base64 without whitespace; API 23 compatible. */
internal object SqveBase64 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    fun encodeNoWrap(input: ByteArray): String {
        val out = StringBuilder(((input.size + 2) / 3) * 4)
        var i = 0
        while (i < input.size) {
            val b0 = input[i].toInt() and 0xff
            val has1 = i + 1 < input.size
            val has2 = i + 2 < input.size
            val b1 = if (has1) input[i + 1].toInt() and 0xff else 0
            val b2 = if (has2) input[i + 2].toInt() and 0xff else 0
            out.append(ALPHABET[b0 ushr 2])
            out.append(ALPHABET[((b0 and 3) shl 4) or (b1 ushr 4)])
            out.append(if (has1) ALPHABET[((b1 and 15) shl 2) or (b2 ushr 6)] else '=')
            out.append(if (has2) ALPHABET[b2 and 63] else '=')
            i += 3
        }
        return out.toString()
    }

    fun decodeCanonical(text: String): ByteArray {
        require(text.length % 4 == 0) { "Invalid Base64 length" }
        if (text.isEmpty()) return ByteArray(0)
        val padding = when {
            text.endsWith("==") -> 2
            text.endsWith("=") -> 1
            else -> 0
        }
        val output = ByteArray(text.length / 4 * 3 - padding)
        var outAt = 0
        for (offset in text.indices step 4) {
            val finalGroup = offset + 4 == text.length
            val c0 = decodeChar(text[offset])
            val c1 = decodeChar(text[offset + 1])
            val c2 = if (text[offset + 2] == '=' && finalGroup) 0 else decodeChar(text[offset + 2])
            val c3 = if (text[offset + 3] == '=' && finalGroup) 0 else decodeChar(text[offset + 3])
            require(text[offset] != '=' && text[offset + 1] != '=') { "Invalid Base64 padding" }
            require(finalGroup || (text[offset + 2] != '=' && text[offset + 3] != '=')) {
                "Base64 padding is only valid in the final quartet"
            }
            if (finalGroup && padding == 2) require((c1 and 15) == 0) { "Noncanonical Base64 tail bits" }
            if (finalGroup && padding == 1) require((c2 and 3) == 0) { "Noncanonical Base64 tail bits" }
            val bits = (c0 shl 18) or (c1 shl 12) or (c2 shl 6) or c3
            if (outAt < output.size) output[outAt++] = (bits ushr 16).toByte()
            if (outAt < output.size) output[outAt++] = (bits ushr 8).toByte()
            if (outAt < output.size) output[outAt++] = bits.toByte()
        }
        require(encodeNoWrap(output) == text) { "Noncanonical Base64 encoding" }
        return output
    }

    private fun decodeChar(char: Char): Int {
        val value = ALPHABET.indexOf(char)
        require(value >= 0) { "Invalid Base64 character" }
        return value
    }
}
